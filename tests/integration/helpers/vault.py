#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import time
from logging import getLogger
from os.path import abspath
from typing import Any, final

import hvac
import requests
from juju.application import Application
from juju.errors import JujuError
from juju.model import Model
from pytest_operator.plugin import OpsTest

from single_kernel_mongo.exceptions import ActionFailedError
from tests.integration.helpers.common import (
    find_unit,
    get_address_of_unit,
    get_juju_secret,
    get_model_secret_id,
    get_unit_app,
)
from tests.integration.helpers.types import Substrate

VAULT = "vault"
VAULT_K8S = "vault-k8s"
VAULT_KV_RELATION = "vault-kv"

FAST_INTERVAL = "20s"

# Vault status codes, see
# https://developer.hashicorp.com/vault/api-docs/system/health for more details
VAULT_STATUS_ACTIVE = 200
VAULT_STATUS_NOT_INITIALIZED = 501

logger = getLogger(__name__)


@final
class Vault:
    """A Vault  helper class.

    This is taken from vault charmintegration test helpers.
    """

    def __init__(self, url: str, ca_file_location: str | None = None, token: str | None = None):
        self.url = url
        verify = abspath(ca_file_location) if ca_file_location else False
        self.client = hvac.Client(url=self.url, verify=verify)
        if token:
            self.client.token = token

    def initialize(self) -> tuple[str, str]:
        """Initialize the vault unit and return the root token and unseal key."""
        seal_type = self.client.seal_status["type"]  # type: ignore -- bad type hints in stubs
        if seal_type == "shamir":
            initialize_response = self.client.sys.initialize(secret_shares=1, secret_threshold=1)
            root_token, unseal_key = (
                initialize_response["root_token"],
                initialize_response["keys"][0],
            )
            return root_token, unseal_key
        initialize_response = self.client.sys.initialize(recovery_shares=1, recovery_threshold=1)
        root_token, recovery_key = (
            initialize_response["root_token"],
            initialize_response["recovery_keys"][0],
        )
        return root_token, recovery_key

    def is_initialized(self) -> bool:
        """Check if the vault unit is initialized."""
        response = self.client.sys.read_health_status()
        return response.status_code != VAULT_STATUS_NOT_INITIALIZED

    def is_sealed(self) -> bool:
        """Check if the vault unit is sealed."""
        return self.client.sys.is_sealed()

    def is_active(self) -> bool:
        """Check if the vault unit is active."""
        response = self.client.sys.read_health_status()
        return response.status_code == VAULT_STATUS_ACTIVE

    def unseal(self, unseal_key: str) -> None:
        """Unseal a vault unit.

        Args:
            unseal_key (str): The unseal key
        """
        if not self.client.sys.is_sealed():
            return
        self.client.sys.submit_unseal_key(unseal_key)
        logger.info("Unsealed vault unit: %s.", self.url)

    async def wait_for_node_to_be_unsealed(self) -> None:
        """Wait for the vault unit to be unsealed."""
        timeout = 300
        t0 = time.time()
        while time.time() < t0 + timeout:
            await asyncio.sleep(5)
            try:
                if not self.is_sealed():
                    logger.info("Vault unit is unsealed.")
                    return
            except requests.exceptions.ConnectionError:
                logger.debug("Vault is not yet available. Waiting...")
                continue
        raise TimeoutError("Timed out waiting for vault to be unsealed.")


async def get_vault_client(
    ops_test: OpsTest,
    substrate: Substrate,
    unit_name: str,
    token: str,
    ca_file_name: str | None = None,
) -> Vault:
    """Get a Vault client for the given application."""
    unit_id, app_name = get_unit_app(unit_name)
    address = await get_address_of_unit(ops_test, substrate, unit_id, app_name)
    return Vault(url=f"https://{address}:8200", token=token, ca_file_location=ca_file_name)


async def deploy_vault(ops_test: OpsTest, substrate: Substrate, vault_charm_name: str) -> None:
    """Deploys vault and runs the initialization process.

    To initialize, you must first initialize on the leaver, then unseal vault on all units,
    and finally authorize.


    The flow is described in vault docs:
    https://canonical-vault-charms.readthedocs-hosted.com/en/latest/tutorial/getting_started_k8s/
    """
    assert ops_test.model
    await ops_test.model.deploy(
        vault_charm_name,
        vault_charm_name,
        num_units=1,
        channel="1.18/stable",  # TODO: keep track of this after newer versions.
        series="noble",
    )
    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[vault_charm_name], wait_for_at_least_units=1, status="blocked", idle_period=5
        )
    await initialize_unseal_authorize_vault(ops_test, substrate, vault_charm_name)


def has_relation(app: Application, relation_name: str) -> bool:
    """Check if the application has the relation with the given name.

    This is a hack since `app.related_applications` does not seem to work.
    """
    for relation in app.relations:
        for endpoint in relation.endpoints:
            if endpoint.application_name != app.name:
                continue
            if endpoint.name == relation_name:
                return True
    return False


async def get_vault_token_and_unseal_key(model: Model, app_name: str) -> tuple[str, str]:
    root_token, unseal_key = await get_juju_secret(
        model, label=f"root-token-key-{app_name}", fields=["root-token", "key"]
    )
    return root_token, unseal_key


async def initialize_unseal_authorize_vault(
    ops_test: OpsTest, substrate: Substrate, app_name: str
) -> tuple[str, str]:
    """Initializes the vault leader, then unseal and authorize."""
    assert ops_test.model

    # Initialize the vault on the leader, and get back the root token and unseal key.
    root_token, unseal_key = await initialize_vault_leader(ops_test, substrate, app_name)

    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        # Using the token and the unseal key, unseal all units, and authorize them
        await unseal_all_vault_units(
            ops_test,
            substrate=substrate,
            app_name=app_name,
            unseal_key=unseal_key,
            token=root_token,
        )
        await authorize_charm_and_wait(ops_test, app_name, root_token)
    return root_token, unseal_key


async def initialize_vault_leader(
    ops_test: OpsTest, substrate: Substrate, vault_charm_name: str
) -> tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key.

    Also adds the root token and unseal key to the model secrets so they can be
    retrieved if tests are run multiple times with a single deploy
    (`--no-deploy) or for debugging in the case of a failure.

    Returns:
        Tuple[str, str]: Root token and unseal key
    """
    assert ops_test.model

    leader = await find_unit(ops_test, leader=True, app_name=vault_charm_name)
    unit_id, app_name = get_unit_app(leader.name)
    address = await get_address_of_unit(ops_test, substrate, unit_id, app_name)

    vault_url = f"https://{address}:8200"

    vault = Vault(url=vault_url, ca_file_location=None)
    if not vault.is_initialized():
        root_token, key = vault.initialize()
        await ops_test.model.add_secret(
            f"root-token-key-{vault_charm_name}", [f"root-token={root_token}", f"key={key}"]
        )
        logger.info("Vault initialized")
        return root_token, key

    root_token, key = await get_vault_token_and_unseal_key(
        ops_test.model, app_name=vault_charm_name
    )
    logger.info("Vault is already initialized")
    return root_token, key


async def unseal_all_vault_units(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    unseal_key: str,
    token: str,
    ca_file_name: str | None = None,
) -> None:
    """Unseal all the vault units."""
    assert ops_test.model
    app = ops_test.model.applications[app_name]

    # We need to unseal the leader first, since this is the one we initialized.
    leader = await find_unit(ops_test, leader=True, app_name=app.name)

    # Create a client with the right token
    vault = await get_vault_client(ops_test, substrate, leader.name, token, ca_file_name)

    # Unseal the leader
    if vault.is_sealed():
        vault.unseal(unseal_key)
    await vault.wait_for_node_to_be_unsealed()

    for unit in app.units:
        # Unseal the all other units.
        vault = await get_vault_client(ops_test, substrate, unit.name, token, ca_file_name)
        vault.unseal(unseal_key)
        await vault.wait_for_node_to_be_unsealed()


async def authorize_charm(
    ops_test: OpsTest, root_token: str, app_name: str, attempts: int = 12
) -> Any | dict[Any, Any]:
    """Authorizes the charm as a client for vault."""
    assert ops_test.model
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    ## Add a new secret with the root token.
    try:
        secret = await ops_test.model.add_secret(
            f"approle-token-{app_name}", [f"token={root_token}"]
        )
    except JujuError:
        await ops_test.model.update_secret(
            f"approle-token-{app_name}",
            [f"token={root_token}"],
            new_name=f"approle-token-{app_name}",
        )
        secret = await get_model_secret_id(ops_test, f"approle-token-{app_name}")
    secret_id = secret.split(":")[-1]

    # Grant it to the charm.
    await ops_test.model.grant_secret(f"approle-token-{app_name}", app_name)

    # Run the action to authorize the charm.
    for attempt in range(1, attempts + 1):
        authorize_action = await leader_unit.run_action(
            action_name="authorize-charm",
            **{
                "secret-id": secret_id,
            },
        )
        result = await ops_test.model.get_action_output(
            action_uuid=authorize_action.entity_id, wait=120
        )
        if result and "result" in result:
            return result
        logger.warning(
            "Failed to authorize charm. Attempt %d/%d. Waiting for 5 seconds...",
            attempt,
            attempts,
        )
        await asyncio.sleep(5)
    logger.error("Failed to authorize charm")
    raise ActionFailedError("Failed to authorize charm")


async def authorize_charm_and_wait(
    ops_test: OpsTest, app_name: str, root_token: str
) -> Any | dict[Any, Any]:
    """Authorize the charm and wait for it to be authorized.

    Args:
        ops_test: Ops test Framework
        root_token: The root token for the vault
        app_name: Application name of the Vault, defaults to "vault-k8s"

    Returns:
        Any | Dict: The result of the authorization
    """
    assert ops_test.model
    result = await authorize_charm(ops_test, root_token, app_name)
    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[app_name],
            status="active",
            timeout=60,  # Since we're not raising on error, don't wait too long. This should be quick.
            wait_for_at_least_units=1,
            raise_on_error=False,  # Sometimes the charm reports an InternalServerError immediately after authorization, but it resolves itself.
        )
    logger.info("Charm authorized")
    return result


def vault_base_path(substrate: Substrate) -> str:
    if substrate == "lxd":
        return "/var/snap/charmed-mongodb/current/etc/vault/"
    return "/etc/vault/"
