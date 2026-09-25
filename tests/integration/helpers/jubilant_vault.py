#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import time
from logging import getLogger
from os.path import abspath
from typing import Any, final

import hvac
import jubilant
import requests
from jubilant.statustypes import UnitStatus

from single_kernel_mongo.exceptions import ActionFailedError
from tests.integration.helpers.constants import BASE
from tests.integration.helpers.jubilant_common import (
    fast_forward,
    find_leader,
    get_ip_from_unit,
    get_secret_uri_by_owner,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
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

    def wait_for_node_to_be_unsealed(self) -> None:
        """Wait for the vault unit to be unsealed."""
        timeout = 300
        t0 = time.time()
        while time.time() < t0 + timeout:
            time.sleep(5)
            try:
                if not self.is_sealed():
                    logger.info("Vault unit is unsealed.")
                    return
            except requests.exceptions.ConnectionError:
                logger.debug("Vault is not yet available. Waiting...")
                continue
        raise TimeoutError("Timed out waiting for vault to be unsealed.")


def get_vault_client(
    substrate: Substrate,
    unit_status: UnitStatus,
    token: str,
    ca_file_name: str | None = None,
) -> Vault:
    address = get_ip_from_unit(substrate, unit_info=unit_status)
    return Vault(url=f"https://{address}:8200", token=token, ca_file_location=ca_file_name)


def deploy_vault(juju: jubilant.Juju, substrate: Substrate, vault_charm_name: str) -> None:
    """Deploys vault and runs the initialization process.

    To initialize, you must first initialize on the leaver, then unseal vault on all units,
    and finally authorize.


    The flow is described in vault docs:
    https://canonical-vault-charms.readthedocs-hosted.com/en/latest/tutorial/getting_started_k8s/
    """
    juju.deploy(
        vault_charm_name,
        vault_charm_name,
        num_units=1,
        channel="1.18/stable",  # TODO: keep track of this after newer versions.
        base=BASE,
    )
    with fast_forward(juju, update_interval=FAST_INTERVAL):
        juju.wait(
            lambda status: (
                jubilant.all_blocked(status, vault_charm_name)
                and jubilant.all_agents_idle(status, vault_charm_name)
            )
        )
    initialize_unseal_authorize_vault(juju, substrate, vault_charm_name)


def get_vault_token_and_unseal_key(juju: jubilant.Juju, app_name: str) -> tuple[str, str]:
    secret = juju.show_secret(identifier=f"root-token-key-{app_name}", reveal=True)
    return secret.content["root-token"], secret.content["key"]


def initialize_unseal_authorize_vault(
    juju: jubilant.Juju, substrate: Substrate, app_name: str
) -> tuple[str, str]:
    """Initializes the vault leader, then unseal and authorize."""
    # Initialize the vault on the leader, and get back the root token and unseal key.
    root_token, unseal_key = initialize_vault_leader(juju, substrate, app_name)

    with fast_forward(juju, update_interval=FAST_INTERVAL):
        # Using the token and the unseal key, unseal all units, and authorize them
        unseal_all_vault_units(
            juju,
            substrate=substrate,
            app_name=app_name,
            unseal_key=unseal_key,
            token=root_token,
        )
        authorize_charm_and_wait(juju, app_name, root_token)
    return root_token, unseal_key


def initialize_vault_leader(
    juju: jubilant.Juju, substrate: Substrate, vault_charm_name: str
) -> tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key.

    Also adds the root token and unseal key to the model secrets so they can be
    retrieved if tests are run multiple times with a single deploy
    (`--no-deploy) or for debugging in the case of a failure.

    Returns:
        Tuple[str, str]: Root token and unseal key
    """
    _, leader_status = find_leader(juju, app_name=vault_charm_name)
    address = get_ip_from_unit(substrate, unit_info=leader_status)

    vault_url = f"https://{address}:8200"

    vault = Vault(url=vault_url, ca_file_location=None)
    if not vault.is_initialized():
        root_token, key = vault.initialize()
        juju.add_secret(
            name=f"root-token-key-{vault_charm_name}",
            content={
                "root-token": root_token,
                "key": key,
            },
        )
        logger.info("Vault initialized")
        return root_token, key

    root_token, key = get_vault_token_and_unseal_key(juju, app_name=vault_charm_name)
    logger.info("Vault is already initialized")
    return root_token, key


def unseal_all_vault_units(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    unseal_key: str,
    token: str,
    ca_file_name: str | None = None,
) -> None:
    """Unseal all the vault units."""
    # We need to unseal the leader first, since this is the one we initialized.
    _, leader_status = find_leader(juju, app_name=app_name)

    # Create a client with the right token
    vault = get_vault_client(
        substrate=substrate, unit_status=leader_status, token=token, ca_file_name=ca_file_name
    )

    # Unseal the leader
    if vault.is_sealed():
        vault.unseal(unseal_key)
    vault.wait_for_node_to_be_unsealed()

    for unit_status in juju.status().get_units(app_name).values():
        # Unseal the all other units.
        vault = get_vault_client(substrate, unit_status, token, ca_file_name)
        vault.unseal(unseal_key)
        vault.wait_for_node_to_be_unsealed()


def authorize_charm(
    juju: jubilant.Juju, root_token: str, app_name: str, attempts: int = 12
) -> dict[str, Any]:
    """Authorizes the charm as a client for vault."""
    leader_unit, _ = find_leader(juju, app_name=app_name)
    ## Add a new secret with the root token.
    try:
        secret = juju.add_secret(f"approle-token-{app_name}", {"token": root_token})
    except jubilant.CLIError:
        juju.update_secret(
            f"approle-token-{app_name}",
            {"token": root_token},
            name=f"approle-token-{app_name}",
        )
        secret = get_secret_uri_by_owner(
            juju, app_or_unit=app_name, label=f"approle-token-{app_name}"
        )

    secret_id = secret.split(":")[-1]

    # Grant it to the charm.
    juju.grant_secret(f"approle-token-{app_name}", app_name)

    # Run the action to authorize the charm.
    for attempt in range(attempts):
        authorize_action = juju.run(
            unit=leader_unit,
            action="authorize-charm",
            params={
                "secret-id": secret_id,
            },
        )
        result = authorize_action.results
        if result and "result" in result:
            return result
        logger.warning(
            "Failed to authorize charm. Attempt %d/%d. Waiting for 5 seconds...",
            attempt + 1,
            attempts,
        )
        time.sleep(5)
    logger.error("Failed to authorize charm")
    raise ActionFailedError("Failed to authorize charm")


def authorize_charm_and_wait(juju: jubilant.Juju, app_name: str, root_token: str) -> dict[str, Any]:
    """Authorize the charm and wait for it to be authorized.

    Args:
        juju: The Juju Client
        root_token: The root token for the vault
        app_name: Application name of the Vault, defaults to "vault-k8s"

    Returns:
        Any | Dict: The result of the authorization
    """
    result = authorize_charm(juju, root_token, app_name)
    with fast_forward(juju, update_interval=FAST_INTERVAL):
        juju.wait(
            lambda status: are_apps_active_and_agents_idle(status, app_name, idle_period=5),
            timeout=60,
        )
    logger.info("Charm authorized")
    return result


def vault_base_path(substrate: Substrate) -> str:
    if substrate == "lxd":
        return "/var/snap/charmed-mongodb/current/etc/vault/"
    return "/etc/vault/"
