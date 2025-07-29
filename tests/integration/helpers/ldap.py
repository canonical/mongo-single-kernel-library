#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from urllib.parse import quote_plus

from juju.model import Model
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    MONGOD_PORT,
    MONGOS_PORT,
    execute_on_mongod,
    generate_mongodb_client,
    get_address_of_unit,
    run_action,
)
from ..helpers.types import Substrate

POSTGRESQL_K8S = "postgresql-k8s"
CERTIFICATES = "self-signed-certificates"
LDAP_APP_NAME = "glauth-k8s"
LDAP_UTILS_APP_NAME = "glauth-utils"
TRAEFIK_CHARM = "traefik-k8s"
LDAP_OFFER = "ldap-integration"
LDAP_CERT_OFFER = "ldap-cert-integration"

logger = logging.getLogger(__name__)


async def apply_ldif(ops_test: OpsTest, kubernetes_model: Model, ldif_file: str) -> None:
    """Apply an LDIF on glauth-utils."""
    source_path = f"./tests/integration/data/{ldif_file}"
    target_path = f"/var/tmp/{ldif_file}"
    with ops_test.model_context("secondary"):
        app = kubernetes_model.applications[LDAP_UTILS_APP_NAME]
        scp_cmd = f"scp {source_path} {app.units[0].name}:{target_path}".split()
        await ops_test.juju(*scp_cmd)
        await run_action(kubernetes_model, LDAP_UTILS_APP_NAME, "apply-ldif", path=target_path)


async def deploy_glauth(ops_test: OpsTest, kubernetes_model: Model) -> None:
    """Deploys glauth and all required charms coming with glauth and relate them.

    Then it offers the two relations provided by glauth.
    """
    with ops_test.model_context("secondary"):
        await asyncio.gather(
            kubernetes_model.deploy(
                LDAP_APP_NAME,
                channel="latest/edge",
                revision=55,
                trust=True,
                config={"ldaps_enabled": True},
            ),
            kubernetes_model.deploy(LDAP_UTILS_APP_NAME, channel="latest/edge", trust=True),
            kubernetes_model.deploy(
                POSTGRESQL_K8S,
                channel="14/stable",
                trust=True,
                series="jammy",
                config={"profile": "testing"},
                storage={"pgdata": "100G"},
            ),
            kubernetes_model.deploy(CERTIFICATES, channel="latest/stable", trust=True),
            kubernetes_model.deploy(TRAEFIK_CHARM, trust=True),
        )
        await kubernetes_model.wait_for_idle(
            apps=[LDAP_APP_NAME, POSTGRESQL_K8S, CERTIFICATES, LDAP_UTILS_APP_NAME],
            raise_on_blocked=False,
        )

        logger.info("Running integrations")
        await kubernetes_model.integrate(LDAP_APP_NAME, POSTGRESQL_K8S)
        await kubernetes_model.integrate(LDAP_APP_NAME, CERTIFICATES)
        await kubernetes_model.integrate(LDAP_APP_NAME, LDAP_UTILS_APP_NAME)

        await kubernetes_model.wait_for_idle(
            apps=[LDAP_APP_NAME, POSTGRESQL_K8S, CERTIFICATES, LDAP_UTILS_APP_NAME],
            raise_on_blocked=False,
        )

        await kubernetes_model.integrate(
            f"{LDAP_APP_NAME}:ldaps-ingress", f"{TRAEFIK_CHARM}:ingress-per-unit"
        )
        await kubernetes_model.wait_for_idle(
            apps=[LDAP_APP_NAME, CERTIFICATES, TRAEFIK_CHARM],
            raise_on_blocked=False,  # postgresql can be in Blocked State because of low free space
            status="active",
        )

        # On k8s creating an offer on a remote model fails somehow, so we fallback to juju command.
        first_offer_command = (
            f"offer {kubernetes_model.info.name}.{LDAP_APP_NAME}:ldap {LDAP_OFFER}"
        )
        await ops_test.juju(*first_offer_command.split())

        second_offer_command = (
            f"offer {kubernetes_model.info.name}.{LDAP_APP_NAME}:send-ca-cert {LDAP_CERT_OFFER}"
        )

        await ops_test.juju(*second_offer_command.split())


async def consume_glauth_offers(ops_test: OpsTest, kubernetes_model: Model) -> None:
    """Consumes the two offers from glauth in the testing model."""
    # On k8s consuming an offer on a remote model fails somehow, so we fallback to juju command.
    first_consume_command = f"consume admin/{kubernetes_model.info.name}.{LDAP_OFFER}"
    await ops_test.juju(*first_consume_command.split())

    second_consume_command = f"consume admin/{kubernetes_model.info.name}.{LDAP_CERT_OFFER}"
    await ops_test.juju(*second_consume_command.split())


async def teardown_offers(ops_test: OpsTest, kubernetes_model: Model) -> None:
    """Teardown the offers, removing both saas, and offers."""
    await ops_test.model.remove_saas(LDAP_OFFER)
    await ops_test.model.remove_saas(LDAP_CERT_OFFER)

    first_remove_offer_command = (
        f"remove-offer admin/{kubernetes_model.name}.{LDAP_OFFER} --force --yes"
    )
    logger.info("Removing ldap offer")
    await ops_test.juju(*first_remove_offer_command.split())

    second_remove_offer_command = (
        f"remove-offer admin/{kubernetes_model.name}.{LDAP_CERT_OFFER} --force --yes"
    )
    logger.info("Removing ldap cert offer")
    await ops_test.juju(*second_remove_offer_command.split())


async def create_mongodb_user_roles(
    ops_test: OpsTest, substrate: Substrate, app_name: str, role_name: str, mongos: bool = False
) -> None:
    """Creates the roles for mongodb with the provided role_name."""
    uri = await generate_mongodb_client(ops_test, substrate, app_name, mongos=mongos)

    result = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        "db.createRole({"
        f"  role: '{role_name}',"
        "  privileges: [],"
        "  roles: [{'db': 'superdb', 'role': 'readWrite'}, {'db': 'superdb', 'role': 'enableSharding'}]"
        "})",
    )
    assert result.succeeded, "Failed to create role"


async def generate_mongodb_ldap_client(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    database: str,
    username: str,
    password: str,
    mongos: bool = False,
) -> str:
    """Generates an ldap client for mongodb."""
    if mongos and substrate == "lxd":
        app_unit = ops_test.model.applications[app_name].units[0]

        hosts = [await app_unit.get_public_address()]
    else:
        hosts = [
            await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
            for unit in ops_test.model.applications[app_name].units
        ]
    port = MONGOS_PORT if mongos else MONGOD_PORT
    hosts = ",".join([f"{host}:{port}" for host in hosts])
    return f"mongodb://{quote_plus(username)}:{quote_plus(password)}@{hosts}/{database}?authSource=\\$external&authMechanism=PLAIN"
