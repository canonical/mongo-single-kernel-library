#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from urllib.parse import quote_plus

import jubilant

from tests.integration.helpers.constants import (
    BASE,
    CHARMED_OPERATOR_USERNAME,
    DATA_INTEGRATOR_APP_NAME,
    MONGOD_PORT,
    MONGOS_PORT,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.jubilant_common import (
    execute_on_mongod,
    find_leader,
    get_ip_from_unit,
    get_ips_for_app,
    get_password,
    unit_uri,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

POSTGRESQL_K8S = "postgresql-k8s"
LDAP_APP_NAME = "glauth-k8s"
LDAP_UTILS_APP_NAME = "glauth-utils"
TRAEFIK_CHARM = "traefik-k8s"
LDAP_OFFER = "ldap-integration"
LDAP_CERT_OFFER = "ldap-cert-integration"

# Roles requested through data-integrator as GROUP entities. The `ou` attribute of the
# `ldap-query-template` makes PSMDB map the superheroes LDAP group to the role `superheroes`.
LDAP_GROUP_ROLE = "superheroes"
LDAP_CLASH_ROLE = "clash"

logger = logging.getLogger(__name__)


def apply_ldif(juju_k8s_model: jubilant.Juju, ldif_file: str):
    """Apply an LDIF on glauth-utils."""
    source_path = f"./tests/integration/data/{ldif_file}"
    target_path = f"/var/tmp/{ldif_file}"
    utils_unit = next(iter(juju_k8s_model.status().get_units(LDAP_UTILS_APP_NAME)))
    juju_k8s_model.scp(source_path, f"{utils_unit}:{target_path}")

    # Wait to be all active before running the command.
    juju_k8s_model.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            LDAP_UTILS_APP_NAME,
            LDAP_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    ldif_action = juju_k8s_model.run(utils_unit, "apply-ldif", params={"path": target_path})
    assert ldif_action.status == "completed", "apply-ldif should succeed"


def deploy_glauth(juju_k8s_model: jubilant.Juju) -> None:
    """Deploys glauth and all required charms coming with glauth and relate them.

    Then it offers the two relations provided by glauth.
    """
    juju_k8s_model.deploy(
        POSTGRESQL_K8S,
        channel="14/stable",
        trust=True,
        base="ubuntu@22.04",
        config={"profile": "testing"},
    )
    juju_k8s_model.deploy(
        LDAP_APP_NAME,
        channel="latest/edge",
        revision=56,
        trust=True,
        config={"ldaps_enabled": True},
    )
    juju_k8s_model.deploy(LDAP_UTILS_APP_NAME, channel="latest/edge", trust=True)
    juju_k8s_model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
        trust=True,
    )
    juju_k8s_model.deploy(TRAEFIK_CHARM, trust=True)

    logger.info(msg="Add integrations for LDAP")
    juju_k8s_model.integrate(f"{LDAP_APP_NAME}:pg-database", f"{POSTGRESQL_K8S}:database")
    juju_k8s_model.integrate(LDAP_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    juju_k8s_model.integrate(LDAP_APP_NAME, LDAP_UTILS_APP_NAME)
    juju_k8s_model.integrate(f"{LDAP_APP_NAME}:ldaps-ingress", f"{TRAEFIK_CHARM}:ingress-per-unit")

    juju_k8s_model.wait(
        lambda status: are_agents_idle(
            status,
            LDAP_APP_NAME,
            LDAP_UTILS_APP_NAME,
            TLS_CERTIFICATES_APP_NAME,
            TRAEFIK_CHARM,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    logger.info(msg="Setup cross-model offers")
    juju_k8s_model.offer(app=LDAP_APP_NAME, endpoint="ldap", name=LDAP_OFFER)
    juju_k8s_model.offer(app=LDAP_APP_NAME, endpoint="send-ca-cert", name=LDAP_CERT_OFFER)


def consume_glauth_offers(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju):
    """Consumes the two offers from glauth in the testing model."""
    assert juju_k8s_model.model
    juju_k8s_model_name = juju_k8s_model.model.split(":")[-1]

    juju.consume(f"{juju_k8s_model_name}.{LDAP_OFFER}")
    juju.consume(f"{juju_k8s_model_name}.{LDAP_CERT_OFFER}")


def teardown_offers(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju):
    """Teardown the offers, removing both saas, and offers."""
    assert juju_k8s_model.model
    juju_k8s_model_name = juju_k8s_model.model.split(":")[-1]
    logger.info("Removing ldap SAAS")
    juju.cli("remove-saas", LDAP_OFFER)
    logger.info("Removing ldap certs SAAS")
    juju.cli("remove-saas", LDAP_CERT_OFFER)
    logger.info("Removing ldap offer")
    juju_k8s_model.cli(
        "remove-offer",
        f"admin/{juju_k8s_model_name}.{LDAP_OFFER}",
        "--force",
        "--yes",
        include_model=False,
    )
    logger.info("Removing ldap cert offer")
    juju_k8s_model.cli(
        "remove-offer",
        f"admin/{juju_k8s_model_name}.{LDAP_CERT_OFFER}",
        "--force",
        "--yes",
        include_model=False,
    )


def create_mongodb_user_roles(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    role_name: str,
    mongos: bool = False,
    db: str = "superdb",
    tls: bool = False,
) -> None:
    """Creates the roles for mongodb with the provided role_name."""
    _, leader_unit_info = find_leader(juju=juju, app_name=app_name)

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)

    ip_address = get_ip_from_unit(substrate=substrate, unit_info=leader_unit_info)

    uri = unit_uri(
        username=CHARMED_OPERATOR_USERNAME,
        ip_address=ip_address,
        password=password,
        replica_set=app_name,
        mongos=mongos,
    )

    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri=uri,
        command=(
            "db.createRole({"
            f"  role: '{role_name}',"
            "  privileges: [],"
            f"  roles: [{{'db': '{db}', 'role': 'readWrite'}}, {{'db': '{db}', 'role': 'enableSharding'}}]"
            "})"
        ),
        tls=tls,
    )
    assert result.succeeded, "Failed to create role"


def drop_mongodb_role(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    role_name: str,
    mongos: bool = False,
    tls: bool = False,
) -> None:
    """Drops the role role_name, e.g. one made by create_mongodb_user_roles."""
    _, leader_unit_info = find_leader(juju=juju, app_name=app_name)

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)

    ip_address = get_ip_from_unit(substrate=substrate, unit_info=leader_unit_info)

    uri = unit_uri(
        username=CHARMED_OPERATOR_USERNAME,
        ip_address=ip_address,
        password=password,
        replica_set=app_name,
        mongos=mongos,
    )

    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri=uri,
        command=f"db.dropRole('{role_name}')",
        tls=tls,
    )
    assert result.succeeded, "Failed to drop role"


def generate_mongodb_ldap_client(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    database: str,
    username: str,
    password: str,
    mongos: bool = False,
) -> str:
    """Generates an ldap client for mongodb."""
    if mongos and substrate == Substrate.lxd:
        app_unit_status = next(iter(juju.status().get_units(app_name).values()))

        _hosts = [app_unit_status.public_address]
    else:
        _hosts = get_ips_for_app(juju, substrate, app_name)
    port = MONGOS_PORT if mongos else MONGOD_PORT
    hosts = ",".join([f"{host}:{port}" for host in _hosts])
    return f"mongodb://{quote_plus(username)}:{quote_plus(password)}@{hosts}/{database}?authSource=\\$external&authMechanism=PLAIN"


def request_ldap_group_role(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    role_name: str = LDAP_GROUP_ROLE,
    permissions: str = "",
    mongos: bool = False,
    wait: bool = True,
) -> None:
    """Asks for the role `role_name` as a GROUP entity through data-integrator.

    data-integrator takes the requested name from the first key of the user secret set as its
    `requested-entities-secret`. It relates to `app_name:database`, or to
    `app_name:mongos_proxy` when `mongos` is set; a VM mongos is a subordinate whose
    `mongos_proxy` endpoint requires `mongos_client`, which data-integrator provides on its
    `mongos` endpoint. With `wait`, returns once data-integrator is Active, which it turns once
    the provider published the entity name, i.e. created the role.
    """
    config: dict[str, jubilant.ConfigValue] = {
        "database-name": "superdb",
        "entity-type": "GROUP",
        "entity-permissions": permissions,
    }
    if DATA_INTEGRATOR_APP_NAME not in juju.status().apps:
        juju.deploy(DATA_INTEGRATOR_APP_NAME, channel="latest/stable", base=BASE, config=config)
    else:
        juju.config(DATA_INTEGRATOR_APP_NAME, config)

    # One secret per role name, kept from an earlier request of the same name.
    secret_name = f"{role_name}-role"
    uri = next((secret.uri for secret in juju.secrets() if secret.name == secret_name), None)
    if uri is None:
        uri = juju.add_secret(secret_name, {role_name: "None"})
        juju.grant_secret(uri, DATA_INTEGRATOR_APP_NAME)
    juju.config(DATA_INTEGRATOR_APP_NAME, {"requested-entities-secret": str(uri)})

    # data-integrator refreshes its status on config-changed and update-status only: without
    # this, a request identical to the previous one could be judged on that one's Active status.
    juju.wait(
        lambda status: not jubilant.all_active(status, DATA_INTEGRATOR_APP_NAME),
        timeout=TIMEOUT,
    )

    if not mongos:
        juju.integrate(f"{DATA_INTEGRATOR_APP_NAME}:mongodb", f"{app_name}:database")
    elif substrate == Substrate.lxd:
        juju.integrate(f"{DATA_INTEGRATOR_APP_NAME}:mongos", f"{app_name}:mongos_proxy")
    else:
        juju.integrate(f"{DATA_INTEGRATOR_APP_NAME}:mongodb", f"{app_name}:mongos_proxy")
    if not wait:
        return

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            DATA_INTEGRATOR_APP_NAME,
            app_name,
            idle_period=30,
            unit_count={DATA_INTEGRATOR_APP_NAME: 1},
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )
