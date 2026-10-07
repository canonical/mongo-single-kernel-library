#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import jubilant

from single_kernel_mongo.config.statuses import LdapStatuses, MongosStatuses
from tests.integration.helpers.common import MONGOS_APP_NAME
from tests.integration.helpers.constants import (
    BASE,
    CLUSTER_COMPONENTS,
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    DATA_INTEGRATOR_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    SHARD_ONE_APP_NAME,
    SHARD_TWO_APP_NAME,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    execute_on_mongod,
    existing_app,
)
from tests.integration.helpers.jubilant_ldap import (
    LDAP_CERT_OFFER,
    LDAP_OFFER,
    apply_ldif,
    consume_glauth_offers,
    create_mongodb_user_roles,
    deploy_glauth,
    generate_mongodb_ldap_client,
    teardown_offers,
)
from tests.integration.helpers.jubilant_sharding import (
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


def test_build_and_deploy_mongodb_cluster(
    juju: jubilant.Juju,
    substrate: Substrate,
    juju_k8s_model: jubilant.Juju,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
) -> None:
    """Build and deploy a sharded cluster.

    Deploy GLAUTH components and expose offers, consumes them and create groups on MongoDB.
    """
    # deploy the glauth-k8s charm
    deploy_glauth(juju_k8s_model)
    # Consume the offers exposed by glauth
    consume_glauth_offers(juju, juju_k8s_model)

    deploy_cluster_components(
        juju,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
        extra_config_config_server={
            "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
        },
        num_units_cluster_config={
            CONFIG_SERVER_APP_NAME: 1,
            SHARD_ONE_APP_NAME: 1,
            SHARD_TWO_APP_NAME: 1,
        },
    )
    integrate_sharding_components(juju)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Apply the LDIF file on glauth-utils to create users and groups
    apply_ldif(juju_k8s_model, "ldap_entries.ldif")

    create_mongodb_user_roles(
        juju, substrate, CONFIG_SERVER_APP_NAME, "ou=superheroes,ou=users,dc=glauth,dc=com"
    )


def test_build_and_deploy_mongos(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongos_charm: str,
    mongos_resource: dict[str, str],
    base_app_name: str,
) -> None:
    """Deploys mongos and data integrator, and integrates both.

    Then integrate mongos and sharded cluster.
    """
    deploy_charm(
        juju=juju,
        charm=mongos_charm,
        substrate=substrate,
        mongod_resource=mongos_resource,
        app_name=base_app_name,
        num_units=1,
        subordinate=(substrate == Substrate.lxd),
    )

    # This is necessary for mongos operator on VM, but we deploy it anyway for flow unicity.
    juju.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        base=BASE,
        num_units=1,
        config={"database-name": "test-database"},
    )

    juju.wait(
        lambda status: are_agents_idle(status, DATA_INTEGRATOR_APP_NAME, idle_period=20),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    juju.integrate(DATA_INTEGRATOR_APP_NAME, base_app_name)

    # verify that Charmed Mongos is blocked and reports incorrect credentials
    juju.wait(
        lambda status: (
            are_agents_idle(status, base_app_name, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    base_app_name: [MongosStatuses.MISSING_CONF_SERVER_REL.value],
                },
                expected_app_statuses={},
            )
        ),
        timeout=TIMEOUT,
    )


def test_config_server_only_integrated_with_mongos(juju: jubilant.Juju):
    app_name = existing_app(juju, charm_name="mongos")
    assert app_name

    juju.integrate(f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap")
    juju.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{CONFIG_SERVER_APP_NAME}:ldap-certificate-transfer"
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    # connect sharded cluster to mongos
    juju.integrate(
        f"{app_name}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    juju.wait(
        lambda status: (
            are_apps_active_and_agents_idle(
                status,
                CONFIG_SERVER_APP_NAME,
                SHARD_ONE_APP_NAME,
                SHARD_TWO_APP_NAME,
                idle_period=20,
            )
            and are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
            and does_status_match(status, {app_name: [LdapStatuses.LDAP_SERVERS_MISMATCH.value]})
        ),
        timeout=TIMEOUT,
    )

    # Go back to normal state
    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap")
    juju.remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{CONFIG_SERVER_APP_NAME}:ldap-certificate-transfer"
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            app_name,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )


def test_glauth_only_integrated_with_mongos(juju: jubilant.Juju):
    """Integrate only mongos, it should go to a blocked state.

    This is because config server is not integrated with LDAP.
    """
    app_name = existing_app(juju, charm_name="mongos")
    assert app_name

    juju.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")

    juju.wait(
        lambda status: (
            are_agents_idle(status, app_name, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    app_name: [LdapStatuses.TLS_REQUIRED.value],
                },
            )
        ),
        timeout=TIMEOUT,
    )
    juju.integrate(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")
    # We go to blocked because config server is not integrated with ldap.
    juju.wait(
        lambda status: (
            are_apps_active_and_agents_idle(
                status,
                CONFIG_SERVER_APP_NAME,
                SHARD_ONE_APP_NAME,
                SHARD_TWO_APP_NAME,
                idle_period=20,
            )
            and are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
            and does_status_match(status, {app_name: [LdapStatuses.LDAP_SERVERS_MISMATCH.value]})
        ),
        timeout=TIMEOUT,
    )


def test_glauth_fully_integrated(juju: jubilant.Juju):
    """Integrate the config server as well, everything should be green."""
    app_name = existing_app(juju, charm_name="mongos")
    assert app_name

    juju.integrate(f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap")
    juju.wait(
        lambda status: (
            are_agents_idle(status, CONFIG_SERVER_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    CONFIG_SERVER_APP_NAME: [LdapStatuses.TLS_REQUIRED.value],
                },
            )
        ),
        timeout=TIMEOUT,
    )

    juju.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{CONFIG_SERVER_APP_NAME}:ldap-certificate-transfer"
    )

    # Everything should be integrated now!
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            app_name,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )


def test_user_can_write(juju: jubilant.Juju, substrate: Substrate):
    app_name = existing_app(juju, charm_name="mongos")
    assert app_name

    # We create a client which should be able to write
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
        mongos=True,
    )

    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri,
        "db.test.insertOne({number: 1})",
        container_name="mongos",
    )
    assert result.succeeded, "Failed to insert value with LDAP client"

    execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri,
        "db.test.findOne({number: 1})",
        container_name="mongos",
    )
    assert result.succeeded, "Failed to read value with LDAP client"


def test_teardown(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju):
    app_name = existing_app(juju, charm_name="mongos")
    assert app_name

    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    juju.remove_relation(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")
    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap")
    juju.remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{CONFIG_SERVER_APP_NAME}:ldap-certificate-transfer"
    )

    # Everything should be integrated now!
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            SHARD_TWO_APP_NAME,
            app_name,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )
    teardown_offers(juju, juju_k8s_model)
