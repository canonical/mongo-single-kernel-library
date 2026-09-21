#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest
from yaml import safe_load

from single_kernel_mongo.config.statuses import LdapStatuses
from tests.integration.helpers.constants import CONFIG_SERVER_APP_NAME, DEPLOYMENT_TIMEOUT
from tests.integration.helpers.jubilant_common import (
    execute_on_mongod,
    mongodb_config_path,
    read_remote_file,
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
from tests.integration.helpers.sharding import CLUSTER_COMPONENTS
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
    none_is_restarting,
)
from tests.integration.helpers.types import Substrate

TIMEOUT = 15 * 60
ENDPOINT_LDAP = "ldap"
ENDPOINT_LDAP_CERT = "send-ca-cert"

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    juju_k8s_model: jubilant.Juju,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
) -> None:
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    deploy_cluster_components(
        juju,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
        extra_config_config_server={
            "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
        },
    )
    juju.wait(
        lambda status: are_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
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

    # deploy the glauth-k8s charm
    deploy_glauth(juju_k8s_model)

    # Consume the offers exposed by glauth
    consume_glauth_offers(juju, juju_k8s_model)

    # Apply the LDIF file on glauth-utils to create users and groups
    apply_ldif(juju_k8s_model, "ldap_entries.ldif")

    create_mongodb_user_roles(
        juju, substrate, CONFIG_SERVER_APP_NAME, "ou=superheroes,ou=users,dc=glauth,dc=com"
    )


@pytest.mark.abort_on_fail
def test_integrate_ldap_only(juju: jubilant.Juju):
    """Only integrate ldap endpoint, should go into blocked state."""
    app_name = CONFIG_SERVER_APP_NAME
    # Integrate LDAP only so it goes into blocked state
    juju.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [LdapStatuses.TLS_REQUIRED.value],
                },
                expected_app_statuses={},
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_integrate_also_ldap_cert(juju: jubilant.Juju):
    app_name = CONFIG_SERVER_APP_NAME
    juju.integrate(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_user_can_write(juju: jubilant.Juju, substrate: Substrate):
    app_name = CONFIG_SERVER_APP_NAME
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

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.insertOne({number: 1})")
    assert result.succeeded, "Failed to insert value with LDAP client"

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.findOne({number: 1})")
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
def test_ldap_user_to_dn_mapping(juju: jubilant.Juju, substrate: Substrate):
    app_name = CONFIG_SERVER_APP_NAME

    # We update the config to be able to login as johndoe@superheroes
    juju.config(
        app_name,
        {
            "ldap-user-to-dn-mapping": '[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]',
            "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))",
        },
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    path = mongodb_config_path(substrate)

    # Check that all units have restarted and updated their configuration.
    for unit in juju.status().get_units(app_name):
        output = read_remote_file(
            juju,
            substrate,
            unit,
            path,
        )
        configuration = safe_load(output)
        assert (
            configuration["security"]["ldap"].get("userToDNMapping", "")
            == '[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]'
        ), "Invalid userToDNMapping."
        assert (
            configuration["security"]["ldap"]["authz"].get("queryTemplate", "")
            == "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))"
        ), "Invalid ldap Query Template."

    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
        mongos=True,
    )
    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.insertOne({number: 2})")
    assert result.succeeded, "Failed to write value with LDAP client"

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.findOne({number: 2})")
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
def test_remove_ldap_goes_to_blocked(juju: jubilant.Juju):
    """Only integrate ldap endpoint, should go into blocked state."""
    app_name = CONFIG_SERVER_APP_NAME
    # We remove the first relation integrated, it should go into blocked state
    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [LdapStatuses.LDAP_REQUIRED.value],
                },
                expected_app_statuses={},
            )
            and none_is_restarting(status, juju, app_name)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_teardown(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju):
    app_name = CONFIG_SERVER_APP_NAME
    juju.remove_relation(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Remove the offers and tear down deployment
    teardown_offers(juju, juju_k8s_model)
