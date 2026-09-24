#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest
from yaml import safe_load

from single_kernel_mongo.config.statuses import LdapStatuses
from tests.integration.helpers.constants import UNIT_IDS
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    execute_on_mongod,
    existing_app,
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
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    juju_k8s_model: jubilant.Juju,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
) -> None:
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=len(UNIT_IDS))
        juju.config(
            app_name,
            {
                "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
            },
        )
    else:
        deploy_charm(
            juju=juju,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=3,
            config={
                "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
            },
        )

    # deploy the glauth-k8s charm
    deploy_glauth(juju_k8s_model)

    # Consume the offers exposed by glauth
    consume_glauth_offers(juju, juju_k8s_model)

    # Apply the LDIF file on glauth-utils to create users and groups
    apply_ldif(juju_k8s_model, "ldap_entries.ldif")

    # Create the roles on MongoDB
    create_mongodb_user_roles(
        juju_k8s_model, substrate, base_app_name, "ou=superheroes,ou=users,dc=glauth,dc=com"
    )


@pytest.mark.abort_on_fail
def test_integrate_ldap_only(juju: jubilant.Juju):
    """Only integrate ldap endpoint, should go into blocked state."""
    app_name = existing_app(juju)
    assert app_name

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
def test_integrate_ldap_cert(juju: jubilant.Juju):
    """Integrate the second relation, we should end up with everything active."""
    app_name = existing_app(juju)
    assert app_name

    # Integrate also certificate relation, it should go into active state
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
    """Checks that the LDAP user can write to the DB.

    This checks both authentication and authorisation.
    """
    app_name = existing_app(juju)
    assert app_name

    # We create a client which should be able to write
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
    )

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.insertOne({number: 1})")
    assert result.succeeded, "Failed to insert value with LDAP client"

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.findOne({number: 1})")
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
def test_ldap_user_to_dn_mapping(juju: jubilant.Juju, substrate: Substrate):
    """We want to ensure that we can log in using the ldap userToDNMapping.

    So we update the config for both and we log in with the user and check that we can
    still write in the DB.
    """
    app_name = existing_app(juju)
    assert app_name

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
    )
    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.insertOne({number: 2})")
    assert result.succeeded, "Failed to write value with LDAP client"

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.findOne({number: 2})")
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
def test_remove_ldap_goes_to_blocked(juju: jubilant.Juju, substrate: Substrate):
    """Only integrate ldap endpoint, should go into blocked state."""
    app_name = existing_app(juju)
    assert app_name

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

    # John should not be able to log in now.
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    # We expect this write to fail when the ldap relation is missing.
    # As soon as one relation is removed, a restart is triggered and it
    # should have disabled LDAP.
    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri,
        "db.test.insertOne({number: 2})",
        expecting_output=False,
    )
    assert result.failed


@pytest.mark.abort_on_fail
def test_remove_ldap_certs_goes_to_blocked(juju: jubilant.Juju, substrate: Substrate):
    """With only certs relation it should also go to blocked."""
    app_name = existing_app(juju)
    assert app_name

    # Add back the ldap relation.
    juju.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    # Everything should go back to normal.
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

    # We remove the cert relation, it should go into blocked state
    juju.remove_relation(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")

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
            and none_is_restarting(status, juju, app_name)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # John should not be able to log in now.
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    # We expect this write to fail when the ldap relation is missing.
    # As soon as one relation is removed, a restart is triggered and it
    # should have disabled LDAP.
    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri,
        "db.test.insertOne({number: 2})",
        expecting_output=False,
    )
    assert result.failed


@pytest.mark.abort_on_fail
def test_teardown(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju):
    """Teardown of the whole offers and relations."""
    app_name = existing_app(juju)
    assert app_name

    # Removing the second relation should go into active
    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")

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
