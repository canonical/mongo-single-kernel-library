#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
from juju.model import Model
from pytest_operator.plugin import OpsTest
from yaml import safe_load

from ...helpers import (
    ProcessError,
    check_or_scale_app,
    deploy_charm,
    execute_on_mongod,
    get_app_name,
    wait_for_mongodb_units_blocked,
)
from ...ldap_helpers import (
    LDAP_CERT_OFFER,
    LDAP_OFFER,
    apply_ldif,
    consume_glauth_offers,
    create_mongodb_user_roles,
    deploy_glauth,
    generate_mongodb_ldap_client,
    teardown_offers,
)

TIMEOUT = 15 * 60
ENDPOINT_LDAP = "ldap"
ENDPOINT_LDAP_CERT = "send-ca-cert"

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    kubernetes_model: Model,
    mongodb_charm: Path,
    substrate: str,
    mongod_resource,
    base_app_name: str,
) -> None:
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, app_name, 3)
        await ops_test.model.applications[app_name].set_config(
            {
                "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
            }
        )
    else:
        await deploy_charm(
            ops_test=ops_test,
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
    await deploy_glauth(ops_test, kubernetes_model)

    # Consume the offers exposed by glauth
    await consume_glauth_offers(ops_test, kubernetes_model)

    # Apply the LDIF file on glauth-utils to create users and groups
    await apply_ldif(ops_test, kubernetes_model, "ldap_entries.ldif")

    # Create the roles on MongoDB
    await create_mongodb_user_roles(
        ops_test, substrate, base_app_name, "ou=superheroes,ou=users,dc=glauth,dc=com"
    )


@pytest.mark.abort_on_fail
async def test_integrate_ldap_only(ops_test: OpsTest):
    """Only integrate ldap endpoint, should go into blocked state."""
    db_app_name = await get_app_name(ops_test)

    # Integrate LDAP only so it goes into blocked state
    await ops_test.model.integrate(f"{LDAP_OFFER}:ldap", f"{db_app_name}:ldap")

    await wait_for_mongodb_units_blocked(
        ops_test,
        db_app_name,
        status="TLS is mandatory for LDAP transport.",
        timeout=300,
    )


@pytest.mark.abort_on_fail
async def test_integrate_ldap_cert(ops_test: OpsTest):
    """Integrate the second relation, we should end up with everything active."""
    db_app_name = await get_app_name(ops_test)

    # Integrate also certificate relation, it should go into active state
    await ops_test.model.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{db_app_name}:ldap-certificate-transfer"
    )

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_user_can_write(ops_test: OpsTest, substrate: str):
    """Checks that the LDAP user can write to the DB.

    This checks both authentication and authorisation.
    """
    db_app_name = await get_app_name(ops_test)

    # We create a client which should be able to write
    uri = await generate_mongodb_ldap_client(
        ops_test,
        substrate,
        db_app_name,
        database="superdb",
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
    )

    await execute_on_mongod(ops_test, db_app_name, substrate, uri, "db.test.insertOne({number: 1})")

    await execute_on_mongod(ops_test, db_app_name, substrate, uri, "db.test.findOne({number: 1})")


@pytest.mark.abort_on_fail
async def test_ldap_user_to_dn_mapping(ops_test: OpsTest, substrate: str):
    """We want to ensure that we can log in using the ldap userToDNMapping.

    So we update the config for both and we log in with the user and check that we can
    still write in the DB.
    """
    db_app_name = await get_app_name(ops_test)

    # We update the config to be able to login as johndoe@superheroes
    await ops_test.model.applications[db_app_name].set_config(
        {
            "ldap-user-to-dn-mapping": '[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]',
            "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))",
        }
    )

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)

    path = (
        "/var/snap/charmed-mongodb/current/etc/mongod/mongod.conf"
        if substrate == "lxd"
        else "/etc/mongod/mongod.conf"
    )

    if substrate == "lxd":
        cat_cmd = "exec --unit {} -- cat {}"
    else:
        cat_cmd = "ssh --container mongod {} cat {}"

    # Check that all units have restarted and updated their configuration.
    for unit in ops_test.model.applications[db_app_name].units:
        cat_cmd = cat_cmd.format(unit.name, path)
        return_code, output, err = await ops_test.juju(*cat_cmd.split())

        if return_code != 0:
            raise ProcessError(f"Could not cat configuration. {output=} {err=}")

        configuration = safe_load(output)
        assert (
            configuration["security"]["ldap"].get("userToDNMapping", "")
            == '[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]'
        ), "Invalid userToDNMapping."
        assert (
            configuration["security"]["ldap"]["authz"].get("queryTemplate", "")
            == "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))"
        ), "Invalid ldap Query Template."

    uri = await generate_mongodb_ldap_client(
        ops_test,
        substrate,
        db_app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )
    await execute_on_mongod(ops_test, db_app_name, substrate, uri, "db.test.insertOne({number: 2})")

    await execute_on_mongod(ops_test, db_app_name, substrate, uri, "db.test.findOne({number: 2})")


@pytest.mark.abort_on_fail
async def test_remove_ldap_goes_to_blocked(ops_test: OpsTest, substrate: str):
    """Only integrate ldap endpoint, should go into blocked state."""
    db_app_name = await get_app_name(ops_test)

    # We remove the first relation integrated, it should go into blocked state
    await ops_test.model.applications[db_app_name].remove_relation(
        f"{LDAP_OFFER}:ldap", f"{db_app_name}:ldap"
    )

    units = ops_test.model.applications[db_app_name].units

    await ops_test.model.block_until(
        *[lambda: unit.workload_status == "blocked" for unit in units], timeout=TIMEOUT
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        db_app_name,
        status="GLauth TLS is integrated but LDAP is not.",
        timeout=300,
    )

    # John should not be able to log in now.
    uri = await generate_mongodb_ldap_client(
        ops_test,
        substrate,
        db_app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    with pytest.raises(ProcessError):
        # We expect this write to fail when the ldap relation is missing.
        # As soon as one relation is removed, a restart is triggered and it
        # should have disabled LDAP.
        await execute_on_mongod(
            ops_test, db_app_name, substrate, uri, "db.test.insertOne({number: 2})"
        )


@pytest.mark.abort_on_fail
async def test_teardown(ops_test: OpsTest, kubernetes_model: Model):
    """Teardown of the whole offers and relations."""
    db_app_name = await get_app_name(ops_test)

    # Removing the second relation should go into active
    await ops_test.model.applications[db_app_name].remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{db_app_name}:ldap-certificate-transfer"
    )
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)

    # Remove the offers and tear down deployment
    await teardown_offers(ops_test, kubernetes_model)
