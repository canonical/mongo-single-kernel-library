#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
from juju.model import Model
from pymongo.errors import OperationFailure
from pytest_operator.plugin import OpsTest
from yaml import safe_load

from ...helpers import (
    ProcessError,
    check_or_scale_app,
    deploy_charm,
    get_app_name,
    wait_for_mongodb_units_blocked,
)
from .helpers import (
    LDAP_CERT_OFFER,
    LDAP_OFFER,
    apply_ldif,
    consume_offers,
    create_groups,
    deploy_glauth,
    generate_mongodb_ldap_client,
    teardown_offers,
)

TIMEOUT = 15 * 60
ENDPOINT_LDAP = "ldap"
ENDPOINT_LDAP_CERT = "send-ca-cert"

logger = logging.getLogger(__name__)


async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: Path,
    substrate: str,
    mongod_resource,
    base_app_name: str,
    kubernetes_model: Model,
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
    await consume_offers(ops_test, kubernetes_model)

    # Apply the LDIF file on glauth-utils to create users and groups
    await apply_ldif(ops_test, kubernetes_model, "add.ldif")

    # Create the roles on MongoDB
    await create_groups(ops_test, base_app_name, "ou=superheroes,ou=users,dc=glauth,dc=com")


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


async def test_integrate_also_ldap_cert(ops_test: OpsTest):
    db_app_name = await get_app_name(ops_test)

    # Integrate also certificate relation, it should go into active state
    await ops_test.model.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{db_app_name}:ldap-certificate-transfer"
    )

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)


async def test_user_can_write(ops_test: OpsTest):
    db_app_name = await get_app_name(ops_test)

    # We create a client which should be able to write
    client = generate_mongodb_ldap_client(
        ops_test,
        db_app_name,
        database="superdb",
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
    )

    client.superdb["test-collection"].insert_one({"number": 1})


async def test_ldap_user_to_dn_mapping(ops_test):
    db_app_name = await get_app_name(ops_test)

    # We update the config to be able to login as johndoe@superheroes
    await ops_test.model.applications[db_app_name].set_config(
        {
            "ldap-user-to-dn-mapping": '[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]',
            "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))",
        }
    )

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)

    # Check that all units have restarted and updated their configuration.
    for unit in ops_test.model.applications[db_app_name].units:
        cat_cmd = f"exec --unit {unit.name} -- cat /var/snap/charmed-mongodb/current/etc/mongod/mongod.conf"
        return_code, output, _ = await ops_test.juju(*cat_cmd.split())

        if return_code != 0:
            raise ProcessError("Could not cat configuration.")

        configuration = safe_load(output)
        assert configuration["security"]["ldap"].get("userToDNMapping", "") != ""
        assert configuration["security"]["ldap"]["authz"].get("queryTemplate", "") != ""

    client = generate_mongodb_ldap_client(
        ops_test,
        db_app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    client.superdb["test-collection"].insert_one({"number": 2})


async def test_remove_ldap_goes_to_blocked(ops_test: OpsTest):
    """Only integrate ldap endpoint, should go into blocked state."""
    db_app_name = await get_app_name(ops_test)

    # We remove the first relation integrated, it should go into blocked state
    await ops_test.model.applications[db_app_name].remove_relation(
        f"{LDAP_OFFER}:ldap", f"{db_app_name}:ldap"
    )
    await wait_for_mongodb_units_blocked(
        ops_test,
        db_app_name,
        status="GLauth TLS is integrated but LDAP is not.",
        timeout=300,
    )

    # John should not be able to log in now.
    client = generate_mongodb_ldap_client(
        ops_test,
        db_app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    with pytest.raises(OperationFailure):
        client.superdb["test-collection"].insert_one({"number": 3})


async def test_teardown(ops_test: OpsTest, kubernetes_model: Model):
    db_app_name = await get_app_name(ops_test)

    # Removing the second relation should go into active
    await ops_test.model.applications[db_app_name].remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{db_app_name}:ldap-certificate-transfer"
    )
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)

    # Remove the offers and tear down deployment
    await teardown_offers(ops_test, kubernetes_model)
