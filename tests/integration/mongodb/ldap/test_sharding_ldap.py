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
    DEPLOYMENT_TIMEOUT,
    ProcessError,
    execute_on_mongod,
    wait_for_mongodb_units_blocked,
)
from ...ldap_helpers import (
    LDAP_CERT_OFFER,
    LDAP_OFFER,
    apply_ldif,
    consume_offers,
    create_groups,
    deploy_glauth,
    generate_mongodb_ldap_client,
    teardown_offers,
)
from ...sharding_helpers import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    deploy_cluster_components,
    integrate_cluster,
)

TIMEOUT = 15 * 60
ENDPOINT_LDAP = "ldap"
ENDPOINT_LDAP_CERT = "send-ca-cert"

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: Path,
    substrate: str,
    mongod_resource,
    kubernetes_model: Model,
) -> None:
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    await deploy_cluster_components(
        ops_test,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
        extra_config_config_server={
            "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(member={PROVIDED_USER}))"
        },
    )
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
        raise_on_blocked=False,
    )
    await integrate_cluster(ops_test)
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )

    # deploy the glauth-k8s charm
    await deploy_glauth(ops_test, kubernetes_model)
    await consume_offers(ops_test, kubernetes_model)

    db_app_name = CONFIG_SERVER_APP_NAME

    await create_groups(
        ops_test, substrate, db_app_name, "ou=superheroes,ou=users,dc=glauth,dc=com"
    )

    await apply_ldif(ops_test, kubernetes_model, "add.ldif")


@pytest.mark.abort_on_fail
async def test_integrate_ldap_only(ops_test: OpsTest):
    """Only integrate ldap endpoint, should go into blocked state."""
    db_app_name = CONFIG_SERVER_APP_NAME
    await ops_test.model.integrate(f"{LDAP_OFFER}:ldap", f"{db_app_name}:ldap")
    await wait_for_mongodb_units_blocked(
        ops_test,
        db_app_name,
        status="TLS is mandatory for LDAP transport.",
        timeout=300,
    )


@pytest.mark.abort_on_fail
async def test_integrate_also_ldap_cert(ops_test: OpsTest):
    db_app_name = CONFIG_SERVER_APP_NAME
    await ops_test.model.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{db_app_name}:ldap-certificate-transfer"
    )

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_user_can_write(ops_test: OpsTest, substrate: str):
    db_app_name = CONFIG_SERVER_APP_NAME
    uri = await generate_mongodb_ldap_client(
        ops_test,
        db_app_name,
        database="superdb",
        username="cn=johndoe,ou=superheros,ou=users,dc=glauth,dc=com",
        password="dogood",
    )

    await execute_on_mongod(ops_test, db_app_name, substrate, uri, "db.test.insertOne({number: 1})")


@pytest.mark.abort_on_fail
async def test_ldap_user_to_dn_mapping(ops_test: OpsTest, substrate: str):
    db_app_name = CONFIG_SERVER_APP_NAME

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

    ssh_command = "ssh --container mongod" if substrate == "microk8s" else "ssh"

    for unit in ops_test.model.applications[db_app_name].units:
        cat_cmd = f"{ssh_command} {unit.name} cat {path}"
        return_code, output, _ = await ops_test.juju(*cat_cmd.split())

        if return_code != 0:
            raise ProcessError("Could not cat configuration.")

        configuration = safe_load(output)
        assert configuration["security"]["ldap"].get("userToDNMapping", "") != ""
        assert configuration["security"]["ldap"]["authz"].get("queryTemplate", "") != ""

    uri = await generate_mongodb_ldap_client(
        ops_test,
        db_app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    await execute_on_mongod(ops_test, db_app_name, substrate, uri, "db.test.insertOne({number: 2})")


@pytest.mark.abort_on_fail
async def test_remove_ldap_goes_to_blocked(ops_test: OpsTest):
    """Only integrate ldap endpoint, should go into blocked state."""
    db_app_name = CONFIG_SERVER_APP_NAME
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


@pytest.mark.abort_on_fail
async def test_teardown(ops_test: OpsTest, kubernetes_model: Model):
    db_app_name = CONFIG_SERVER_APP_NAME
    await ops_test.model.applications[db_app_name].remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{db_app_name}:ldap-certificate-transfer"
    )
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", timeout=TIMEOUT)

    await teardown_offers(ops_test, kubernetes_model)
