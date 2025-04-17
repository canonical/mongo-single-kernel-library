#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
from juju.model import Model
from pytest_operator.plugin import OpsTest

from ...helpers import (
    DATA_INTEGRATOR_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    check_or_scale_app,
    deploy_charm,
    get_app_name,
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
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_TWO_APP_NAME,
    deploy_cluster_components,
    integrate_cluster,
)

TIMEOUT = 15 * 60


@pytest.mark.abort_on_fail
async def test_build_and_deploy_mongodb_cluster(
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

    await create_groups(ops_test, db_app_name, "ou=superheroes,ou=users,dc=glauth,dc=com")

    await apply_ldif(ops_test, kubernetes_model, "add.ldif")


@pytest.mark.abort_on_fail
async def test_build_and_deploy_mongos(
    ops_test: OpsTest, mongos_charm: Path, substrate: str, mongod_resource, base_app_name
) -> None:
    if app_name := await get_app_name(ops_test, ch_name="mongos"):
        await check_or_scale_app(ops_test, app_name, 3)
    else:
        await deploy_charm(
            ops_test=ops_test,
            charm=mongos_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=3,
            subordinate=(substrate == "lxd"),
        )
        app_name = base_app_name

    await ops_test.model.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="edge",
        base="ubuntu@22.04",
        num_units=2,
        config={"database-name": "test-database"},
    )
    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)

    await ops_test.model.integrate(DATA_INTEGRATOR_APP_NAME, app_name)

    # verify that Charmed Mongos is blocked and reports incorrect credentials
    await wait_for_mongodb_units_blocked(
        ops_test,
        app_name,
        status="Missing relation to config-server.",
        timeout=300,
    )

    # connect sharded cluster to mongos
    await ops_test.model.integrate(
        f"{app_name}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, app_name],
        idle_period=20,
        status="active",
    )


@pytest.mark.abort_on_fail
async def test_only_mongos_integrated(ops_test: OpsTest):
    app_name = await get_app_name(ops_test, ch_name="mongos")

    await ops_test.model.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    await ops_test.model.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer"
    )
    # We go to blocked because config server is not integrated with ldap.
    await wait_for_mongodb_units_blocked(
        ops_test,
        app_name,
        status="mongos and config-server not integrated with the same ldap server.",
        timeout=300,
    )


@pytest.mark.abort_on_fail
async def test_all_integrated(ops_test: OpsTest):
    app_name = await get_app_name(ops_test, ch_name="mongos")

    await ops_test.model.integrate(f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap")
    await ops_test.model.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{CONFIG_SERVER_APP_NAME}:ldap-certificate-transfer"
    )

    # Everything should be integrated now!
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, app_name],
        idle_period=20,
        status="active",
    )


@pytest.mark.abort_on_fail
async def test_user_can_write(ops_test: OpsTest):
    app_name = await get_app_name(ops_test, ch_name="mongos")

    # We create a client which should be able to write
    client = generate_mongodb_ldap_client(
        ops_test,
        app_name,
        database="superdb",
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
        mongos=True,
    )

    client.superdb["test-collection"].insert_one({"number": 1})


@pytest.mark.abort_on_fail
async def test_only_mongodb_integrated(ops_test: OpsTest):
    app_name = await get_app_name(ops_test, ch_name="mongos")
    await ops_test.model.applications[CONFIG_SERVER_APP_NAME].remove_relation(
        f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap"
    )
    await ops_test.model.applications[CONFIG_SERVER_APP_NAME].remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{CONFIG_SERVER_APP_NAME}:ldap-certificate-transfer"
    )
    await wait_for_mongodb_units_blocked(
        ops_test,
        app_name,
        status="mongos and config-server not integrated with the same ldap server.",
        timeout=300,
    )


@pytest.mark.abort_on_fail
async def test_teardown(ops_test: OpsTest, kubernetes_model: Model):
    app_name = await get_app_name(ops_test, ch_name="mongos")
    await ops_test.model.applications[app_name].remove_relation(
        f"{LDAP_OFFER}:ldap", f"{app_name}:ldap"
    )
    await ops_test.model.applications[app_name].remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer"
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, app_name],
        status="active",
        timeout=TIMEOUT,
    )
    await teardown_offers(ops_test, kubernetes_model)
