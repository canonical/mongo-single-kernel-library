#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
from juju.model import Model
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DATA_INTEGRATOR_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    check_or_scale_app,
    check_status_detail,
    deploy_charm,
    execute_on_mongod,
    get_app_name,
    wait_for_mongodb_units_blocked,
)
from ...helpers.ldap import (
    LDAP_CERT_OFFER,
    LDAP_OFFER,
    apply_ldif,
    consume_glauth_offers,
    create_mongodb_user_roles,
    deploy_glauth,
    generate_mongodb_ldap_client,
    teardown_offers,
)
from ...helpers.sharding import (
    CLUSTER_COMPONENTS,
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_TWO_APP_NAME,
    deploy_cluster_components,
    integrate_sharding_components,
)
from ...helpers.types import Substrate

TIMEOUT = 15 * 60


@pytest.mark.abort_on_fail
async def test_build_and_deploy_mongodb_cluster(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource,
    kubernetes_model: Model,
) -> None:
    """Build and deploy one unit of MongoDB."""
    # deploy the glauth-k8s charm
    await deploy_glauth(ops_test, kubernetes_model)
    await consume_glauth_offers(ops_test, kubernetes_model)

    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    await deploy_cluster_components(
        ops_test,
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
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
        raise_on_blocked=False,
    )
    await integrate_sharding_components(ops_test)
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )

    await create_mongodb_user_roles(
        ops_test, substrate, CONFIG_SERVER_APP_NAME, "ou=superheroes,ou=users,dc=glauth,dc=com"
    )

    await apply_ldif(ops_test, kubernetes_model, "ldap_entries.ldif")


@pytest.mark.abort_on_fail
async def test_build_and_deploy_mongos(
    ops_test: OpsTest, mongos_charm: Path, substrate: Substrate, mongod_resource, base_app_name
) -> None:
    """Deploys mongos and data integrator, and integrates both.

    Then integrate mongos and sharded cluster.
    """
    if app_name := await get_app_name(ops_test, charm_name="mongos"):
        await check_or_scale_app(ops_test, substrate, app_name, 1)
    else:
        await deploy_charm(
            ops_test=ops_test,
            charm=mongos_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=1,
            subordinate=(substrate == "lxd"),
        )
        app_name = base_app_name

    # This is necessary for mongos operator on VM, but we deploy it anyway for flow unicity.
    await ops_test.model.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        series="jammy",
        num_units=1,
        config={"database-name": "test-database"},
    )
    await ops_test.model.wait_for_idle(apps=[DATA_INTEGRATOR_APP_NAME], timeout=DEPLOYMENT_TIMEOUT)

    await ops_test.model.integrate(DATA_INTEGRATOR_APP_NAME, app_name)

    # verify that Charmed Mongos is blocked and reports incorrect credentials
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        app_name,
        status="Missing relation to config-server.",
        timeout=300,
        subordinate=(substrate == "lxd"),
    )
    await check_status_detail(
        ops_test,
        app_name,
        status="blocked",
        message="Missing relation to config-server.",
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
async def test_glauth_only_integrated_with_mongos(ops_test: OpsTest, substrate: Substrate):
    """Integrate only mongos, it should go to a blocked state.

    This is because config server is not integrated with LDAP.
    """
    app_name = await get_app_name(ops_test, charm_name="mongos")

    await ops_test.model.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        app_name,
        status="TLS is mandatory for LDAP transport.",
        timeout=300,
        subordinate=(substrate == "lxd"),
    )
    await ops_test.model.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer"
    )
    # We go to blocked because config server is not integrated with ldap.
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        app_name,
        status="mongos and config-server not integrated with the same ldap server.",
        timeout=600,
        subordinate=(substrate == "lxd"),
    )


@pytest.mark.abort_on_fail
async def test_glauth_fully_integrated(ops_test: OpsTest, substrate: Substrate):
    """Integrate the config server as well, everything should be green."""
    app_name = await get_app_name(ops_test, charm_name="mongos")

    await ops_test.model.integrate(f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap")
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        CONFIG_SERVER_APP_NAME,
        status="TLS is mandatory for LDAP transport.",
        timeout=300,
    )

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
async def test_user_can_write(ops_test: OpsTest, substrate: Substrate):
    app_name = await get_app_name(ops_test, charm_name="mongos")

    # We create a client which should be able to write
    uri = await generate_mongodb_ldap_client(
        ops_test,
        substrate,
        app_name,
        database="superdb",
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
        mongos=True,
    )

    result = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        "db.test.insertOne({number: 1})",
        container_name="mongos",
    )
    assert result.succeeded, "Failed to insert value with LDAP client"

    await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        "db.test.findOne({number: 1})",
        container_name="mongos",
    )
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
async def test_teardown(ops_test: OpsTest, kubernetes_model: Model):
    app_name = await get_app_name(ops_test, charm_name="mongos")
    await ops_test.model.applications[app_name].remove_relation(
        f"{LDAP_OFFER}:ldap", f"{app_name}:ldap"
    )
    await ops_test.model.applications[app_name].remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer"
    )
    await ops_test.model.applications[app_name].remove_relation(
        f"{LDAP_OFFER}:ldap", f"{CONFIG_SERVER_APP_NAME}:ldap"
    )
    await ops_test.model.applications[app_name].remove_relation(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{CONFIG_SERVER_APP_NAME}:ldap-certificate-transfer"
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, app_name],
        status="active",
        timeout=TIMEOUT,
    )
    await teardown_offers(ops_test, kubernetes_model)
