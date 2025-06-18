#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pymongo.errors import OperationFailure
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from ...helpers.common import (
    DATA_INTEGRATOR_APP_NAME,
    MONGOS_APP_NAME,
    TIMEOUT,
    deploy_charm,
    get_direct_mongo_client,
    get_username_password,
)
from ...helpers.sharding import (
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    count_users,
)
from ...helpers.types import Substrate


async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    mongos_charm: str,
    substrate: Substrate,
    mongod_resource,
    mongos_resource,
) -> None:
    """Build and deploy a sharded cluster."""
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=SHARD_ONE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )
    await deploy_charm(
        ops_test,
        mongos_charm,
        substrate,
        app_name=MONGOS_APP_NAME,
        mongod_resource=mongos_resource,
        num_units=(1 if substrate == "microk8s" else 0),
    )
    await ops_test.model.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        series="jammy",
        config={"extra-user-roles": "admin", "database-name": "test-database"},
    )


@pytest.mark.abort_on_fail
async def test_connect_to_cluster_creates_user(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verifies that when the cluster is formed a new user is created."""
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[SHARD_ONE_APP_NAME, CONFIG_SERVER_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
        status="active",
    )

    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}",
        f"{DATA_INTEGRATOR_APP_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[
            DATA_INTEGRATOR_APP_NAME,
            MONGOS_APP_NAME,
            SHARD_ONE_APP_NAME,
            CONFIG_SERVER_APP_NAME,
        ],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
        raise_on_error=False,
    )

    mongos_client = await get_direct_mongo_client(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, mongos=True
    )
    num_users = count_users(mongos_client)

    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}",
        f"{CONFIG_SERVER_APP_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, MONGOS_APP_NAME],
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_error=False,
    )

    num_users_after_integration = count_users(mongos_client)

    assert (
        num_users_after_integration > num_users
    ), "Cluster did not create new users after integration."

    (username, password) = await get_username_password(
        ops_test, app_name=MONGOS_APP_NAME, relation_name=CLUSTER_REL_NAME
    )
    mongos_user_client = await get_direct_mongo_client(
        ops_test,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongos=True,
        username=username,
        password=password,
    )

    mongos_user_client.admin.command("dbStats")


@pytest.mark.abort_on_fail
async def test_disconnect_from_cluster_removes_user(
    ops_test: OpsTest, substrate: Substrate
) -> None:
    """Verifies that when the cluster is formed a the user is removed."""
    # generate URI for new mongos user
    (username, password) = await get_username_password(
        ops_test, app_name=MONGOS_APP_NAME, relation_name=CLUSTER_REL_NAME
    )
    mongos_user_client = await get_direct_mongo_client(
        ops_test,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongos=True,
        username=username,
        password=password,
    )

    # generate URI for operator mongos user (i.e. admin)
    mongos_client = await get_direct_mongo_client(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, mongos=True
    )
    num_users = count_users(mongos_client)

    await ops_test.model.applications[MONGOS_APP_NAME].remove_relation(
        f"{MONGOS_APP_NAME}:cluster",
        f"{CONFIG_SERVER_APP_NAME}:cluster",
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, MONGOS_APP_NAME],
        status="active",
        idle_period=30,
        timeout=TIMEOUT,
        raise_on_error=False,
    )

    for attempt in Retrying(stop=stop_after_delay(300), wait=wait_fixed(10), reraise=True):
        with attempt:
            num_users_after_removal = count_users(mongos_client)
            assert (
                num_users > num_users_after_removal
            ), "Cluster did not remove user after integration removal."

    with pytest.raises(OperationFailure) as pymongo_error:
        mongos_user_client.admin.command("dbStats")

    assert pymongo_error.value.code == 18, "User still exists after relation was removed."
