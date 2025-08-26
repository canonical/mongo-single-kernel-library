#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    MONGOS_APP_NAME,
    MONGOS_PORT,
    check_status_detail,
    execute_on_mongod,
    get_mongodb_hostname_for_unit,
    remove_units,
    wait_for_mongodb_units_blocked,
)
from ..helpers.mongos import (
    MONGOS_CLIENT_APPLICATION,
    MONGOS_SOCKET,
    TEST_DB_NAME,
    TEST_USER_NAME,
    TEST_USER_PWD,
    deploy_cluster_components,
    generate_mongos_uri,
    is_mongos_running,
)
from ..helpers.sharding import (
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
)
from ..helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict,
    mongos_resource: dict,
    mongos_client_application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        mongos_client_application_path,
    )


@pytest.mark.abort_on_fail
async def test_waits_for_config_server(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verifies that the application and unit are active."""
    await ops_test.model.integrate(MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME)

    # verify that Charmed Mongos is blocked and reports incorrect credentials
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        MONGOS_APP_NAME,
        status="Cluster relation is missing",
        timeout=300,
        subordinate=(substrate == "lxd"),
    )

    await check_status_detail(
        ops_test,
        MONGOS_APP_NAME,
        status="blocked",
        message="The cluster relation with the config-server is missing",
    )


@pytest.mark.abort_on_fail
async def test_mongos_starts_with_config_server(ops_test: OpsTest, substrate: Substrate) -> None:
    """Integrate the cluster and checks that mongos starts."""
    # prepare sharded cluster
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME],
        idle_period=10,
        raise_on_blocked=False,
    )
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
    )

    # connect sharded cluster to mongos
    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, MONGOS_APP_NAME],
        idle_period=20,
        status="active",
    )

    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    mongos_running = await is_mongos_running(
        ops_test, substrate, mongos_unit, app_name=MONGOS_APP_NAME, auth=False
    )
    assert mongos_running, "Mongos is not currently running."


@pytest.mark.abort_on_fail
async def test_mongos_has_user(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos has user by running a check with authentication."""
    # prepare sharded cluster
    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    mongos_running = await is_mongos_running(
        ops_test, substrate, mongos_unit, app_name=MONGOS_CLIENT_APPLICATION, auth=True
    )
    assert mongos_running, "Mongos is not currently running."


@pytest.mark.abort_on_fail
async def test_mongos_updates_config_db(ops_test: OpsTest, substrate: Substrate) -> None:
    """Checks that mongos supports scale up and down of config server."""
    # completely change the hosts that mongos was connected to
    await ops_test.model.applications[CONFIG_SERVER_APP_NAME].add_units(count=1)
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME],
        status="active",
        timeout=1000,
    )

    # destroy the unit we were initially connected to
    config_server_unit = ops_test.model.applications[CONFIG_SERVER_APP_NAME].units[0]
    await remove_units(ops_test, substrate, CONFIG_SERVER_APP_NAME, [config_server_unit])
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME],
        status="active",
        timeout=1000,
    )

    # prepare sharded cluster
    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    mongos_running = await is_mongos_running(
        ops_test, substrate, mongos_unit, app_name=MONGOS_CLIENT_APPLICATION, auth=True
    )
    assert mongos_running, "Mongos is not currently running."


@pytest.mark.abort_on_fail
async def test_user_with_extra_roles(ops_test: OpsTest, substrate: Substrate) -> None:
    """Check that we can create user with extra roles, and that it is accessible."""
    cmd = f"db.createUser({{user: '{TEST_USER_NAME}', pwd: '{TEST_USER_PWD}', roles: [{{'role': 'readWrite', 'db': '{TEST_DB_NAME}'}}]}})"
    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    uri = await generate_mongos_uri(
        ops_test, substrate, auth=True, app_name=MONGOS_CLIENT_APPLICATION
    )
    res = await execute_on_mongod(
        ops_test, MONGOS_APP_NAME, substrate, uri, cmd, container_name="mongos"
    )
    assert (
        res.succeeded
    ), f"mongos user does not have correct permissions to create new user, error: {res.stderr}"

    if substrate == "lxd":
        test_user_uri = f"mongodb://{TEST_USER_NAME}:{TEST_USER_PWD}@{MONGOS_SOCKET}/{TEST_DB_NAME}"
    else:
        hostname = await get_mongodb_hostname_for_unit(ops_test, substrate, mongos_unit.name)
        test_user_uri = (
            f"mongodb://{TEST_USER_NAME}:{TEST_USER_PWD}@{hostname}:{MONGOS_PORT}/{TEST_DB_NAME}"
        )
    mongos_running = await is_mongos_running(
        ops_test,
        substrate,
        mongos_unit,
        app_name=MONGOS_APP_NAME,
        auth=True,
        uri=test_user_uri,
    )
    assert mongos_running, "User created is not accessible."


@pytest.mark.abort_on_fail
async def test_mongos_can_scale(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos powers down when no config server is accessible."""
    if substrate == "lxd":
        # note mongos scales only when hosting application scales
        await ops_test.model.applications[MONGOS_CLIENT_APPLICATION].add_units(count=1)
    else:
        await ops_test.model.applications[MONGOS_APP_NAME].scale(2)
    await ops_test.model.wait_for_idle(
        apps=[MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME],
        status="active",
        timeout=1000,
    )

    for mongos_unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        mongos_running = await is_mongos_running(
            ops_test, substrate, mongos_unit, app_name=MONGOS_CLIENT_APPLICATION, auth=True
        )
        assert mongos_running, "Mongos is not currently running."

    # destroy the unit we were initially connected to
    if substrate == "lxd":
        await ops_test.model.applications[MONGOS_CLIENT_APPLICATION].destroy_units(
            f"{MONGOS_CLIENT_APPLICATION}/0"
        )
    else:
        await ops_test.model.applications[MONGOS_APP_NAME].scale(scale_change=-1)

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME],
        status="active",
        timeout=1000,
    )

    # prepare sharded cluster
    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    mongos_running = await is_mongos_running(
        ops_test, substrate, mongos_unit, app_name=MONGOS_CLIENT_APPLICATION, auth=True
    )
    assert mongos_running, "Mongos is not currently running."
