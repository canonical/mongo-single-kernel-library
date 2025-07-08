#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    find_unit,
    stop_continous_writes,
    unit_hostname,
)
from ...helpers.ha import cut_network_from_unit, restore_network_for_unit
from ...helpers.sharding import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_ONE_COLL_NAME,
    SHARD_ONE_DB_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_TWO_COLL_NAME,
    SHARD_TWO_DB_NAME,
    count_shard_writes,
    deploy_cluster_components,
    integrate_sharding_components,
)
from ...helpers.types import Substrate
from ...helpers.upgrade import assert_successful_run_upgrade_sequence


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, substrate: Substrate, mongodb_charm, mongod_resource, application_path
) -> None:
    """Build and deploy one unit of MongoDB."""
    num_units_cluster_config = {
        CONFIG_SERVER_APP_NAME: 3,
        SHARD_ONE_APP_NAME: 3,
        SHARD_TWO_APP_NAME: 3,
    }

    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongod_resource,
        num_units_cluster_config=num_units_cluster_config,
        channel="6/stable",
    )
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_blocked=False,
        raise_on_error=False,
    )

    await integrate_sharding_components(ops_test)
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        timeout=DEPLOYMENT_TIMEOUT,
        status="active",
        idle_period=20,
        raise_on_blocked=False,
        raise_on_error=False,
    )


@pytest.mark.abort_on_fail
async def test_upgrade(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm,
    mongod_resource,
    add_continuous_writes_to_shards,
) -> None:
    """Verify that the sharded cluster can be safely upgraded without losing writes."""
    for sharding_component in CLUSTER_COMPONENTS:
        await assert_successful_run_upgrade_sequence(
            ops_test,
            substrate,
            app_name=sharding_component,
            new_charm=mongodb_charm,
            mongod_resource=mongod_resource,
        )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        timeout=1000,
        idle_period=30,
        raise_on_error=False,
    )

    shard_one_expected_writes = await stop_continous_writes(
        ops_test,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_ONE_DB_NAME,
        coll_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_total_expected_writes = await stop_continous_writes(
        ops_test,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
    )

    actual_shard_one_writes = await count_shard_writes(
        ops_test,
        substrate,
        config_server_name=CONFIG_SERVER_APP_NAME,
        db_name=SHARD_ONE_DB_NAME,
        collection_name=SHARD_ONE_COLL_NAME,
    )
    actual_shard_two_writes = await count_shard_writes(
        ops_test,
        substrate,
        config_server_name=CONFIG_SERVER_APP_NAME,
        db_name=SHARD_TWO_DB_NAME,
        collection_name=SHARD_TWO_COLL_NAME,
    )

    assert (
        actual_shard_one_writes == shard_one_expected_writes
    ), "missed writes during upgrade procedure."
    assert (
        actual_shard_two_writes == shard_two_total_expected_writes
    ), "missed writes during upgrade procedure."


@pytest.mark.abort_on_fail
async def test_pre_upgrade_check_success(ops_test: OpsTest) -> None:
    """Verify that the pre-refresh check succeeds in the happy path."""
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        timeout=1000,
        idle_period=30,
        raise_on_error=False,
    )

    for sharding_component in CLUSTER_COMPONENTS:
        leader_unit = await find_unit(ops_test, leader=True, app_name=sharding_component)
        action = await leader_unit.run_action("pre-refresh-check")
        await action.wait()
        assert action.status == "completed", "pre-refresh-check failed, expected to succeed."


@pytest.mark.abort_on_fail
async def test_pre_upgrade_check_failure(
    ops_test: OpsTest, substrate: Substrate, chaos_mesh
) -> None:
    """Verify that the pre-refresh check fails if there is a problem with one of the shards."""
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        timeout=1000,
        idle_period=30,
        raise_on_error=False,
    )

    leader_unit = await find_unit(ops_test, leader=True, app_name=SHARD_TWO_APP_NAME)

    non_leader_unit = None
    for unit in ops_test.model.applications[SHARD_TWO_APP_NAME].units:
        if unit.name != leader_unit.name:
            non_leader_unit = unit
            break

    assert non_leader_unit, "No non leader unit found"

    if substrate == "lxd":
        hostname = await unit_hostname(ops_test, non_leader_unit.name)
    else:
        hostname = non_leader_unit.name
    cut_network_from_unit(ops_test, substrate, hostname)

    for sharding_component in CLUSTER_COMPONENTS:
        leader_unit = await find_unit(ops_test, leader=True, app_name=sharding_component)
        action = await leader_unit.run_action("pre-refresh-check")
        await action.wait()
        assert action.status == "failed", "pre-refresh-check succeeded, expected to fail."

    # restore network after test
    restore_network_for_unit(ops_test, substrate, hostname)
    await ops_test.model.wait_for_idle(
        apps=[SHARD_TWO_APP_NAME],
        status="active",
        timeout=1000,
        idle_period=30,
        raise_on_error=False,
    )
