#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    find_unit,
    stop_continous_writes,
)
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
from ...helpers.upgrade import refresh_charm, refresh_with_juju


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, substrate: Substrate, mongodb_charm, mongod_resource
) -> None:
    """Build and deploy one unit of MongoDB."""
    num_units_cluster_config = {
        CONFIG_SERVER_APP_NAME: 3,
        SHARD_ONE_APP_NAME: 3,
        SHARD_TWO_APP_NAME: 1,
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
        timeout=TIMEOUT,
        idle_period=20,
        raise_on_blocked=False,
        raise_on_error=False,
        status="active",
    )


@pytest.mark.abort_on_fail
async def test_rollback_on_config_server(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm,
    mongod_resource,
    add_continuous_writes_to_shards,
) -> None:
    """Verify that the config-server can safely rollback without losing writes."""
    config_server_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_APP_NAME)
    action = await config_server_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "completed", "pre-refresh-check failed, expected to succeed."

    await refresh_charm(ops_test, substrate, CONFIG_SERVER_APP_NAME, mongodb_charm, mongod_resource)

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME], timeout=TIMEOUT, idle_period=120
    )

    # instead of resuming upgrade refresh with the old version
    # TODO: Use this when https://github.com/juju/python-libjuju/issues/1086 is fixed
    # await ops_test.model.applications[CONFIG_SERVER_APP_NAME].refresh(
    #     channel="6/edge", switch="ch:mongodb"
    # )
    await refresh_with_juju(ops_test, CONFIG_SERVER_APP_NAME, "6/edge")

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        timeout=1000,
        idle_period=30,
    )

    # verify no writes were skipped during upgrade/rollback process
    shard_one_expected_writes = await stop_continous_writes(
        ops_test,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_ONE_DB_NAME,
        coll_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_expected_writes = await stop_continous_writes(
        ops_test,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
    )

    shard_one_actual_writes = await count_shard_writes(
        ops_test,
        substrate,
        CONFIG_SERVER_APP_NAME,
        SHARD_ONE_DB_NAME,
        collection_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_actual_writes = await count_shard_writes(
        ops_test,
        substrate,
        CONFIG_SERVER_APP_NAME,
        SHARD_TWO_DB_NAME,
        collection_name=SHARD_TWO_COLL_NAME,
    )
    assert (
        shard_one_actual_writes == shard_one_expected_writes
    ), "continuous writes to shard one failed during upgrade"
    assert (
        shard_two_actual_writes == shard_two_expected_writes
    ), "continuous writes to shard two failed during upgrade"

    await ops_test.model.wait_for_idle(apps=CLUSTER_COMPONENTS, timeout=1000, idle_period=20)
