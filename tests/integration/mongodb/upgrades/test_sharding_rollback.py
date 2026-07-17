#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    find_unit,
    get_juju_status,
    get_unit_id,
    stop_continous_writes,
)
from tests.integration.helpers.sharding import (
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
from tests.integration.helpers.types import Substrate
from tests.integration.helpers.upgrade import refresh_charm, refresh_with_juju
from tests.integration.mongodb.upgrades.test_rollback import UPGRADE_TIMEOUT

logger = logging.getLogger()


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
        channel="8/edge",
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
    base_app_name: str,
    mongodb_charm: dict[str, str],
    mongod_resource: dict[str, str],
    faulty_mongodb_upgrade_charm,
    add_continuous_writes_to_shards,
) -> None:
    """Verify that the config-server can safely rollback without losing writes."""
    config_server_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_APP_NAME)
    leader_id = get_unit_id(config_server_unit.name)

    logger.info("Running pre refresh checks")
    action = await config_server_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "completed", "pre-refresh-check failed, expected to succeed."

    mongodb_application = ops_test.model.applications[CONFIG_SERVER_APP_NAME]
    refresh_order = sorted(
        mongodb_application.units,
        key=lambda unit: int(unit.name.split("/")[1]),
        reverse=True,
    )

    logger.info("Refresing the charm")
    await refresh_charm(
        ops_test, substrate, CONFIG_SERVER_APP_NAME, faulty_mongodb_upgrade_charm, mongod_resource
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME], timeout=TIMEOUT, idle_period=120
    )
    for attempt in Retrying(
        reraise=True,
        stop=stop_after_delay(UPGRADE_TIMEOUT),
        wait=wait_fixed(10),
    ):
        with attempt:
            assert "incompatible" in get_juju_status(
                ops_test.model.name, CONFIG_SERVER_APP_NAME
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")

    # instead of resuming upgrade refresh with the old version
    # TODO: Use this when https://github.com/juju/python-libjuju/issues/1086 is fixed
    # await ops_test.model.applications[CONFIG_SERVER_APP_NAME].refresh(
    #     channel="6/edge", switch="ch:mongodb"
    # )
    await refresh_with_juju(ops_test, CONFIG_SERVER_APP_NAME, "8/edge", charm_name=base_app_name)

    await ops_test.model.wait_for_idle(apps=[CONFIG_SERVER_APP_NAME], idle_period=30)

    if any(
        item in get_juju_status(ops_test.model.name, CONFIG_SERVER_APP_NAME)
        for item in ("incompatible", "missing/incorrect")
    ):
        # will be marked "incompatible" if rollback is not to the same revision as initially
        # deployed
        logger.info("Rollback is blocked due to incompatibility")

        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        action = await refresh_order[0].run_action(
            "force-refresh-start",
            **{"check-compatibility": False, "check-workload-container": False},
        )
        result = await action.wait()
        logger.info(f"force refresh start {result}")
        assert result.results.get("return-code") == 0, "force-refresh-start failed"

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME], idle_period=20, raise_on_blocked=False
    )

    if "resume-refresh" in get_juju_status(ops_test.model.name, CONFIG_SERVER_APP_NAME):
        if substrate == "lxd":
            unit = refresh_order[1]
        else:
            unit = config_server_unit

        action = await unit.run_action("resume-refresh")
        await action.wait()
        if (substrate == "lxd") or (
            substrate == "microk8s" and leader_id != get_unit_id(refresh_order[1].name)
        ):
            assert action.status == "completed", "resume-refresh failed, expected to succeed."

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
