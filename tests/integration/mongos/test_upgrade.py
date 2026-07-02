#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    MONGOS_APP_NAME,
    find_unit,
    get_juju_status,
    get_unit_id,
)
from tests.integration.helpers.mongos import build_cluster, deploy_cluster_components
from tests.integration.helpers.types import Substrate
from tests.integration.helpers.upgrade import refresh_charm

logger = logging.getLogger()


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
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
        channel="8/edge",
        mongos_units=2,
    )
    await build_cluster(ops_test, substrate, integrate_with_mongos=True)


@pytest.mark.abort_on_fail
async def test_upgrade(
    ops_test: OpsTest, substrate: Substrate, mongos_charm: str, mongos_resource: dict[str, str]
):
    """Refreshes the charm and wait for it to be active again."""
    leader_unit = await find_unit(ops_test, leader=True, app_name=MONGOS_APP_NAME)
    leader_id = get_unit_id(leader_unit.name)
    mongodb_application = ops_test.model.applications[MONGOS_APP_NAME]
    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        mongodb_application.units,
        key=lambda unit: int(unit.name.split("/")[1]),
        reverse=True,
    )
    await refresh_charm(ops_test, substrate, MONGOS_APP_NAME, mongos_charm, mongos_resource)
    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], timeout=1000, idle_period=60)

    if "incompatible" in get_juju_status(ops_test.model.name, MONGOS_APP_NAME):
        logger.info("Upgrade is blocked due to incompatibility")

        logger.info(f"Continue refresh on unit {refresh_order[0].name}")
        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_action = await refresh_order[0].run_action(
            "force-refresh-start",
            **{
                "check-compatibility": False,
                "run-pre-refresh-checks": False,
                "check-workload-container": False,
            },
        )
        force_refresh_response = await force_refresh_action.wait()
        assert force_refresh_response.results.get("return-code") == 0, "action failed"

    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], idle_period=20)

    if "resume-refresh" in mongodb_application.status_message:
        logger.info("Continue refresh on all other units with `resume-refresh` action")
        logger.info("Calling resume refresh")
        if substrate == "lxd":
            unit = refresh_order[1]
        else:
            unit = leader_unit

        action = await unit.run_action("resume-refresh")
        await action.wait()
        if (substrate == "lxd") or (
            substrate == "microk8s" and leader_id != get_unit_id(refresh_order[1].name)
        ):
            assert action.status == "completed", "resume-refresh failed, expected to succeed."
