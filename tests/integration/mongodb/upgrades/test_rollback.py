#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time
from pathlib import Path

import pytest
import tomllib
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
    find_unit,
    get_app_name,
    get_juju_status,
    get_unit_id,
)
from tests.integration.helpers.types import Substrate
from tests.integration.helpers.upgrade import get_workload_version, refresh_with_juju

logger = logging.getLogger(__name__)

UPGRADE_TIMEOUT = 15 * 60


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, substrate: Substrate, base_app_name) -> None:
    """Build and deploy one unit of MongoDB."""
    if substrate == "lxd":
        mongodb_charm_name = "mongodb"
    else:
        mongodb_charm_name = "mongodb-k8s"

    await ops_test.model.deploy(
        mongodb_charm_name,
        channel="8/edge",
        num_units=3,
        application_name=base_app_name,
        trust=(substrate == "microk8s"),
    )

    await ops_test.model.wait_for_idle(
        apps=[base_app_name], status="active", timeout=DEPLOYMENT_TIMEOUT, idle_period=120
    )


@pytest.mark.abort_on_fail
async def test_rollback(
    ops_test: OpsTest,
    substrate: Substrate,
    base_app_name: str,
    mongod_base_path: Path,
    mongodb_charm: str,
    mongod_resource: dict,
    faulty_mongodb_upgrade_charm: Path,
) -> None:
    app_name = await get_app_name(ops_test)
    mongodb_application = ops_test.model.applications[app_name]
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    leader_id = get_unit_id(leader_unit.name)

    resources = mongod_resource if substrate == "microk8s" else None

    refresh_order = sorted(
        mongodb_application.units,
        key=lambda unit: int(unit.name.split("/")[1]),
        reverse=True,
    )

    initial_version_path = mongod_base_path / "refresh_versions.toml"
    data = tomllib.loads(initial_version_path.read_text())
    initial_version = data["workload"]

    await mongodb_application.refresh(path=faulty_mongodb_upgrade_charm, resources=resources)
    logger.info("Wait for refresh to fail")

    for attempt in Retrying(
        reraise=True,
        stop=stop_after_delay(UPGRADE_TIMEOUT),
        wait=wait_fixed(10),
    ):
        with attempt:
            assert "incompatible" in get_juju_status(
                ops_test.model.name, app_name
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")

    await refresh_with_juju(ops_test, app_name, "8/edge", charm_name=base_app_name)

    # sleep to ensure that active status from before re-refresh does not affect below check
    time.sleep(15)
    await ops_test.model.wait_for_idle(apps=[app_name], idle_period=30)
    if any(
        item in get_juju_status(ops_test.model.name, app_name)
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

    await ops_test.model.wait_for_idle(apps=[app_name], idle_period=20)

    if "resume-refresh" in get_juju_status(ops_test.model.name, app_name):
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

    logger.info("Wait for the charm to be rolled back")
    await ops_test.model.wait_for_idle(
        apps=[app_name],
        status="active",
        timeout=1000,
        idle_period=30,
    )

    for unit in mongodb_application.units:
        workload_version = await get_workload_version(ops_test, unit.name)
        assert workload_version == initial_version
