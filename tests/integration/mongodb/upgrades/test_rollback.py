#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import shutil
import time
import zipfile
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    find_unit,
    get_app_name,
    get_juju_status,
)
from ...helpers.types import Substrate
from ...helpers.upgrade import get_workload_version

logger = logging.getLogger(__name__)

UPGRADE_TIMEOUT = 15 * 60


@pytest.fixture
async def faulty_upgrade_charm(mongod_base_path: Path, mongodb_charm: str, tmp_path: Path):
    fault_charm = tmp_path / "fault_charm.charm"
    shutil.copy(mongodb_charm, fault_charm)
    initial_version_path = mongod_base_path / Path("workload_version")
    workload_version = initial_version_path.read_text().strip()

    [major, minor, patch] = workload_version.split(".")

    with zipfile.ZipFile(fault_charm, mode="a") as charm_zip:
        charm_zip.writestr("workload_version", f"{int(major) - 1}.{minor}.{patch}+testrollback")

    yield fault_charm


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, substrate: Substrate, base_app_name) -> None:
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == "lxd" else "mongodb-k8s"

    await ops_test.model.deploy(
        mongodb_charm_name, channel="6/edge", num_units=3, application_name=base_app_name
    )

    await ops_test.model.wait_for_idle(
        apps=[base_app_name], status="active", timeout=DEPLOYMENT_TIMEOUT, idle_period=120
    )


@pytest.mark.abort_on_fail
async def test_rollback(
    ops_test: OpsTest, mongod_base_path: Path, mongodb_charm: str, faulty_upgrade_charm: Path
) -> None:
    app_name = await get_app_name(ops_test)

    mongodb_application = ops_test.model.applications[app_name]

    initial_version_path = mongod_base_path / Path("workload_version")
    initial_version = initial_version_path.read_text().strip()

    await mongodb_application.refresh(path=faulty_upgrade_charm)
    logger.info("Wait for refresh to fail")

    for attempt in Retrying(
        reraise=True,
        stop=stop_after_delay(UPGRADE_TIMEOUT),
        wait=wait_fixed(10),
    ):
        with attempt:
            assert "Refresh incompatible" in get_juju_status(
                ops_test.model.name, app_name
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")
    await mongodb_application.refresh(path=mongodb_charm)
    # sleep to ensure that active status from before re-refresh does not affect below check

    time.sleep(15)
    await ops_test.model.block_until(
        lambda: all(unit.workload_status == "active" for unit in mongodb_application.units)
        and all(unit.agent_status == "idle" for unit in mongodb_application.units),
        wait_period=15,
    )

    logger.info("Running resume-refresh on the leader unit")
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    action = await leader_unit.run_action("resume-refresh")
    await action.wait()

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
