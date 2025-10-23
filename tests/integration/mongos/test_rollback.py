#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import time

import pytest
import tenacity
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.upgrade import refresh_charm

from ..helpers.common import MONGOS_APP_NAME, TIMEOUT, find_unit, get_juju_status, get_unit_id
from ..helpers.mongos import (
    MONGOS_CLIENT_APPLICATION,
    build_cluster,
    deploy_cluster_components,
    exec_on_mongos,
)
from ..helpers.types import Substrate

logger = logging.getLogger(__name__)


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
        mongos_units=3,
    )
    await build_cluster(ops_test, substrate, integrate_with_mongos=True)


@pytest.mark.abort_on_fail
async def test_failed_upgrade_and_rollback(
    ops_test: OpsTest,
    substrate: Substrate,
    mongos_charm: str,
    mongos_resource: dict[str, str],
    faulty_mongos_upgrade_charm: str,
) -> None:
    """Tests that upgrade can be ran successfully."""
    leader_unit = await find_unit(ops_test, leader=True, app_name=MONGOS_APP_NAME)
    leader_id = get_unit_id(leader_unit.name)
    mongos_application = ops_test.model.applications[MONGOS_APP_NAME]
    refresh_order = sorted(
        mongos_application.units,
        key=lambda unit: int(unit.name.split("/")[1]),
        reverse=True,
    )
    await mongos_application.refresh(path=faulty_mongos_upgrade_charm)
    logger.info("Wait for upgrade to fail")
    for attempt in tenacity.Retrying(
        reraise=True,
        stop=tenacity.stop_after_delay(TIMEOUT),
        wait=tenacity.wait_fixed(10),
    ):
        with attempt:
            assert "incompatible" in get_juju_status(
                ops_test.model.name, MONGOS_APP_NAME
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")
    await refresh_charm(ops_test, substrate, MONGOS_APP_NAME, mongos_charm, mongos_resource)

    # sleep to ensure that active status from before re-refresh does not affect below check
    time.sleep(15)
    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], idle_period=30)

    if "incompatible" in mongos_application.status_message:
        # will be marked "incompatible" if rollback is not to the same revision as initially
        # deployed
        logger.info("Rollback is blocked due to incompatibility")

        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        await refresh_order[0].run_action("force-refresh-start", **{"check-compatibility": False})

    logger.info("Wait for the charm to be rolled back")
    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], idle_period=20)

    if "resume-refresh" in get_juju_status(ops_test.model.name, MONGOS_APP_NAME):
        action = await leader_unit.run_action("resume-refresh")
        await action.wait()
        if (substrate == "lxd") or (substrate == "microk8s" and leader_id != 0):
            assert action.status == "completed", "resume-refresh failed, expected to succeed."
        assert action.status == "completed", "resume-refresh failed, expected to succeed"

    for unit in mongos_application.units:
        number = unit.name.split("/")[-1]
        cmd = f"db.test_collection.insertOne({{number: {number}}} );"
        check = await exec_on_mongos(
            ops_test, substrate, unit, auth=True, app_name=MONGOS_CLIENT_APPLICATION, cmd=cmd
        )
        assert check, "mongos user failed to write data"
