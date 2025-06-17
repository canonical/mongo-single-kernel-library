#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import time

import pytest
import tenacity
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.upgrade import refresh_charm

from ..helpers.common import MONGOS_APP_NAME, TIMEOUT, get_juju_status
from ..helpers.mongos import (
    MONGOS_CLIENT_APPLICATION,
    build_cluster,
    check_mongos,
    deploy_cluster_components,
)
from ..helpers.types import Substrate

logger = logging.getLogger(__name__)


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
    await build_cluster(ops_test, substrate, integrate_with_mongos=True)


@pytest.mark.abort_on_fail
async def test_failed_upgrade_and_rollback(
    ops_test: OpsTest,
    substrate: Substrate,
    mongos_charm: str,
    mongos_resource: dict,
    faulty_mongos_upgrade_charm: str,
) -> None:
    """Tests that upgrade can be ran successfully."""
    mongos_application = ops_test.model.applications[MONGOS_APP_NAME]
    await mongos_application.refresh(path=faulty_mongos_upgrade_charm)
    logger.info("Wait for upgrade to fail")
    for attempt in tenacity.Retrying(
        reraise=True,
        stop=tenacity.stop_after_delay(TIMEOUT),
        wait=tenacity.wait_fixed(10),
    ):
        with attempt:
            assert "Refresh incompatible" in get_juju_status(
                ops_test.model.name, MONGOS_APP_NAME
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")
    await refresh_charm(ops_test, substrate, MONGOS_APP_NAME, mongos_charm, mongos_resource)

    # sleep to ensure that active status from before re-refresh does not affect below check
    time.sleep(15)

    await ops_test.model.block_until(
        lambda: all(unit.workload_status == "active" for unit in mongos_application.units)
        and all(unit.agent_status == "idle" for unit in mongos_application.units)
    )

    logger.info("Wait for the charm to be rolled back")
    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME],
        status="active",
        timeout=1000,
        idle_period=30,
    )

    for unit in mongos_application.units:
        number = unit.name.split("/")[-1]
        cmd = f"db.test_collection.insertOne({{number: {number}}} );"
        return_code, _, std_err = await check_mongos(
            ops_test, substrate, unit, auth=True, app_name=MONGOS_CLIENT_APPLICATION, cmd=cmd
        )
        assert return_code == 0, f"mongos user failed to write data, error: {std_err}"
