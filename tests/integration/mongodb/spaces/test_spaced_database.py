#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from time import sleep

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.conftest import stop_continous_writes
from tests.integration.helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    clear_continous_writes,
    deploy_application,
    deploy_charm,
    get_address_of_unit,
    get_app_name,
    get_unit_id,
    start_continous_writes,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)

ISOLATED_APP_NAME = "isolated"


@pytest.mark.skip_if_substrate("microk8s")
@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
    application_path: str,
    lxd_spaces,
):
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, substrate, app_name, len(UNIT_IDS))
        return

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
        constraints={"spaces": ["client", "peers"]},
        bind={"database-peers": "peers", "database": "client"},
    )

    await deploy_application(
        ops_test=ops_test,
        application_path=application_path,
        app_name=CONTINUOUS_WRITE_APPLICATION,
        constraints={"spaces": ["client"]},
        bind={"mongodb": "client"},
    )

    await ops_test.model.wait_for_idle(
        apps=[base_app_name], timeout=DEPLOYMENT_TIMEOUT, status="active"
    )


@pytest.mark.skip_if_substrate("microk8s")
@pytest.mark.abort_on_fail
async def test_integrate_with_spaces(ops_test: OpsTest, substrate: Substrate):
    app_name = await get_app_name(ops_test)
    await ops_test.model.integrate(
        f"{app_name}:database", f"{CONTINUOUS_WRITE_APPLICATION}:mongodb"
    )

    await ops_test.model.wait_for_idle(
        apps=[app_name, CONTINUOUS_WRITE_APPLICATION], status="active"
    )

    unit = ops_test.model.applications[CONTINUOUS_WRITE_APPLICATION].units[0]

    # remove default route on client so traffic can't be routed through default interface
    logger.info("Flush default routes on client")
    await unit.run("sudo ip route flush default")

    # Get IP on database interface:
    unit_address = await get_address_of_unit(
        ops_test, substrate, get_unit_id(unit.name), CONTINUOUS_WRITE_APPLICATION
    )

    # Add a route to access all nodes in the replica set
    logger.info("Add a route to contact all nodes on the replicaset")
    await unit.run(f"sudo ip route add 10.10.10.0/24 via {unit_address}")

    await start_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)
    sleep(10)
    number_of_writes = await stop_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)

    assert number_of_writes > 0, "Show continuous writes failed."
    await clear_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)


@pytest.mark.skip_if_substrate("microk8s")
@pytest.mark.abort_on_fail
async def test_integrate_with_isolated_space(ops_test: OpsTest, application_path: str):
    app_name = await get_app_name(ops_test)
    await deploy_application(
        ops_test=ops_test,
        application_path=application_path,
        app_name=ISOLATED_APP_NAME,
        constraints={"spaces": ["isolated"]},
        bind={"mongodb": "isolated"},
    )
    await ops_test.model.wait_for_idle(
        apps=[ISOLATED_APP_NAME], timeout=DEPLOYMENT_TIMEOUT, status="waiting"
    )

    await ops_test.model.integrate(f"{app_name}:database", f"{ISOLATED_APP_NAME}:mongodb")

    await ops_test.model.wait_for_idle(apps=[app_name, ISOLATED_APP_NAME], status="active")

    unit = ops_test.model.applications[ISOLATED_APP_NAME].units[0]

    # remove default route on client so traffic can't be routed through default interface
    logger.info("Flush default routes on client")
    await unit.run("sudo ip route flush default")

    await start_continous_writes(ops_test, ISOLATED_APP_NAME)
    sleep(10)

    number_of_writes = await stop_continous_writes(ops_test, ISOLATED_APP_NAME)
    assert number_of_writes <= 0, "network was not isolated enough"
