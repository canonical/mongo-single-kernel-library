#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.ha import replica_set_primary, scale_application

from ..helpers.common import (
    DEPLOYMENT_TIMEOUT,
    check_or_scale_app,
    deploy_charm,
    get_address_of_unit,
    get_app_name,
    get_unit_id,
)
from ..helpers.types import Substrate

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, mongodb_charm: str, substrate: Substrate, mongod_resource, base_app_name
):
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, substrate, app_name, 1)
        return

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=1,
    )
    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)

    # effectively disable the update status from firing
    await ops_test.model.set_config({"update-status-hook-interval": "60m"})


async def test_long_scale_up_scale_down_units(ops_test: OpsTest, substrate: Substrate):
    """Scale up and down the application and verify the replica set is healthy."""
    scales = [2, -1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6, 7, -7]
    for count in scales:
        await scale_and_verify(ops_test, substrate, count=count)


async def scale_and_verify(ops_test: OpsTest, substrate: Substrate, count: int):
    if count == 0:
        logger.warning("Skipping scale up/down by 0")
        return
    if count > 0:
        logger.info(f"Scaling up by {count} units")
    else:
        logger.info(f"Scaling down by {abs(count)} units")

    app_name = await get_app_name(ops_test)

    await scale_application(ops_test, substrate, app_name, count, wait=False)

    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, raise_on_error=False
    )

    hosts = [
        await get_address_of_unit(ops_test, substrate, get_unit_id(unit.name), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary = await replica_set_primary(
        ops_test, substrate, replica_set_hosts=hosts, app_name=app_name
    )
    assert primary is not None, "Replica set has no primary"
