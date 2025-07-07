#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    deploy_charm,
    get_address_of_unit,
    get_app_name,
)
from ...helpers.ha import (
    replica_set_primary,
    scale_application,
    verify_writes,
)
from ...helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict,
    base_app_name: str,
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
    )
    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


@pytest.mark.abort_on_fail
@pytest.mark.unstable
async def test_scale_up_down(ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db):
    """Scale up and down the application and verify the replica set is healthy."""
    app_name = await get_app_name(ops_test)
    scales = [3, -3, 4, -4, 5, -5]
    for count in scales:
        await scale_application(
            ops_test, substrate, app_name, count=count, wait=True, timeout=DEPLOYMENT_TIMEOUT
        )
        ip_addresses = [
            await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
            for unit in ops_test.model.applications[app_name].units
        ]
        primary = await replica_set_primary(
            ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
        )
        assert primary is not None, "Replica set has no primary"

    await verify_writes(ops_test, substrate, app_name)
