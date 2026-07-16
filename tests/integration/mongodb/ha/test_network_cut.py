#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import time
from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    MEDIAN_REELECTION_TIME,
    UNIT_IDS,
    check_or_scale_app,
    count_writes,
    deploy_charm,
    get_address_of_unit,
    get_app_name,
    get_unit_id,
    instance_ip,
    mongod_ready,
    unit_hostname,
)
from ...helpers.ha import (
    cut_network_from_unit,
    get_controller_machine,
    is_machine_reachable_from,
    replica_set_primary,
    replica_set_secondary,
    restore_network_for_unit,
    verify_replica_set_configuration,
    verify_writes,
    wait_network_restore,
    wait_until_unit_in_status,
)
from ...helpers.types import Substrate

logger = getLogger(__name__)


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
    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT, status="active")


@pytest.mark.abort_on_fail
async def test_network_cut(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db, chaos_mesh
):
    # locate primary unit
    app_name = await get_app_name(ops_test)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )

    assert primary, "No primary unit found"

    other_unit = await replica_set_secondary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert other_unit, "No secondary unit found"

    all_units = ops_test.model.applications[app_name].units

    model_name = ops_test.model.info.name

    if substrate == "lxd":
        primary_hostname = await unit_hostname(ops_test, primary.name)
    else:
        primary_hostname = primary.name
    primary_unit_ip = await get_address_of_unit(
        ops_test, substrate, get_unit_id(primary.name), app_name
    )

    # before cutting network verify that connection is possible
    assert await mongod_ready(
        ops_test, primary_unit_ip, app_name=app_name
    ), f"Connection to host {primary_unit_ip} is not possible"

    cut_network_from_unit(ops_test, substrate, primary_hostname)

    logger.info(f"Cut network for {primary_hostname}")

    units_to_check = {unit for unit in all_units if unit.name != primary.name}
    logger.info(f"Checking: {units_to_check}")
    # verify machine is not reachable from peer units
    for unit in units_to_check:
        logger.info(f"Waiting for unit {unit}")
        await wait_until_unit_in_status(
            ops_test, substrate, primary, unit, "(not reachable/healthy)", app_name
        )

    if substrate == "lxd":
        logger.info("Checking reachability from controller")
        controller: str = await get_controller_machine(ops_test)
        assert not is_machine_reachable_from(
            controller, primary_hostname
        ), "unit is reachable from controller"

    # sleep for twice the median election time
    logger.info(f"Sleeping for {MEDIAN_REELECTION_TIME * 2} seconds")
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    time.sleep(5)
    more_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    assert more_writes > writes, "writes not continuing to DB"

    # verify that a new primary gets elected
    new_primary = await replica_set_primary(
        ops_test,
        substrate,
        app_name=app_name,
        replica_set_hosts=ip_addresses,
    )
    assert new_primary.name != primary.name

    # verify that no writes to the db were missed
    total_expected_writes = await verify_writes(
        ops_test,
        substrate,
        app_name,
    )

    # restore network connectivity to old primary
    restore_network_for_unit(ops_test, substrate, primary_hostname)

    # wait until network is reestablished for the unit
    await wait_network_restore(
        ops_test, substrate, model_name, app_name, primary_hostname, primary_unit_ip
    )

    # self healing is performed with update status hook
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=1000)

    # verify we have connection to the old primary
    if substrate == "lxd":
        new_ip = instance_ip(model_name, primary_hostname)
        assert await mongod_ready(
            ops_test, new_ip, app_name=app_name
        ), f"Connection to host {new_ip} is not possible"

    # verify presence of primary, replica set member configuration, and number of primaries
    await verify_replica_set_configuration(ops_test, substrate, app_name=app_name)

    # verify that no writes were missed.
    secondary_writes = await count_writes(ops_test, substrate, app_name, unit=primary)
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."
