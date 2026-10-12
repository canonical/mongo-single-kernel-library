#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import time
from logging import getLogger

import jubilant

from tests.integration.helpers.common import CHARMED_OPERATOR_USERNAME
from tests.integration.helpers.constants import (
    DEPLOYMENT_TIMEOUT,
    MEDIAN_REELECTION_TIME,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import (
    count_writes,
    replica_set_primary,
    replica_set_secondary,
    verify_writes,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    fast_forward,
    get_ip_from_unit,
    get_mongodb_hostname_for_unit,
    get_password,
    mongod_ready,
    unit_hostname,
)
from tests.integration.helpers.jubilant_ha import (
    cut_network_from_unit,
    instance_ip,
    is_unit_reachable_lxd,
    lxd_get_controller_hostname,
    mongodb_unit_in_status,
    restore_network_to_unit,
    verify_replica_set_configuration,
    wait_network_restore,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
):
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=len(UNIT_IDS))
        return

    app_name = base_app_name
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=app_name,
        num_units=len(UNIT_IDS),
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_network_cut(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db, jubilant_chaos_mesh
):
    # locate primary unit
    app_name = existing_app(juju)
    assert app_name

    primary_name, primary_status = replica_set_primary(juju, substrate, app_name=app_name)

    password = get_password(juju, app_name, username=CHARMED_OPERATOR_USERNAME)

    assert primary_name, "No primary unit found"

    other_unit, other_unit_status = replica_set_secondary(juju, substrate, app_name=app_name)
    assert other_unit, "No secondary unit found"

    all_units = juju.status().get_units(app_name).keys()

    model_name = juju.model
    assert model_name

    primary_hostname = unit_hostname(juju, primary_name)
    mongodb_primary_hostname = get_mongodb_hostname_for_unit(
        juju, substrate, primary_name, primary_status
    )
    primary_unit_ip = get_ip_from_unit(substrate, primary_status)

    # before cutting network verify that connection is possible
    assert mongod_ready(
        juju, primary_unit_ip, app_name=app_name
    ), f"Connection to host {primary_unit_ip} is not possible"

    cut_network_from_unit(substrate, model_name, primary_hostname, ip_change=True)

    logger.info(f"Cut network for {primary_hostname}")

    units_to_check = {unit_name for unit_name in all_units if unit_name != primary_name}

    logger.info(f"Checking: {units_to_check}")

    # verify machine is not reachable from peer units
    juju.wait(
        lambda status: mongodb_unit_in_status(
            status,
            substrate,
            unit_to_check=primary_name,
            unit_to_check_hostname=mongodb_primary_hostname,
            expected_status="(not reachable/healthy)",
            username=CHARMED_OPERATOR_USERNAME,
            password=password,
        ),
        timeout=TIMEOUT,
    )

    if substrate == Substrate.lxd:
        logger.info("Checking reachability from controller")
        controller: str = lxd_get_controller_hostname(juju)
        assert not is_unit_reachable_lxd(
            controller, primary_hostname, number_of_retries=3
        ), "unit is reachable from controller"

    # sleep for twice the median election time
    logger.info(f"Sleeping for {MEDIAN_REELECTION_TIME * 2} seconds")
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit, unit_info=other_unit_status
    )
    time.sleep(5)
    more_writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit, unit_info=other_unit_status
    )
    assert more_writes > writes, "writes not continuing to DB"

    # verify that a new primary gets elected
    new_primary_name, _ = replica_set_primary(
        juju,
        substrate,
        app_name=app_name,
    )
    assert new_primary_name != primary_name

    # verify that no writes to the db were missed
    total_expected_writes = verify_writes(
        juju,
        substrate,
        app_name,
    )

    assert juju.model
    # restore network connectivity to old primary
    restore_network_to_unit(substrate, juju.model, primary_hostname, ip_change=True)

    # wait until network is reestablished for the unit
    wait_network_restore(
        juju,
        substrate,
        app_name,
        primary_hostname,
        primary_unit_ip,
        ip_change=True,
        unit_count=len(UNIT_IDS),
    )

    # self healing is performed with update status hook
    with fast_forward(juju, update_interval="1m"):
        juju.wait(
            lambda status: are_apps_active_and_agents_idle(
                status, app_name, idle_period=20, unit_count=len(UNIT_IDS)
            ),
            timeout=TIMEOUT,
        )

    # verify we have connection to the old primary
    if substrate == Substrate.lxd:
        new_ip = instance_ip(juju, primary_hostname)
        assert mongod_ready(
            juju, new_ip, app_name=app_name
        ), f"Connection to host {new_ip} is not possible"

    # verify presence of primary, replica set member configuration, and number of primaries
    verify_replica_set_configuration(juju, substrate, app_name=app_name)

    new_unit_info = None
    for unit_name, unit_info in juju.status().get_units(app_name).items():
        if unit_name == primary_name:
            new_unit_info = unit_info

    assert new_unit_info, f"No information in juju status for {primary_name}"

    # verify that no writes were missed.
    secondary_writes = count_writes(
        juju, substrate, app_name, unit_name=primary_name, unit_info=new_unit_info
    )
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."
