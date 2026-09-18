#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import time

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CHARMED_STATS_USERNAME,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    find_leader,
    get_ip_from_unit,
    set_password,
    unit_hostname,
    verify_endpoints,
)
from tests.integration.helpers.jubilant_ha import (
    cut_network_from_unit,
    restore_network_to_unit,
    wait_network_restore,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

MEDIAN_REELECTION_TIME = 12


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
) -> None:
    """Build the charm-under-test and deploy it with three units."""
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


async def test_endpoints(juju: jubilant.Juju, substrate: Substrate):
    """Sanity check that endpoints are running."""
    app_name = existing_app(juju)
    assert app_name

    for unit_name, unit_info in juju.status().get_units(app_name).items():
        verify_endpoints(substrate, unit_name, unit_info)


async def test_endpoints_new_password(juju: jubilant.Juju, substrate: Substrate):
    """Verify that endpoints still function correctly after the stats user password changes."""
    app_name = existing_app(juju)
    assert app_name

    set_password(juju, app_name, username=CHARMED_STATS_USERNAME, password="new_password")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    for unit_name, unit_info in juju.status().get_units(app_name).items():
        verify_endpoints(substrate, unit_name, unit_info)


async def test_endpoints_network_cut(
    juju: jubilant.Juju, substrate: Substrate, jubilant_chaos_mesh: None
):
    """Verify that endpoint still function correctly after a network cut."""
    app_name = existing_app(juju)
    assert app_name
    assert juju.model

    leader_name, leader_unit_info = find_leader(juju=juju, app_name=app_name)
    unit_ip = get_ip_from_unit(substrate, leader_unit_info)

    hostname = unit_hostname(juju, leader_name)

    cut_network_from_unit(substrate, juju.model, hostname, ip_change=True)
    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # wait until network is reestablished for the unit
    restore_network_to_unit(substrate, juju.model, hostname, ip_change=True)
    wait_network_restore(
        juju,
        substrate,
        juju.model,
        app_name,
        hostname,
        unit_ip,
        ip_change=True,
        unit_count=len(UNIT_IDS),
    )
    verify_endpoints(substrate, leader_name, leader_unit_info)
