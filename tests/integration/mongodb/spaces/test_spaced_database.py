#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from time import sleep

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import (
    clear_continuous_writes,
    start_continuous_writes,
    stop_continuous_writes,
)
from tests.integration.helpers.jubilant_common import (
    deploy_application,
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    find_leader,
    get_ip_from_unit,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)

ISOLATED_APP_NAME = "isolated"


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_build_and_deploy(
    juju: jubilant.Juju,
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
        constraints={"spaces": "peers,clients"},
        bind={"database-peers": "peers", "database": "client"},
    )

    deploy_application(
        juju,
        application_path,
        app_name=CONTINUOUS_WRITE_APPLICATION,
        constraints={"spaces": "client"},
        bind={"mongodb": "client"},
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_integrate_with_spaces(juju: jubilant.Juju, substrate: Substrate):
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(f"{app_name}:database", f"{CONTINUOUS_WRITE_APPLICATION}:mongodb")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, CONTINUOUS_WRITE_APPLICATION, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    unit_name, unit_status = find_leader(juju, CONTINUOUS_WRITE_APPLICATION)

    # remove default route on client so traffic can't be routed through default interface
    logger.info("Flush default routes on client")
    juju.ssh(unit_name, "sudo ip route flush default")

    # Get IP on database interface:
    unit_address = get_ip_from_unit(substrate, unit_status)

    # Add a route to access all nodes in the replica set
    logger.info("Add a route to contact all nodes on the replicaset")
    juju.ssh(unit_name, f"sudo ip route add 10.10.10.0/24 via {unit_address}")

    start_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)
    sleep(10)
    number_of_writes = stop_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)

    assert number_of_writes > 0, "Show continuous writes failed."
    clear_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_integrate_with_isolated_space(juju: jubilant.Juju, application_path: str):
    app_name = existing_app(juju)
    assert app_name
    deploy_application(
        juju=juju,
        application_path=application_path,
        app_name=ISOLATED_APP_NAME,
        constraints={"spaces": "isolated"},
        bind={"mongodb": "isolated"},
    )
    juju.wait(
        lambda status: (
            jubilant.all_waiting(status, ISOLATED_APP_NAME)
            and jubilant.all_agents_idle(status, ISOLATED_APP_NAME)
        )
    )

    juju.integrate(f"{app_name}:database", f"{ISOLATED_APP_NAME}:mongodb")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, ISOLATED_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )

    unit_name, _ = find_leader(juju, ISOLATED_APP_NAME)

    # remove default route on client so traffic can't be routed through default interface
    logger.info("Flush default routes on client")
    juju.ssh(unit_name, "sudo ip route flush default")
    # Give some time for the route to be updated.
    sleep(10)

    start_continuous_writes(juju, ISOLATED_APP_NAME)
    sleep(10)

    number_of_writes = stop_continuous_writes(juju, ISOLATED_APP_NAME)
    assert number_of_writes <= 0, "network was not isolated enough"
