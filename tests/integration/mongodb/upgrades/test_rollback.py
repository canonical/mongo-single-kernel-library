#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time

import jubilant
from tenacity import Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.constants import DEPLOYMENT_TIMEOUT, TIMEOUT, UNIT_IDS
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    existing_app,
    find_leader,
    get_unit_id,
)
from tests.integration.helpers.jubilant_upgrades import (
    get_workload_version,
    refresh_with_juju,
    upgrade_incompatible,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


def test_build_and_deploy(juju: jubilant.Juju, substrate: Substrate, base_app_name: str) -> None:
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == Substrate.lxd else "mongodb-k8s"

    deploy_charm(
        juju,
        mongodb_charm_name,
        substrate,
        channel="8/edge",
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, base_app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_rollback(
    juju: jubilant.Juju,
    substrate: Substrate,
    base_app_name: str,
    mongod_resource: dict[str, str],
    faulty_mongodb_upgrade_charm: str,
) -> None:
    app_name = existing_app(juju)
    assert app_name

    leader_name, _ = find_leader(juju, app_name)
    leader_id = get_unit_id(leader_name)

    resources = mongod_resource if substrate == Substrate.k8s else None

    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        juju.status().get_units(app_name),
        key=lambda unit: get_unit_id(unit),
        reverse=True,
    )

    initial_version = get_workload_version(juju, leader_name)

    juju.refresh(app=app_name, path=faulty_mongodb_upgrade_charm, resources=resources)
    logger.info("Wait for refresh to fail")

    for attempt in Retrying(
        reraise=True,
        stop=stop_after_delay(TIMEOUT),
        wait=wait_fixed(10),
    ):
        with attempt:
            assert upgrade_incompatible(
                juju, substrate, app_name, refresh_order[0]
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")

    refresh_with_juju(juju, app_name, "8/edge", charm_name=base_app_name)

    # sleep to ensure that active status from before re-refresh does not affect below check
    time.sleep(15)
    juju.wait(
        lambda status: are_agents_idle(
            status,
            app_name,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )
    if upgrade_incompatible(juju, substrate, app_name, refresh_order[0]):
        # will be marked "incompatible" if rollback is not to the same revision as initially
        # deployed
        logger.info("Rollback is blocked due to incompatibility")

        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_task = juju.run(
            refresh_order[0],
            "force-refresh-start",
            params={"check-compatibility": False, "run-pre-refresh-checks": False},
        )
        assert force_refresh_task.return_code == 0, "action failed"

    juju.wait(
        lambda status: are_agents_idle(
            status,
            app_name,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    if "resume-refresh" in juju.status().apps.get(app_name).app_status.message:
        logger.info("Continue refresh on all other units with `resume-refresh` action")
        logger.info("Calling resume refresh")
        if substrate == Substrate.lxd:
            unit = refresh_order[1]
        else:
            unit = leader_name

        task = juju.run(unit, "resume-refresh")

        if (substrate == Substrate.lxd) or (
            substrate == Substrate.k8s and leader_id != get_unit_id(refresh_order[1])
        ):
            assert task.status == "completed", "resume-refresh failed, expected to succeed."

    logger.info("Wait for the charm to be rolled back")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=120, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    for unit in juju.status().get_units(app_name):
        workload_version = get_workload_version(juju, unit)
        assert workload_version == initial_version
