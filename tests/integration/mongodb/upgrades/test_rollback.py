#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import time

import jubilant

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

    # pin the image the channel ships, since Juju keeps the uploaded one
    original_resources: dict[str, str] | None = None
    if substrate == Substrate.k8s:
        channel_resources = json.loads(
            juju.cli("charm-resources", app_name, "--channel", "8/edge", "--format", "json")
        )
        original_resources = {
            resource["name"]: resource["revision"] for resource in channel_resources
        }
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

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=60,
            )
            and upgrade_incompatible(status, substrate, app_name, refresh_order[0])
        ),
        timeout=TIMEOUT,
    )

    logger.info("Re-refresh the charm")

    refresh_with_juju(
        juju, app_name, "8/edge", charm_name=base_app_name, resources=original_resources
    )

    # sleep to ensure that active status from before re-refresh does not affect below check
    time.sleep(15)
    juju.wait(
        lambda status: are_agents_idle(
            status,
            app_name,
            idle_period=20,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    if "resume-refresh" in juju.status().apps.get(app_name).app_status.message:
        logger.info("Continue refresh on all other units with `resume-refresh` action")
        logger.info("Calling resume refresh")
        if substrate == Substrate.lxd:
            unit = refresh_order[1]
        else:
            unit = leader_name

        try:
            task = juju.run(unit, "resume-refresh")
        except jubilant.TaskError as err:
            task = err.task

        assert task.results["result"].startswith(
            "Refresh resumed."
        ), "resume-refresh failed, expected to succeed."

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
