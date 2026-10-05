#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant

from tests.integration.helpers.constants import DEPLOYMENT_TIMEOUT, TIMEOUT, UNIT_IDS
from tests.integration.helpers.continuous_writes_helpers import (
    verify_writes,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    existing_app,
    find_leader,
    get_unit_id,
)
from tests.integration.helpers.jubilant_upgrades import UPGRADE_INCOMPATIBLE_STATUS, refresh_charm
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    unit_in_status,
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
        app_name=base_app_name,
        mongod_resource={},  # unused
        channel="8/edge",
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


def test_upgrade(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    jubilant_continuous_writes_to_db,
) -> None:
    """Verifies that the upgrade can run successfully."""
    app_name = existing_app(juju)
    assert app_name

    leader_name, _ = find_leader(juju, app_name)
    leader_id = get_unit_id(leader_name)

    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        juju.status().get_units(app_name),
        key=lambda unit: get_unit_id(unit),
        reverse=True,
    )

    logger.info("Calling pre-refresh-check")
    task = juju.run(leader_name, "pre-refresh-check")

    assert task.status == "completed", "pre-refresh-check-failed, expected to succeed"

    logger.info("Refreshing the application")
    refresh_charm(juju, substrate, app_name, mongodb_charm, mongod_resource)
    juju.wait(
        lambda status: are_agents_idle(
            status,
            app_name,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    if unit_in_status(
        juju.status(),
        app_name,
        refresh_order[0],
        UPGRADE_INCOMPATIBLE_STATUS,
    ):
        logger.info("Upgrade is blocked due to incompatibility")

        logger.info(f"Continue refresh on unit {refresh_order[0]}")
        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_task = juju.run(
            refresh_order[0],
            "force-refresh-start",
            params={"check-compatibility": False, "run-pre-refresh-checks": False},
        )
        assert force_refresh_task.results.get("return-code") == 0, "action failed"

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

        try:
            task = juju.run(unit, "resume-refresh")
        except jubilant.TaskError as error:
            task = error.task

        if (substrate == Substrate.lxd) or (
            substrate == Substrate.k8s and leader_id != get_unit_id(refresh_order[1])
        ):
            assert task.status == "completed", "resume-refresh failed, expected to succeed."

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    # verify that the no writes were skipped
    verify_writes(juju, substrate, app_name)


def test_preflight_check(juju: jubilant.Juju) -> None:
    """Verifies that the preflight check can run successfully."""
    app_name = existing_app(juju)
    assert app_name

    leader_name, _ = find_leader(juju, app_name)
    logger.info("Calling pre-refresh-check")
    task = juju.run(leader_name, "pre-refresh-check")

    assert task.status == "completed", "pre-refresh-check failed, expected to succeed."

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )
