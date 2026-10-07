#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant

from tests.integration.helpers.constants import MONGOS_APP_NAME, TIMEOUT
from tests.integration.helpers.jubilant_common import (
    find_leader,
    get_unit_id,
)
from tests.integration.helpers.jubilant_mongos import build_cluster, deploy_cluster_components
from tests.integration.helpers.jubilant_upgrades import UPGRADE_INCOMPATIBLE_STATUS, refresh_charm
from tests.integration.helpers.status_helpers import are_agents_idle, unit_in_status
from tests.integration.helpers.types import Substrate

logger = logging.getLogger()


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    mongos_client_application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    deploy_cluster_components(
        juju,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        mongos_client_application_path,
        channel="8/edge",
        mongos_units=2,
    )
    build_cluster(juju, substrate, integrate_with_mongos=True)


def test_upgrade(
    juju: jubilant.Juju, substrate: Substrate, mongos_charm: str, mongos_resource: dict[str, str]
):
    """Refreshes the charm and wait for it to be active again."""
    leader_unit, _ = find_leader(juju, app_name=MONGOS_APP_NAME)
    leader_id = get_unit_id(leader_unit)
    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        juju.status().get_units(MONGOS_APP_NAME),
        key=lambda unit: get_unit_id(unit),
        reverse=True,
    )

    logger.info("Refreshing the application")
    refresh_charm(juju, substrate, MONGOS_APP_NAME, mongos_charm, mongos_resource)

    juju.wait(
        lambda status: are_agents_idle(
            status,
            MONGOS_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    if unit_in_status(
        juju.status(),
        MONGOS_APP_NAME,
        refresh_order[0],
        UPGRADE_INCOMPATIBLE_STATUS,
    ):
        logger.info("Upgrade is blocked due to incompatibility")

        logger.info(f"Continue refresh on unit {refresh_order[0]}")
        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_task = juju.run(
            refresh_order[0],
            "force-refresh-start",
            {
                "check-compatibility": False,
                "run-pre-refresh-checks": False,
                "check-workload-container": False,
            },
        )
        assert force_refresh_task.return_code == 0, "action failed"

    juju.wait(
        lambda status: are_agents_idle(
            status,
            MONGOS_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    if "resume-refresh" in juju.status().apps.get(MONGOS_APP_NAME).app_status.message:
        logger.info("Continue refresh on all other units with `resume-refresh` action")
        logger.info("Calling resume refresh")
        if substrate == Substrate.lxd:
            unit = refresh_order[1]
        else:
            unit = leader_unit

        try:
            task = juju.run(unit, "resume-refresh")
        except jubilant.TaskError as error:
            task = error.task
        if (substrate == Substrate.lxd) or (
            substrate == Substrate.k8s and leader_id != get_unit_id(refresh_order[1])
        ):
            assert task.status == "completed", "resume-refresh failed, expected to succeed."
