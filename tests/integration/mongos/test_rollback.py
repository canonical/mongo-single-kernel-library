#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import time

import jubilant
import tenacity

from tests.integration.helpers.constants import (
    DEPLOYMENT_TIMEOUT,
    MONGOS_APP_NAME,
    MONGOS_CLIENT_APPLICATION,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import execute_on_mongod, find_leader, get_unit_id
from tests.integration.helpers.jubilant_mongos import (
    build_cluster,
    deploy_cluster_components,
    generate_mongos_uri,
)
from tests.integration.helpers.jubilant_upgrades import UPGRADE_INCOMPATIBLE_STATUS, refresh_charm
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    unit_in_status,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


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
        mongos_units=3,
    )
    build_cluster(juju, substrate, integrate_with_mongos=True)


def test_failed_upgrade_and_rollback(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongos_charm: str,
    mongos_resource: dict[str, str],
    faulty_mongos_upgrade_charm: str,
) -> None:
    """Tests that upgrade can be ran successfully."""
    leader_unit, _ = find_leader(juju, app_name=MONGOS_APP_NAME)
    leader_id = get_unit_id(leader_unit)

    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        juju.status().get_units(MONGOS_APP_NAME),
        key=lambda unit: get_unit_id(unit),
        reverse=True,
    )

    refresh_charm(juju, substrate, MONGOS_APP_NAME, faulty_mongos_upgrade_charm, mongos_resource)
    logger.info("Wait for upgrade to fail")

    for attempt in tenacity.Retrying(
        reraise=True,
        stop=tenacity.stop_after_delay(TIMEOUT),
        wait=tenacity.wait_fixed(10),
    ):
        with attempt:
            assert unit_in_status(
                juju.status(), MONGOS_APP_NAME, refresh_order[0], UPGRADE_INCOMPATIBLE_STATUS
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")
    refresh_charm(juju, substrate, MONGOS_APP_NAME, mongos_charm, mongos_resource)

    # sleep to ensure that active status from before re-refresh does not affect below check
    time.sleep(15)
    juju.wait(
        lambda status: are_agents_idle(
            status,
            MONGOS_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    if unit_in_status(
        juju.status(), MONGOS_APP_NAME, refresh_order[0], UPGRADE_INCOMPATIBLE_STATUS
    ):
        # will be marked "incompatible" if rollback is not to the same revision as initially
        # deployed
        logger.info("Rollback is blocked due to incompatibility")

        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_task = juju.run(
            refresh_order[0],
            "force-refresh-start",
            {
                "check-compatibility": False,
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
        if substrate == Substrate.lxd:
            unit = refresh_order[1]
        else:
            unit = leader_unit

        task = juju.run(unit, "resume-refresh")

        if (substrate == Substrate.lxd) or (
            substrate == Substrate.k8s and leader_id != get_unit_id(refresh_order[1])
        ):
            assert task.status == "completed", "resume-refresh failed, expected to succeed."

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGOS_APP_NAME, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    for unit, mongos_unit_status in juju.status().get_units(MONGOS_APP_NAME).items():
        number = get_unit_id(unit)
        cmd = f"db.test_collection.insertOne({{number: {number}}} );"
        uri = generate_mongos_uri(
            juju,
            substrate,
            MONGOS_CLIENT_APPLICATION,
            auth=True,
            mongos_unit_status=mongos_unit_status,
        )
        check = execute_on_mongod(
            juju,
            substrate,
            app_name=MONGOS_APP_NAME,
            uri=uri,
            command=cmd,
            unit_name=unit,
            container_name="mongos",
        )
        assert check, "mongos user failed to write data"
