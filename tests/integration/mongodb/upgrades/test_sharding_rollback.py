#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time

import jubilant
from tenacity import Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.constants import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    SHARD_ONE_APP_NAME,
    SHARD_ONE_COLL_NAME,
    SHARD_ONE_DB_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_TWO_COLL_NAME,
    SHARD_TWO_DB_NAME,
    SMALL_K8S_STORAGE,
    TIMEOUT,
)
from tests.integration.helpers.continuous_writes_helpers import stop_continuous_writes
from tests.integration.helpers.jubilant_common import (
    find_leader,
    get_unit_id,
)
from tests.integration.helpers.jubilant_sharding import (
    count_shard_writes,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.jubilant_upgrades import (
    refresh_charm,
    refresh_with_juju,
    upgrade_incompatible,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger()


def test_build_and_deploy(juju: jubilant.Juju, substrate: Substrate, mongodb_charm: str) -> None:
    """Build and deploy one unit of MongoDB."""
    num_units_cluster_config = {
        CONFIG_SERVER_APP_NAME: 3,
        SHARD_ONE_APP_NAME: 3,
        SHARD_TWO_APP_NAME: 1,
    }

    deploy_cluster_components(
        juju,
        substrate,
        mongodb_charm,
        {},
        num_units_cluster_config=num_units_cluster_config,
        channel="8/edge",
        storage=SMALL_K8S_STORAGE if substrate == Substrate.k8s else None,
    )

    integrate_sharding_components(juju)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )


def test_rollback_on_config_server(
    juju: jubilant.Juju,
    substrate: Substrate,
    base_app_name: str,
    mongod_resource: dict[str, str],
    faulty_mongodb_upgrade_charm: str,
    jubilant_add_continuous_writes_to_shards,
) -> None:
    """Verify that the config-server can safely rollback without losing writes."""
    config_server_leader, _ = find_leader(juju, CONFIG_SERVER_APP_NAME)
    leader_id = get_unit_id(config_server_leader)

    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        juju.status().get_units(CONFIG_SERVER_APP_NAME),
        key=lambda unit: get_unit_id(unit),
        reverse=True,
    )

    logger.info("Calling pre-refresh-check")
    task = juju.run(config_server_leader, "pre-refresh-check")

    assert task.status == "completed", "pre-refresh-check failed, expected to succeed."

    logger.info("Refreshing the application")
    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        juju.status().get_units(CONFIG_SERVER_APP_NAME),
        key=lambda unit: get_unit_id(unit),
        reverse=True,
    )

    logger.info("Refresing the charm")
    refresh_charm(
        juju, substrate, CONFIG_SERVER_APP_NAME, faulty_mongodb_upgrade_charm, mongod_resource
    )

    juju.wait(
        lambda status: are_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    for attempt in Retrying(
        reraise=True,
        stop=stop_after_delay(TIMEOUT),
        wait=wait_fixed(10),
    ):
        with attempt:
            assert upgrade_incompatible(
                juju, substrate, CONFIG_SERVER_APP_NAME, refresh_order[0]
            ), "Not indicating charm incompatible"

    logger.info("Re-refresh the charm")

    # instead of resuming upgrade refresh with the old version
    refresh_with_juju(juju, CONFIG_SERVER_APP_NAME, "8/edge", charm_name=base_app_name)

    time.sleep(15)
    juju.wait(
        lambda status: are_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    if upgrade_incompatible(juju, substrate, CONFIG_SERVER_APP_NAME, refresh_order[0]):
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
            CONFIG_SERVER_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    if "resume-refresh" in juju.status().apps.get(CONFIG_SERVER_APP_NAME).app_status.message:
        logger.info("Continue refresh on all other units with `resume-refresh` action")
        logger.info("Calling resume refresh")
        if substrate == Substrate.lxd:
            unit = refresh_order[1]
        else:
            unit = config_server_leader

        task = juju.run(unit, "resume-refresh")

        if (substrate == Substrate.lxd) or (
            substrate == Substrate.k8s and leader_id != get_unit_id(refresh_order[1])
        ):
            assert task.status == "completed", "resume-refresh failed, expected to succeed."

    logger.info("Wait for the charm to be rolled back")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    # verify no writes were skipped during upgrade/rollback process
    shard_one_expected_writes = stop_continuous_writes(
        juju,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_ONE_DB_NAME,
        coll_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_expected_writes = stop_continuous_writes(
        juju,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
    )

    shard_one_actual_writes = count_shard_writes(
        juju,
        substrate,
        CONFIG_SERVER_APP_NAME,
        SHARD_ONE_DB_NAME,
        collection_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_actual_writes = count_shard_writes(
        juju,
        substrate,
        CONFIG_SERVER_APP_NAME,
        SHARD_TWO_DB_NAME,
        collection_name=SHARD_TWO_COLL_NAME,
    )
    assert (
        shard_one_actual_writes == shard_one_expected_writes
    ), "continuous writes to shard one failed during upgrade"
    assert (
        shard_two_actual_writes == shard_two_expected_writes
    ), "continuous writes to shard two failed during upgrade"

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )
