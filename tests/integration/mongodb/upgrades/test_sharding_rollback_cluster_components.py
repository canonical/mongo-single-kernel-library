#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant

from single_kernel_mongo.config.statuses import ConfigServerStatuses, ShardStatuses
from tests.integration.helpers.constants import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    CONTINUOUS_WRITE_APPLICATION,
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
from tests.integration.helpers.jubilant_sharding import (
    count_shard_writes,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.jubilant_upgrades import (
    assert_successful_run_upgrade_sequence,
    refresh_with_juju,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
) -> None:
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


def test_rollback_on_shard_and_config_server(
    juju: jubilant.Juju,
    substrate: Substrate,
    base_app_name: str,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    jubilant_add_continuous_writes_to_shards,
) -> None:
    """Verify that a config-server and shard can safely rollback without losing writes."""
    assert_successful_run_upgrade_sequence(
        juju, substrate, CONFIG_SERVER_APP_NAME, mongodb_charm, mongod_resource
    )

    revision = "test/0.0.0+dirty"
    shard_revision_statuses = {
        app_name: [
            ShardStatuses.shard_needs_upgrade(
                str(juju.status().apps.get(app_name).charm_rev), "", revision, "-locally built"
            )
        ]
        for app_name in (SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME)
    }
    config_server_statuses = {
        CONFIG_SERVER_APP_NAME: [
            ConfigServerStatuses.waiting_for_shard_upgrade(revision, "-locally built")
        ]
    }

    # Wait for statuses to settle down
    juju.wait(
        lambda status: (
            are_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={},
                expected_app_statuses=shard_revision_statuses | config_server_statuses,
            )
        )
    )

    assert_successful_run_upgrade_sequence(
        juju,
        substrate,
        SHARD_ONE_APP_NAME,
        new_charm=mongodb_charm,
        mongod_resource=mongod_resource,
    )

    # Wait for statuses to settle down
    juju.wait(
        lambda status: (
            are_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={},
                expected_app_statuses={
                    SHARD_TWO_APP_NAME: shard_revision_statuses[SHARD_TWO_APP_NAME]
                }
                | config_server_statuses,
            )
        )
    )

    refresh_with_juju(juju, CONFIG_SERVER_APP_NAME, channel="8/edge", charm_name=base_app_name)

    # verify no writes were skipped during upgrade process
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
        shard_one_actual_writes >= shard_one_expected_writes
    ), "continuous writes to shard one failed during upgrade"
    assert (
        shard_two_actual_writes >= shard_two_expected_writes
    ), "continuous writes to shard two failed during upgrade"
