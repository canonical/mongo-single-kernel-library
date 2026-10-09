#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

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
    find_non_leader,
    unit_hostname,
)
from tests.integration.helpers.jubilant_ha import cut_network_from_unit, restore_network_to_unit
from tests.integration.helpers.jubilant_sharding import (
    count_shard_writes,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.jubilant_upgrades import assert_successful_run_upgrade_sequence
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
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
        SHARD_TWO_APP_NAME: 3,
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


def test_upgrade(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    jubilant_add_continuous_writes_to_shards,
) -> None:
    """Verify that the sharded cluster can be safely upgraded without losing writes."""
    for sharding_component in CLUSTER_COMPONENTS:
        assert_successful_run_upgrade_sequence(
            juju,
            substrate,
            app_name=sharding_component,
            new_charm=mongodb_charm,
            mongod_resource=mongod_resource,
        )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=120,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    shard_one_expected_writes = stop_continuous_writes(
        juju,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_ONE_DB_NAME,
        coll_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_total_expected_writes = stop_continuous_writes(
        juju,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
    )

    actual_shard_one_writes = count_shard_writes(
        juju,
        substrate,
        config_server_name=CONFIG_SERVER_APP_NAME,
        db_name=SHARD_ONE_DB_NAME,
        collection_name=SHARD_ONE_COLL_NAME,
    )
    actual_shard_two_writes = count_shard_writes(
        juju,
        substrate,
        config_server_name=CONFIG_SERVER_APP_NAME,
        db_name=SHARD_TWO_DB_NAME,
        collection_name=SHARD_TWO_COLL_NAME,
    )

    assert (
        actual_shard_one_writes == shard_one_expected_writes
    ), "missed writes during upgrade procedure."
    assert (
        actual_shard_two_writes == shard_two_total_expected_writes
    ), "missed writes during upgrade procedure."


def test_pre_upgrade_check_success(juju: jubilant.Juju) -> None:
    """Verify that the pre-refresh check succeeds in the happy path."""
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    for sharding_component in CLUSTER_COMPONENTS:
        leader_name, _ = find_leader(juju, app_name=sharding_component)
        task = juju.run(leader_name, "pre-refresh-check")
        assert task.status == "completed", "pre-refresh-check failed, expected to succeed."


def test_pre_upgrade_check_failure(
    juju: jubilant.Juju, substrate: Substrate, jubilant_chaos_mesh
) -> None:
    """Verify that the pre-refresh check fails if there is a problem with one of the shards."""
    assert juju.model
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    leader_name, _ = find_leader(juju, app_name=SHARD_TWO_APP_NAME)
    non_leader_name, _ = find_non_leader(juju, app_name=SHARD_TWO_APP_NAME)

    machine_name = unit_hostname(juju, non_leader_name)

    cut_network_from_unit(substrate, juju.model, machine_name)

    for sharding_component in CLUSTER_COMPONENTS:
        with pytest.raises(jubilant.TaskError) as error:
            leader_name, _ = find_leader(juju, app_name=sharding_component)
            juju.run(leader_name, "pre-refresh-check")
        assert error.value.task.status == "failed", "pre-refresh-check succeeded, expected to fail."

    # restore network after test
    restore_network_to_unit(substrate, substrate, machine_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )
