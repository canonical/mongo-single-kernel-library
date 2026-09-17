#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    check_app_status,
    stop_continous_writes,
)
from tests.integration.helpers.sharding import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_ONE_COLL_NAME,
    SHARD_ONE_DB_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_TWO_COLL_NAME,
    SHARD_TWO_DB_NAME,
    SMALL_K8S_STORAGE,
    count_shard_writes,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.types import Substrate
from tests.integration.helpers.upgrade import (
    assert_successful_run_upgrade_sequence,
    refresh_with_juju,
)

# TODO: Re-enable on Kubernetes after a new release is available on 8/edge.
pytestmark = pytest.mark.skip_if_substrate(Substrate.k8s)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, substrate: Substrate, mongodb_charm, mongod_resource
) -> None:
    """Build and deploy one unit of MongoDB."""
    num_units_cluster_config = {
        CONFIG_SERVER_APP_NAME: 3,
        SHARD_ONE_APP_NAME: 3,
        SHARD_TWO_APP_NAME: 1,
    }

    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongod_resource,
        num_units_cluster_config=num_units_cluster_config,
        channel="8/edge",
        storage=SMALL_K8S_STORAGE if substrate == Substrate.k8s else None,
    )
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_blocked=False,
        raise_on_error=False,
    )

    await integrate_sharding_components(ops_test)
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        timeout=TIMEOUT,
        idle_period=120,
        raise_on_blocked=False,
        raise_on_error=False,
        status="active",
    )


@pytest.mark.abort_on_fail
async def test_rollback_on_shard_and_config_server(
    ops_test: OpsTest,
    substrate: Substrate,
    base_app_name: str,
    mongod_base_path: Path,
    mongodb_charm: str,
    mongod_resource: dict,
    add_continuous_writes_to_shards,
) -> None:
    """Verify that a config-server and shard can safely rollback without losing writes."""
    await assert_successful_run_upgrade_sequence(
        ops_test, substrate, CONFIG_SERVER_APP_NAME, mongodb_charm, mongod_resource
    )

    revision = "test/0.0.0+dirty"
    shard_revision_messages = {
        app_name: (
            f"Charm revision ({ops_test.model.applications[app_name].charm_url.rsplit('-', 1)[-1]}) "
            f"is not up-to date with config-server ({revision}-locally built)."
        )
        for app_name in (SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME)
    }

    # Wait for statuses to settle down
    await asyncio.gather(
        check_app_status(
            ops_test,
            SHARD_ONE_APP_NAME,
            status="blocked",
            message=shard_revision_messages[SHARD_ONE_APP_NAME],
        ),
        check_app_status(
            ops_test,
            SHARD_TWO_APP_NAME,
            status="blocked",
            message=shard_revision_messages[SHARD_TWO_APP_NAME],
        ),
        check_app_status(
            ops_test,
            CONFIG_SERVER_APP_NAME,
            status="waiting",
            message=f"Waiting for shards to upgrade/downgrade to revision {revision}-locally built.",
        ),
    )

    await assert_successful_run_upgrade_sequence(
        ops_test,
        substrate,
        SHARD_ONE_APP_NAME,
        new_charm=mongodb_charm,
        mongod_resource=mongod_resource,
    )

    # Wait for statuses to settle down
    await asyncio.gather(
        check_app_status(
            ops_test,
            SHARD_TWO_APP_NAME,
            status="blocked",
            message=shard_revision_messages[SHARD_TWO_APP_NAME],
        ),
        ops_test.model.wait_for_idle(apps=[SHARD_ONE_APP_NAME], timeout=1000, idle_period=20),
        check_app_status(
            ops_test,
            CONFIG_SERVER_APP_NAME,
            status="waiting",
            message=f"Waiting for shards to upgrade/downgrade to revision {revision}-locally built.",
        ),
    )

    await refresh_with_juju(
        ops_test, CONFIG_SERVER_APP_NAME, channel="8/edge", charm_name=base_app_name
    )

    # verify no writes were skipped during upgrade process
    shard_one_expected_writes = await stop_continous_writes(
        ops_test,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_ONE_DB_NAME,
        coll_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_expected_writes = await stop_continous_writes(
        ops_test,
        client_app_name=CONTINUOUS_WRITE_APPLICATION,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
    )

    shard_one_actual_writes = await count_shard_writes(
        ops_test,
        substrate,
        CONFIG_SERVER_APP_NAME,
        SHARD_ONE_DB_NAME,
        collection_name=SHARD_ONE_COLL_NAME,
    )
    shard_two_actual_writes = await count_shard_writes(
        ops_test,
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
