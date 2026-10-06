#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant

from tests.integration.helpers.constants import (
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    SHARD_THREE_APP_NAME,
    SHARD_TWO_APP_NAME,
    SMALL_K8S_STORAGE,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    fast_forward,
)
from tests.integration.helpers.jubilant_sharding import (
    build_mongos_client,
    has_correct_shards,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

RC_TIMEOUT = 60 * 30


def test_build_and_deploy(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
) -> None:
    """Build and deploy 2 config servers, one shard and one mongos."""
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=CONFIG_SERVER_APP_NAME,
        num_units=3,
        config={"role": "config-server"},
        storage=SMALL_K8S_STORAGE if substrate == Substrate.k8s else None,
    )
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=SHARD_ONE_APP_NAME,
        num_units=3,
        config={"role": "shard"},
        storage=SMALL_K8S_STORAGE if substrate == Substrate.k8s else None,
    )
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=SHARD_TWO_APP_NAME,
        num_units=3,
        config={"role": "shard"},
        storage=SMALL_K8S_STORAGE if substrate == Substrate.k8s else None,
    )
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=SHARD_THREE_APP_NAME,
        num_units=3,
        config={"role": "shard"},
        storage=SMALL_K8S_STORAGE if substrate == Substrate.k8s else None,
    )


def test_immediate_relate(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests the immediate integration of cluster components works without error."""
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.integrate(
        f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.integrate(
        f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    # This test mainly fails on GH runners due to to low timeout (still 30 mins) +
    # update-status-hook-interval to be too high.
    # Safe to use here because `wait_for_idle` cannot raise an error.
    with fast_forward(juju, "3m"):
        juju.wait(
            lambda status: are_apps_active_and_agents_idle(
                status,
                CONFIG_SERVER_APP_NAME,
                SHARD_ONE_APP_NAME,
                SHARD_TWO_APP_NAME,
                SHARD_THREE_APP_NAME,
                idle_period=30,
            ),
            timeout=RC_TIMEOUT,
        )

    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)

    # verify sharded cluster config
    assert has_correct_shards(
        mongos_client,
        expected_shards=[SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, SHARD_THREE_APP_NAME],
    ), "Config server did not process config properly"
