#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pymongo import MongoClient
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    TIMEOUT,
    deploy_charm,
    find_unit,
    generate_mongodb_client,
    get_address_of_unit,
    get_unit_id,
)
from ...helpers.sharding import (
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    SHARD_THREE_APP_NAME,
    SHARD_TWO_APP_NAME,
    has_correct_shards,
)
from ...helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource,
) -> None:
    """Build and deploy 2 config servers, one shard and one mongos."""
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=SHARD_ONE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=2,
        config={"role": "shard"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=SHARD_TWO_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=2,
        config={"role": "shard"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=SHARD_THREE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=2,
        config={"role": "shard"},
    )


@pytest.mark.abort_on_fail
async def test_immediate_relate(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests the immediate integration of cluster components works without error."""
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.integrate(
        f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.integrate(
        f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    # This test mainly fails on GH runners due to to low timeout (still 30 mins) +
    # update-status-hook-interval to be too high.
    # Safe to use here because `wait_for_idle` cannot raise an error.
    async with ops_test.fast_forward("3m"):
        await ops_test.model.wait_for_idle(
            apps=[
                CONFIG_SERVER_APP_NAME,
                SHARD_ONE_APP_NAME,
                SHARD_TWO_APP_NAME,
                SHARD_THREE_APP_NAME,
            ],
            idle_period=20,
            status="active",
            timeout=TIMEOUT,
            raise_on_error=False,
        )

    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_APP_NAME)

    leader_host = await get_address_of_unit(
        ops_test, substrate, get_unit_id(leader_unit.name), CONFIG_SERVER_APP_NAME
    )

    mongos_uri = await generate_mongodb_client(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, mongos=True, hosts=[leader_host]
    )
    mongos_client = MongoClient(mongos_uri, directConnection=True)

    # verify sharded cluster config
    assert has_correct_shards(
        mongos_client,
        expected_shards=[SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, SHARD_THREE_APP_NAME],
    ), "Config server did not process config properly"
