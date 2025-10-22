#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.sharding import CONFIG_SERVER_REL_NAME, SHARD_REL_NAME

from ...helpers.common import DEPLOYMENT_TIMEOUT, TIMEOUT, check_app_status, deploy_charm
from ...helpers.types import Substrate

LOCAL_SHARD_APP_NAME = "local-shard"
REMOTE_SHARD_APP_NAME = "remote-shard"
LOCAL_CONFIG_SERVER_APP_NAME = "local-config-server"
REMOTE_CONFIG_SERVER_APP_NAME = "remote-config-server"

CLUSTER_COMPONENTS = [
    LOCAL_SHARD_APP_NAME,
    REMOTE_SHARD_APP_NAME,
    LOCAL_CONFIG_SERVER_APP_NAME,
    REMOTE_CONFIG_SERVER_APP_NAME,
]


async def test_build_and_deploy(
    ops_test: OpsTest, mongodb_charm: str, substrate: Substrate, mongod_resource
) -> None:
    charm = "mongodb" if substrate == "lxd" else "mongodb-k8s"
    await deploy_charm(
        ops_test,
        charm,
        substrate,
        app_name=REMOTE_CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
        channel="8/edge",
    )
    await deploy_charm(
        ops_test,
        charm,
        substrate,
        app_name=REMOTE_SHARD_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
        channel="8/edge",
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=LOCAL_CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=LOCAL_SHARD_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS, idle_period=20, timeout=DEPLOYMENT_TIMEOUT, raise_on_blocked=False
    )


@pytest.mark.abort_on_fail
async def test_local_config_server_reports_remote_shard(ops_test: OpsTest) -> None:
    """Tests that the local config server reports remote shard."""
    await ops_test.model.integrate(
        f"{REMOTE_SHARD_APP_NAME}:{SHARD_REL_NAME}",
        f"{LOCAL_CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[LOCAL_CONFIG_SERVER_APP_NAME],
        raise_on_blocked=False,
        idle_period=20,
        timeout=TIMEOUT,
    )
    await check_app_status(ops_test, LOCAL_CONFIG_SERVER_APP_NAME, status="waiting")

    config_server_app = ops_test.model.applications[LOCAL_CONFIG_SERVER_APP_NAME]

    assert (
        "Waiting for shards to upgrade/downgrade to revision" in config_server_app.status_message
    ), "Config server does not correctly report mismatch in revision"


@pytest.mark.abort_on_fail
async def test_local_shard_reports_remote_config_server(
    ops_test: OpsTest, substrate: Substrate
) -> None:
    """Tests that the local shard reports remote config-server."""
    await ops_test.model.integrate(
        f"{LOCAL_SHARD_APP_NAME}:{SHARD_REL_NAME}",
        f"{REMOTE_CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[LOCAL_SHARD_APP_NAME],
        raise_on_blocked=False,
        idle_period=20,
        timeout=TIMEOUT,
    )
    local_shard_app = ops_test.model.applications[LOCAL_SHARD_APP_NAME]

    assert (
        "is not up-to data with config-server" in local_shard_app.status_message
    ), "Shard does not correctly report mismatch in revision"
