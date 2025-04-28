# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

from pytest_operator.plugin import OpsTest

from .helpers import DEPLOYMENT_TIMEOUT, deploy_charm

MONGODB_CHARM_NAME = "mongodb"
SHARD_ONE_APP_NAME = "shard-one"
SHARD_TWO_APP_NAME = "shard-two"
CONFIG_SERVER_APP_NAME = "config-server"
CLUSTER_COMPONENTS = [SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, CONFIG_SERVER_APP_NAME]
CONFIG_SERVER_REL_NAME = "config-server"
SHARD_REL_NAME = "sharding"
CLUSTER_REL_NAME = "cluster"


async def deploy_cluster_components(
    ops_test: OpsTest,
    substrate: str,
    mongodb_charm: Path,
    mongod_resource: str,
    num_units_cluster_config: dict | None = None,
    config_server_name: str = CONFIG_SERVER_APP_NAME,
    shard_one_name: str = SHARD_ONE_APP_NAME,
    shard_two_name: str = SHARD_TWO_APP_NAME,
    channel: str | None = None,
    extra_config_config_server: dict[str, str] = {},
) -> None:
    if not num_units_cluster_config:
        num_units_cluster_config = {
            config_server_name: 2,
            shard_one_name: 3,
            shard_two_name: 1,
        }

    if channel is None:
        my_charm = mongodb_charm
    else:
        my_charm = MONGODB_CHARM_NAME

    await deploy_charm(
        ops_test,
        my_charm,
        substrate,
        app_name=config_server_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[config_server_name],
        channel=channel,
        config={"role": "config-server"} | extra_config_config_server,
    )
    await deploy_charm(
        ops_test,
        my_charm,
        substrate,
        app_name=shard_one_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_one_name],
        channel=channel,
        config={"role": "shard"},
    )
    await deploy_charm(
        ops_test,
        my_charm,
        substrate,
        app_name=shard_two_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_two_name],
        channel=channel,
        config={"role": "shard"},
    )

    await ops_test.model.wait_for_idle(
        apps=[config_server_name, shard_one_name, shard_two_name],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )


async def integrate_sharding_components(
    ops_test: OpsTest,
    config_server_name: str = CONFIG_SERVER_APP_NAME,
    shard_one_name: str = SHARD_ONE_APP_NAME,
    shard_two_name: str = SHARD_TWO_APP_NAME,
) -> None:
    """Integrates the cluster components with each other."""
    await ops_test.model.integrate(
        f"{shard_one_name}:{SHARD_REL_NAME}",
        f"{config_server_name}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.integrate(
        f"{shard_two_name}:{SHARD_REL_NAME}",
        f"{config_server_name}:{CONFIG_SERVER_REL_NAME}",
    )
