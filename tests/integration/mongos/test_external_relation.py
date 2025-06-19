#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    DATA_INTEGRATOR_APP_NAME,
    MONGOS_APP_NAME,
    deploy_charm,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.mongos import check_mongos, generate_mongos_uri, get_k8s_public_ip
from tests.integration.helpers.sharding import (
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
)

from ..helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict,
    mongos_resource: dict,
) -> None:
    """Build and deploy a sharded cluster."""
    await ops_test.model.deploy(DATA_INTEGRATOR_APP_NAME, channel="latest/stable", series="jammy")
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        config={"role": "config-server"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=SHARD_ONE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )
    await deploy_charm(
        ops_test,
        mongos_charm,
        substrate,
        app_name=MONGOS_APP_NAME,
        mongod_resource=mongos_resource,
        num_units=0 if substrate == "lxd" else 1,
    )
    await ops_test.model.wait_for_idle(
        apps=[DATA_INTEGRATOR_APP_NAME, SHARD_ONE_APP_NAME, CONFIG_SERVER_APP_NAME],
        idle_period=10,
        raise_on_blocked=False,
    )

    if substrate == "microk8s":
        await ops_test.model.applications[MONGOS_APP_NAME].set_config(
            {"expose-external": "nodeport"}
        )


@pytest.mark.abort_on_fail
async def test_mongos_starts_with_config_server(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify mongos is running and can be accessed externally via IP-address."""
    # mongos cannot start until it has a host application
    await ops_test.model.applications[DATA_INTEGRATOR_APP_NAME].set_config(
        {
            "database-name": "test-database",
        }
    )

    await ops_test.model.integrate(DATA_INTEGRATOR_APP_NAME, MONGOS_APP_NAME)
    await wait_for_mongodb_units_blocked(
        ops_test, substrate, MONGOS_APP_NAME, timeout=300, subordinate=(substrate == "lxd")
    )
    # prepare sharded cluster
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME],
        idle_period=10,
        raise_on_blocked=False,
    )
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
    )

    # connect sharded cluster to mongos
    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, MONGOS_APP_NAME],
        idle_period=20,
        status="active",
    )

    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    mongos_running = await check_mongos(
        ops_test, substrate, mongos_unit, app_name=MONGOS_APP_NAME, auth=False, external=True
    )
    assert mongos_running, "Mongos is not currently running."


@pytest.mark.abort_on_fail
async def test_mongos_has_user(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify mongos has user and is able to connect externally via IP-address."""
    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    mongos_running = await check_mongos(
        ops_test,
        substrate,
        mongos_unit,
        app_name=DATA_INTEGRATOR_APP_NAME,
        auth=True,
        external=True,
    )
    assert mongos_running, "Mongos is not currently running."


@pytest.mark.abort_on_fail
async def test_mongos_can_scale(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify hosts are up to date after scaling."""
    first_mongos_host = ops_test.model.applications[DATA_INTEGRATOR_APP_NAME].units[0]

    # in order to scale mongos, we need to scale the host
    if substrate == "lxd":
        await ops_test.model.applications[DATA_INTEGRATOR_APP_NAME].add_unit(count=1)
    else:
        await ops_test.model.applications[MONGOS_APP_NAME].scale(scale_change=1)

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME, DATA_INTEGRATOR_APP_NAME], idle_period=20, wait_for_exact_units=2
    )

    for mongos_unit in ops_test.model.applications[MONGOS_APP_NAME].units:
        secret_uri = await generate_mongos_uri(
            ops_test, substrate, auth=True, app_name=DATA_INTEGRATOR_APP_NAME, external=True
        )
        if substrate == "lxd":
            mongos_ip = mongos_unit.public_address
        else:
            mongos_ip = get_k8s_public_ip()
        assert mongos_ip in secret_uri, f"host for {mongos_unit} is not present in URI"

        mongos_running = await check_mongos(
            ops_test,
            substrate,
            mongos_unit,
            app_name=DATA_INTEGRATOR_APP_NAME,
            auth=True,
            external=True,
        )
        assert mongos_running, f"Mongos is not currently running on unit {mongos_unit}."

    if substrate == "lxd":
        # destroy the first unit so the hosts are different from when the application was deployed
        first_mongos_host_public_address = first_mongos_host.public_address
        await ops_test.model.applications[DATA_INTEGRATOR_APP_NAME].destroy_unit(
            first_mongos_host.name
        )

        await ops_test.model.wait_for_idle(
            apps=[MONGOS_APP_NAME, DATA_INTEGRATOR_APP_NAME],
            idle_period=20,
        )

        secret_uri = await generate_mongos_uri(
            ops_test, substrate, auth=True, app_name=DATA_INTEGRATOR_APP_NAME, external=True
        )
        assert (
            first_mongos_host_public_address not in secret_uri
        ), "old host is still present in URI"
