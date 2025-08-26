#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    DATA_INTEGRATOR_APP_NAME,
    MONGOS_APP_NAME,
    check_status_detail,
    deploy_charm,
    wait_for_mongodb_units_blocked,
)
from ..helpers.mongos import (
    MONGOS_CLIENT_APPLICATION,
    assert_all_unit_node_ports_are_unavailable,
    assert_all_unit_node_ports_available,
    assert_app_uri_matches_external_setting,
    get_port_from_node_port,
    is_external_mongos_client_reachable,
)
from ..helpers.sharding import (
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
)
from ..helpers.types import Substrate


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_build_and_deploy(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict,
    mongos_resource: dict,
    mongos_client_application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    await ops_test.model.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        series="jammy",
        config={"database-name": "test-database"},
    )
    await ops_test.model.deploy(
        mongos_client_application_path, application_name=MONGOS_CLIENT_APPLICATION
    )
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
        apps=[
            DATA_INTEGRATOR_APP_NAME,
            MONGOS_CLIENT_APPLICATION,
            SHARD_ONE_APP_NAME,
            CONFIG_SERVER_APP_NAME,
        ],
        idle_period=10,
        raise_on_blocked=False,
    )
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.integrate(DATA_INTEGRATOR_APP_NAME, MONGOS_APP_NAME)
    await wait_for_mongodb_units_blocked(ops_test, substrate, MONGOS_APP_NAME, timeout=300)
    await ops_test.model.integrate(MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME)
    await wait_for_mongodb_units_blocked(ops_test, substrate, MONGOS_APP_NAME, timeout=300)

    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[
            DATA_INTEGRATOR_APP_NAME,
            MONGOS_CLIENT_APPLICATION,
            SHARD_ONE_APP_NAME,
            CONFIG_SERVER_APP_NAME,
        ],
        idle_period=10,
        raise_on_blocked=False,
        status="active",
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_mongos_external_connections(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos is accessible externally."""
    configuration_parameters = {"expose-external": "nodeport"}

    # apply new configuration options
    await ops_test.model.applications[MONGOS_APP_NAME].set_config(configuration_parameters)
    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], status="active", idle_period=15)

    # verify each unit has a node port available
    await assert_all_unit_node_ports_available(ops_test)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_mongos_external_connections_scale(ops_test: OpsTest) -> None:
    """Tests that new mongos units are accessible externally."""
    await ops_test.model.applications[MONGOS_APP_NAME].scale(2)
    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], status="active", idle_period=15)

    # verify each unit has a node port available
    await assert_all_unit_node_ports_available(ops_test)


async def test_mongos_bad_configuration(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that mongos is accessible externally."""
    if substrate == "lxd":
        pytest.skip(reason="Only runs on K8S.")
    configuration_parameters = {"expose-external": "nonsensical-setting"}

    # apply new configuration options
    await ops_test.model.applications[MONGOS_APP_NAME].set_config(configuration_parameters)

    # verify that Charmed Mongos is blocked and reports incorrect credentials
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        MONGOS_APP_NAME,
        status="Invalid expose-external config",
        timeout=300,
    )

    await check_status_detail(
        ops_test,
        MONGOS_APP_NAME,
        status="blocked",
        message="The expose-external config option is invalid. Valid options are `nodeport` and `none`.",
    )

    # verify new-configuration didn't break old configuration
    await assert_all_unit_node_ports_available(ops_test)

    # reset config for other tests
    configuration_parameters = {"expose-external": "nodeport"}
    await ops_test.model.applications[MONGOS_APP_NAME].set_config(configuration_parameters)
    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], status="active", idle_period=15)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_all_clients_use_nodeport(ops_test: OpsTest) -> None:
    """Test that all clients use nodeport."""
    await assert_app_uri_matches_external_setting(
        ops_test, app_name=DATA_INTEGRATOR_APP_NAME, rel_name="mongodb", external=True
    )
    await assert_app_uri_matches_external_setting(
        ops_test, app_name=MONGOS_CLIENT_APPLICATION, rel_name="mongos", external=True
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_mongos_disable_external_connections(ops_test: OpsTest) -> None:
    """Tests that mongos can disable external connections."""
    # get exposed node port before toggling off exposure
    exposed_node_port = get_port_from_node_port(
        ops_test, node_port_name=f"{MONGOS_APP_NAME}-0-external"
    )

    configuration_parameters = {"expose-external": "none"}

    # apply new configuration options
    await ops_test.model.applications[MONGOS_APP_NAME].set_config(configuration_parameters)
    await ops_test.model.wait_for_idle(
        apps=[MONGOS_APP_NAME, DATA_INTEGRATOR_APP_NAME],
        status="active",
        idle_period=15,
    )

    # verify each unit has a node port available
    await assert_all_unit_node_ports_are_unavailable(ops_test)

    assert not await is_external_mongos_client_reachable(ops_test, exposed_node_port)

    await assert_app_uri_matches_external_setting(
        ops_test, app_name=DATA_INTEGRATOR_APP_NAME, rel_name="mongodb", external=False
    )
    await assert_app_uri_matches_external_setting(
        ops_test, app_name=MONGOS_CLIENT_APPLICATION, rel_name="mongos", external=False
    )
