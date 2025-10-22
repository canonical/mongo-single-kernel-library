#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    deploy_charm,
    find_unit,
    get_status_detail,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.sharding import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    SHARD_THREE_APP_NAME,
    SHARD_TWO_APP_NAME,
    check_cluster_tls_enabled,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.tls import (
    DIFFERENT_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_APP_NAME,
    integrate_apps_with_tls,
    remove_tls_integrations,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_tls_then_build_cluster(
    ops_test: OpsTest, substrate: Substrate, mongodb_charm: str, mongod_resource: dict
) -> None:
    """Tests that the cluster can be integrated with TLS."""
    num_units_cluster_config = {
        CONFIG_SERVER_APP_NAME: 2,
        SHARD_ONE_APP_NAME: 3,
        SHARD_TWO_APP_NAME: 1,
    }

    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongod_resource,
        num_units_cluster_config=num_units_cluster_config,
    )
    # deploy the self-signed-certificates charm
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel="latest/stable",
        base="ubuntu@22.04",
    )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS + [TLS_CERTIFICATES_APP_NAME],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
        raise_on_blocked=False,
    )

    await integrate_apps_with_tls(ops_test, applications=CLUSTER_COMPONENTS)

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
    )

    await integrate_sharding_components(ops_test)

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        status="active",
    )

    await check_cluster_tls_enabled(
        ops_test,
        substrate,
        components=CLUSTER_COMPONENTS,
        config_server=CONFIG_SERVER_APP_NAME,
    )


@pytest.mark.abort_on_fail
async def test_tls_inconsistent_rels(ops_test: OpsTest, substrate: Substrate) -> None:
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        application_name=DIFFERENT_CERTIFICATES_APP_NAME,
        channel="latest/stable",
        base="ubuntu@22.04",
    )

    # CASE 1: Config-server has TLS enabled - but shard does not
    await remove_tls_integrations(ops_test, applications=[SHARD_ONE_APP_NAME])

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        SHARD_ONE_APP_NAME,
        status="Shard requires peer TLS to be enabled.",
        timeout=TIMEOUT,
    )

    # Re-integrate to bring cluster back to steady state
    await integrate_apps_with_tls(ops_test, applications=[SHARD_ONE_APP_NAME])

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
        status="active",
    )

    # CASE 2: Config-server does not have TLS enabled - but shard does
    await remove_tls_integrations(ops_test, applications=[CONFIG_SERVER_APP_NAME])

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
    )
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        SHARD_ONE_APP_NAME,
        status="Invalid peer-certificates relation.",
        timeout=450,
    )

    # CASE 3: Cluster components are using different CA's

    # Re-integrate to bring cluster back to steady state
    await integrate_apps_with_tls(
        ops_test,
        applications=[CONFIG_SERVER_APP_NAME],
        cert_provider_app=DIFFERENT_CERTIFICATES_APP_NAME,
    )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        SHARD_ONE_APP_NAME,
        status="Peer CA mismatch.",
        timeout=450,
    )

    leader_unit = await find_unit(ops_test, leader=True, app_name=SHARD_ONE_APP_NAME)
    statuses = await get_status_detail(leader_unit)

    unit_statuses = json.loads(statuses["unit"])
    assert any(
        unit_status["Message"] == "Shard internal CA and Config-Server internal CA don't match."
        for unit_status in unit_statuses
    ), "Shard internal CA status not well reported."
    assert any(
        unit_status["Message"] == "Shard client CA and Config-Server client CA don't match."
        for unit_status in unit_statuses
    ), "Shard client CA status not well reported."


async def test_invalid_relation_not_yet_established(
    ops_test: OpsTest, substrate: Substrate, mongodb_charm: str, mongod_resource: dict
):
    """Deploy a shard, integrate it but only the config server has TLS.

    Then remove it and it should remove immediately and keep the relation to
    config-server status.
    """
    # Deploy a new shard
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=SHARD_THREE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )
    await ops_test.model.wait_for_idle(
        apps=[SHARD_THREE_APP_NAME],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )

    # Integrate the shard with the config-server
    await ops_test.model.integrate(
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
    )

    # Shard has not TLS but config server has
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        SHARD_THREE_APP_NAME,
        status="Shard requires peer TLS to be enabled.",
        timeout=TIMEOUT,
    )

    # Remove the not yet added shard
    await ops_test.model.applications[SHARD_THREE_APP_NAME].remove_relation(
        f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    # Wait to go back to normal status.
    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        SHARD_THREE_APP_NAME,
        status="Missing relation to config-server.",
        timeout=TIMEOUT,
    )
