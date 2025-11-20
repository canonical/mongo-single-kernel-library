#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    deploy_charm,
    wait_for_mongodb_units_blocked,
)
from ...helpers.sharding import (
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
    integrate_with_tls,
)
from ...helpers.tls import (
    DIFFERENT_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_APP_NAME,
    TLS_RELATION_NAME,
)
from ...helpers.types import Substrate


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

    await integrate_with_tls(ops_test, applications=CLUSTER_COMPONENTS)

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
    await ops_test.model.applications[SHARD_ONE_APP_NAME].remove_relation(
        f"{SHARD_ONE_APP_NAME}:{TLS_RELATION_NAME}",
        f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
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
        status="Shard requires TLS to be enabled",
        timeout=TIMEOUT,
    )

    # Re-integrate to bring cluster back to steady state
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{TLS_RELATION_NAME}",
        f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
        raise_on_blocked=False,
        status="active",
    )

    # CASE 2: Config-server does not have TLS enabled - but shard does
    await ops_test.model.applications[CONFIG_SERVER_APP_NAME].remove_relation(
        f"{CONFIG_SERVER_APP_NAME}:{TLS_RELATION_NAME}",
        f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
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
        status="TLS must be disabled in shard, since it is disabled on the config-server in the cluster relation.",
        timeout=450,
    )

    # CASE 3: Cluster components are using different CA's

    # Re-integrate to bring cluster back to steady state
    await ops_test.model.integrate(
        f"{CONFIG_SERVER_APP_NAME}:{TLS_RELATION_NAME}",
        f"{DIFFERENT_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
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
        status="Shard CA and config-server CA don't match.",
        timeout=450,
    )


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
        status="Shard requires TLS to be enabled.",
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
