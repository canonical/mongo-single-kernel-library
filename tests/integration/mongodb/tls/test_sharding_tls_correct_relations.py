#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import DEPLOYMENT_TIMEOUT, TIMEOUT
from ...helpers.sharding import (
    CLUSTER_COMPONENTS,
    check_cluster_tls_disabled,
    check_cluster_tls_enabled,
    deploy_cluster_components,
    integrate_sharding_components,
    integrate_with_tls,
    remove_tls_integrations,
    rotate_and_verify_certs,
)
from ...helpers.tls import TLS_CERTIFICATES_APP_NAME
from ...helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource,
) -> None:
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    await deploy_cluster_components(
        ops_test,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
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


@pytest.mark.abort_on_fail
async def test_built_cluster_with_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that the cluster can be integrated with TLS."""
    await integrate_sharding_components(ops_test)
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
    )

    await integrate_with_tls(ops_test)

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS, idle_period=20, timeout=TIMEOUT, status="active"
    )

    await check_cluster_tls_enabled(ops_test, substrate)

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        idle_period=20,
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_rotate_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that each cluster component can rotate TLS certs."""
    for cluster_app in CLUSTER_COMPONENTS:
        await rotate_and_verify_certs(ops_test, substrate, cluster_app)


@pytest.mark.abort_on_fail
async def test_disable_cluster_with_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that the cluster can disable TLS."""
    await remove_tls_integrations(ops_test)
    await check_cluster_tls_disabled(ops_test, substrate)
