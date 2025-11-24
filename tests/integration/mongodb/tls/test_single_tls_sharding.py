#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import DEPLOYMENT_TIMEOUT, TIMEOUT
from tests.integration.helpers.sharding import (
    CLUSTER_COMPONENTS,
    check_cluster_tls_disabled,
    check_cluster_tls_enabled,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.tls import (
    CLIENT_TLS_RELATION_NAME,
    PEER_TLS_RELATION_NAME,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.types import Substrate


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
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
    )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS + [TLS_CERTIFICATES_APP_NAME],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
        raise_on_blocked=False,
    )


@pytest.mark.abort_on_fail
async def test_built_cluster_with_peer_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that the cluster, when integrated with peer TLS, allows non TLS client relations."""
    await integrate_sharding_components(ops_test)
    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        timeout=TIMEOUT,
    )

    for app in CLUSTER_COMPONENTS:
        await ops_test.model.integrate(TLS_CERTIFICATES_APP_NAME, f"{app}:{PEER_TLS_RELATION_NAME}")

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS, idle_period=20, timeout=TIMEOUT, status="active"
    )

    # This checks that clients can connect using non-tls connections.
    await check_cluster_tls_disabled(ops_test, substrate)

    for app in CLUSTER_COMPONENTS:
        await ops_test.model.applications[app].remove_relation(
            f"{app}:{PEER_TLS_RELATION_NAME}", TLS_CERTIFICATES_APP_NAME
        )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS, idle_period=20, timeout=TIMEOUT, status="active"
    )


@pytest.mark.abort_on_fail
async def test_built_cluster_with_client_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that the cluster, when integrated with client TLS, enforces the TLS relations."""
    for app in CLUSTER_COMPONENTS:
        await ops_test.model.integrate(
            TLS_CERTIFICATES_APP_NAME, f"{app}:{CLIENT_TLS_RELATION_NAME}"
        )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS, idle_period=20, timeout=TIMEOUT, status="active"
    )

    # This checks that clients can connect using non-tls connections.
    await check_cluster_tls_enabled(ops_test, substrate)

    for app in CLUSTER_COMPONENTS:
        await ops_test.model.applications[app].remove_relation(
            f"{app}:{CLIENT_TLS_RELATION_NAME}", TLS_CERTIFICATES_APP_NAME
        )

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        status="active",
        idle_period=20,
        timeout=TIMEOUT,
    )
