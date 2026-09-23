#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import jubilant
import pytest

from tests.integration.helpers.constants import (
    CLIENT_TLS_RELATION_NAME,
    CLUSTER_COMPONENTS,
    DEPLOYMENT_TIMEOUT,
    PEER_TLS_RELATION_NAME,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.jubilant_sharding import (
    check_cluster_tls_disabled,
    check_cluster_tls_enabled,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
) -> None:
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    deploy_cluster_components(
        juju,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
    )
    # deploy the self-signed-certificates charm
    juju.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
    )

    juju.wait(
        lambda status: are_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=30,
            unit_count=3,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_built_cluster_with_peer_tls(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that the cluster, when integrated with peer TLS, allows non TLS client relations."""
    integrate_sharding_components(juju)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    for app in CLUSTER_COMPONENTS:
        juju.integrate(TLS_CERTIFICATES_APP_NAME, f"{app}:{PEER_TLS_RELATION_NAME}")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # This checks that clients can connect using non-tls connections.
    check_cluster_tls_disabled(juju, substrate)

    for app in CLUSTER_COMPONENTS:
        juju.remove_relation(f"{app}:{PEER_TLS_RELATION_NAME}", TLS_CERTIFICATES_APP_NAME)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_built_cluster_with_client_tls(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that the cluster, when integrated with client TLS, enforces the TLS relations."""
    for app in CLUSTER_COMPONENTS:
        juju.integrate(TLS_CERTIFICATES_APP_NAME, f"{app}:{CLIENT_TLS_RELATION_NAME}")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # This checks that clients can connect using non-tls connections.
    check_cluster_tls_enabled(juju, substrate)

    for app in CLUSTER_COMPONENTS:
        juju.remove_relation(f"{app}:{CLIENT_TLS_RELATION_NAME}", TLS_CERTIFICATES_APP_NAME)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )
