#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CLUSTER_COMPONENTS,
    DEPLOYMENT_TIMEOUT,
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
    rotate_and_verify_certs,
)
from tests.integration.helpers.jubilant_tls import (
    integrate_apps_with_tls,
    remove_tls_integrations,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
) -> None:
    """Build and deploy one unit of MongoDB."""
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
async def test_built_cluster_with_tls(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that the cluster can be integrated with TLS."""
    assert juju.model
    integrate_sharding_components(juju)
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

    integrate_apps_with_tls(juju, *CLUSTER_COMPONENTS)

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

    check_cluster_tls_enabled(juju, substrate)


@pytest.mark.abort_on_fail
def test_rotate_tls(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that each cluster component can rotate TLS certs."""
    for cluster_app in CLUSTER_COMPONENTS:
        rotate_and_verify_certs(juju, substrate, cluster_app)


@pytest.mark.abort_on_fail
async def test_disable_cluster_with_tls(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that the cluster can disable TLS."""
    remove_tls_integrations(juju, *CLUSTER_COMPONENTS)
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
    check_cluster_tls_disabled(juju, substrate)
