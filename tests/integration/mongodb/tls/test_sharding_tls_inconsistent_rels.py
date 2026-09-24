#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import jubilant
import pytest

from single_kernel_mongo.config.statuses import ShardStatuses
from tests.integration.helpers.constants import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    DEPLOYMENT_TIMEOUT,
    DIFFERENT_CERTIFICATES_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    SHARD_THREE_APP_NAME,
    SHARD_TWO_APP_NAME,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    find_leader,
    get_status_detail,
)
from tests.integration.helpers.jubilant_sharding import (
    check_cluster_tls_enabled,
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.jubilant_tls import (
    integrate_apps_with_tls,
    remove_tls_integrations,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
def test_tls_then_build_cluster(
    juju: jubilant.Juju, substrate: Substrate, mongodb_charm: str, mongod_resource: dict[str, str]
) -> None:
    """Tests that the cluster can be integrated with TLS."""
    num_units_cluster_config = {
        CONFIG_SERVER_APP_NAME: 2,
        SHARD_ONE_APP_NAME: 3,
        SHARD_TWO_APP_NAME: 1,
    }

    deploy_cluster_components(
        juju,
        substrate,
        mongodb_charm,
        mongod_resource,
        num_units_cluster_config=num_units_cluster_config,
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
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    integrate_apps_with_tls(juju, *CLUSTER_COMPONENTS)

    juju.wait(
        lambda status: are_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=30,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    integrate_sharding_components(juju)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    check_cluster_tls_enabled(
        juju,
        substrate,
        components=CLUSTER_COMPONENTS,
        config_server=CONFIG_SERVER_APP_NAME,
    )


@pytest.mark.abort_on_fail
def test_tls_inconsistent_rels(juju: jubilant.Juju, substrate: Substrate) -> None:
    juju.deploy(
        charm=TLS_CERTIFICATES_APP_NAME,
        app=DIFFERENT_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
    )

    # CASE 1: Config-server has TLS enabled - but shard does not
    remove_tls_integrations(juju, SHARD_ONE_APP_NAME)

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                *CLUSTER_COMPONENTS,
                idle_period=30,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    SHARD_ONE_APP_NAME: [ShardStatuses.MISSING_PEER_TLS_REL.value]
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Re-integrate to bring cluster back to steady state
    integrate_apps_with_tls(juju, SHARD_ONE_APP_NAME)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # CASE 2: Config-server does not have TLS enabled - but shard does
    remove_tls_integrations(juju, CONFIG_SERVER_APP_NAME)

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                *CLUSTER_COMPONENTS,
                idle_period=30,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    SHARD_ONE_APP_NAME: [ShardStatuses.INVALID_PEER_TLS_REL.value]
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # CASE 3: Cluster components are using different CA's
    integrate_apps_with_tls(
        juju,
        CONFIG_SERVER_APP_NAME,
        cert_provider_app=DIFFERENT_CERTIFICATES_APP_NAME,
    )

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                *CLUSTER_COMPONENTS,
                idle_period=30,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={SHARD_ONE_APP_NAME: [ShardStatuses.PEER_CA_MISMATCH.value]},
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    leader_name, _ = find_leader(juju, app_name=SHARD_ONE_APP_NAME)
    statuses = get_status_detail(juju, leader_name)

    assert any(
        unit_status["Message"] == "Shard internal CA and Config-Server internal CA don't match."
        for unit_status in statuses["unit"]
    ), "Shard internal CA status not well reported."
    assert any(
        unit_status["Message"] == "Shard client CA and Config-Server client CA don't match."
        for unit_status in statuses["unit"]
    ), "Shard client CA status not well reported."


def test_invalid_relation_not_yet_established(
    juju: jubilant.Juju, substrate: Substrate, mongodb_charm: str, mongod_resource: dict[str, str]
):
    """Deploy a shard, integrate it but only the config server has TLS.

    Then remove it and it should remove immediately and keep the relation to
    config-server status.
    """
    # Deploy a new shard
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=SHARD_THREE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )

    juju.wait(
        lambda status: are_agents_idle(
            status,
            SHARD_THREE_APP_NAME,
            idle_period=30,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    # Integrate the shard with the config-server
    juju.integrate(
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
    )

    # Shard has not TLS but config server has
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                SHARD_THREE_APP_NAME,
                idle_period=30,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    SHARD_THREE_APP_NAME: [ShardStatuses.MISSING_PEER_TLS_REL.value]
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Remove the not yet added shard
    juju.remove_relation(
        f"{SHARD_THREE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    # Wait to go back to normal status.
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                SHARD_THREE_APP_NAME,
                idle_period=30,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    SHARD_THREE_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value]
                },
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )
