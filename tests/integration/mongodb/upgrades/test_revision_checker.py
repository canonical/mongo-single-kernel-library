#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant

from single_kernel_mongo.config.statuses import ConfigServerStatuses, ShardStatuses
from tests.integration.helpers.constants import (
    CONFIG_SERVER_REL_NAME,
    DEPLOYMENT_TIMEOUT,
    SHARD_REL_NAME,
)
from tests.integration.helpers.jubilant_common import deploy_charm
from tests.integration.helpers.status_helpers import are_agents_idle, does_status_match
from tests.integration.helpers.types import Substrate

LOCAL_SHARD_APP_NAME = "local-shard"
REMOTE_SHARD_APP_NAME = "remote-shard"
LOCAL_CONFIG_SERVER_APP_NAME = "local-config-server"
REMOTE_CONFIG_SERVER_APP_NAME = "remote-config-server"

CLUSTER_COMPONENTS = [
    LOCAL_SHARD_APP_NAME,
    REMOTE_SHARD_APP_NAME,
    LOCAL_CONFIG_SERVER_APP_NAME,
    REMOTE_CONFIG_SERVER_APP_NAME,
]


def test_build_and_deploy(
    juju: jubilant.Juju, mongodb_charm: str, substrate: Substrate, mongod_resource: dict[str, str]
) -> None:
    charm = "mongodb" if substrate == Substrate.lxd else "mongodb-k8s"
    deploy_charm(
        juju,
        charm,
        substrate,
        app_name=REMOTE_CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
        channel="8/edge",
    )
    deploy_charm(
        juju,
        charm,
        substrate,
        app_name=REMOTE_SHARD_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
        channel="8/edge",
    )
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=LOCAL_CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
    )
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=LOCAL_SHARD_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                *CLUSTER_COMPONENTS,
                idle_period=20,
                unit_count={},
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    REMOTE_CONFIG_SERVER_APP_NAME: [
                        ConfigServerStatuses.MISSING_CONF_SERVER_REL.value
                    ],
                    LOCAL_CONFIG_SERVER_APP_NAME: [
                        ConfigServerStatuses.MISSING_CONF_SERVER_REL.value
                    ],
                    REMOTE_SHARD_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
                    LOCAL_SHARD_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
                },
            )
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_local_config_server_reports_remote_shard(juju: jubilant.Juju) -> None:
    """Tests that the local config server reports remote shard."""
    revision = "test/0.0.0+dirty"
    juju.integrate(
        f"{REMOTE_SHARD_APP_NAME}:{SHARD_REL_NAME}",
        f"{LOCAL_CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                LOCAL_CONFIG_SERVER_APP_NAME,
                idle_period=20,
                unit_count={},
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={},
                expected_app_statuses={
                    LOCAL_CONFIG_SERVER_APP_NAME: [
                        ConfigServerStatuses.waiting_for_shard_upgrade(revision, "-locally built")
                    ]
                },
            )
        )
    )


def test_local_shard_reports_remote_config_server(juju: jubilant.Juju) -> None:
    """Tests that the local shard reports remote config-server."""
    revision = "test/0.0.0+dirty"
    cfg_server_revision = str(juju.status().apps.get(REMOTE_CONFIG_SERVER_APP_NAME).charm_rev)
    juju.integrate(
        f"{LOCAL_SHARD_APP_NAME}:{SHARD_REL_NAME}",
        f"{REMOTE_CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    # Because we can't provide an exact status easily, we build a status that
    # contains the correct prefixes.
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                LOCAL_CONFIG_SERVER_APP_NAME,
                idle_period=20,
                unit_count={},
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={},
                expected_app_statuses={
                    LOCAL_SHARD_APP_NAME: [
                        ShardStatuses.shard_needs_upgrade(
                            revision, "-locally built", cfg_server_revision, ""
                        )
                    ]
                },
            )
        )
    )
