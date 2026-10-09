#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

from single_kernel_mongo.config.statuses import MongoDBStatuses
from tests.integration.helpers.constants import (
    APPLICATION_APP_NAME,
    BASE,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    CONFIG_SERVER_TWO_APP_NAME,
    DATA_INTEGRATOR_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    FIRST_DATABASE_RELATION_NAME,
    MONGOS_APP_NAME,
    REPLICATION_APP_NAME,
    S3_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
)
from tests.integration.helpers.jubilant_tls import (
    integrate_apps_with_tls,
    remove_tls_integrations,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate

SHARDING_COMPONENTS = [SHARD_ONE_APP_NAME, CONFIG_SERVER_APP_NAME]

RELATION_LIMIT_MESSAGE = 'cannot add relation "shard-one:sharding config-server-two:config-server": establishing a new relation for shard-one:sharding would exceed its maximum relation limit of 1'


def test_build_and_deploy(
    juju: jubilant.Juju,
    mongodb_charm: str,
    mongos_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    client_relation_charm_path: str,
) -> None:
    """Build and deploy 2 config servers, one shard and one mongos."""
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
    )
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_TWO_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
    )
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=SHARD_ONE_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "shard"},
    )
    deploy_charm(
        juju,
        mongos_charm,
        substrate,
        app_name=MONGOS_APP_NAME,
        mongod_resource=mongos_resource,
        num_units=1,
    )
    juju.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_CERTIFICATES_CHANNEL, base=TLS_CERTIFICATES_BASE
    )
    juju.deploy(S3_APP_NAME, channel="2/edge")

    juju.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        base=BASE,
        config={"extra-user-roles": "admin"},
    )

    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=REPLICATION_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
    )
    juju.deploy(
        client_relation_charm_path,
        app=APPLICATION_APP_NAME,
        num_units=1,
        base=BASE,
    )

    juju.wait(
        lambda status: are_agents_idle(
            status,
            APPLICATION_APP_NAME,
            CONFIG_SERVER_APP_NAME,
            CONFIG_SERVER_TWO_APP_NAME,
            SHARD_ONE_APP_NAME,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=20,
            unit_count={
                APPLICATION_APP_NAME: 1,
                CONFIG_SERVER_APP_NAME: 1,
                CONFIG_SERVER_TWO_APP_NAME: 1,
                SHARD_ONE_APP_NAME: 1,
                TLS_CERTIFICATES_APP_NAME: 1,
            },
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    juju.integrate(
        f"{MONGOS_APP_NAME}",
        f"{DATA_INTEGRATOR_APP_NAME}",
    )

    juju.wait(
        lambda status: are_agents_idle(
            status,
            DATA_INTEGRATOR_APP_NAME,
            MONGOS_APP_NAME,
            idle_period=20,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_only_one_config_server_relation(juju: jubilant.Juju) -> None:
    """Verify that a shard can only be related to one config server."""
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    with pytest.raises(jubilant.CLIError) as juju_error:
        juju.integrate(
            f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
            f"{CONFIG_SERVER_TWO_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        )

    assert (
        RELATION_LIMIT_MESSAGE in juju_error.value.stderr
    ), "Shard can relate to multiple config servers."

    # clean up relation
    juju.remove_relation(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )


def test_cannot_use_db_relation(juju: jubilant.Juju) -> None:
    """Verify that sharding components cannot use the DB relation."""
    for sharded_component in SHARDING_COMPONENTS:
        juju.integrate(f"{APPLICATION_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}", sharded_component)

    juju.wait(
        lambda status: (
            are_agents_idle(status, *SHARDING_COMPONENTS, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    app_name: [MongoDBStatuses.INVALID_DB_REL.value]
                    for app_name in SHARDING_COMPONENTS
                },
                expected_app_statuses={},
            )
        ),
        timeout=600,
    )

    # clean up relations
    for sharded_component in SHARDING_COMPONENTS:
        juju.remove_relation(
            f"{APPLICATION_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}",
            sharded_component,
        )

    juju.wait(
        lambda status: are_agents_idle(status, *SHARDING_COMPONENTS, idle_period=20),
        timeout=TIMEOUT,
    )


def test_replication_config_server_relation(juju: jubilant.Juju):
    """Verifies that using a replica as a shard fails."""
    # attempt to add a replication deployment as a shard to the config server.
    juju.integrate(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: (
            are_agents_idle(status, REPLICATION_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    REPLICATION_APP_NAME: [MongoDBStatuses.INVALID_SHARDING_REL.value]
                },
                expected_app_statuses={},
            )
        ),
        timeout=600,
    )

    # clean up relations
    juju.remove_relation(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: are_agents_idle(status, REPLICATION_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )


def test_replication_shard_relation(juju: jubilant.Juju):
    """Verifies that using a replica as a config-server fails."""
    # attempt to add a shard to a replication deployment as a config server.
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: (
            are_agents_idle(status, REPLICATION_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    REPLICATION_APP_NAME: [MongoDBStatuses.INVALID_SHARDING_REL.value]
                },
                expected_app_statuses={},
            )
        ),
        timeout=600,
    )

    # clean up relation
    juju.remove_relation(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: are_agents_idle(status, REPLICATION_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )


def test_replication_mongos_relation(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verifies connecting a replica to a mongos router fails."""
    # attempt to add a replication deployment as a shard to the config server.
    juju.integrate(
        f"{REPLICATION_APP_NAME}",
        f"{MONGOS_APP_NAME}",
    )

    juju.wait(
        lambda status: (
            are_agents_idle(status, REPLICATION_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    REPLICATION_APP_NAME: [MongoDBStatuses.INVALID_MONGOS_REL.value]
                },
                expected_app_statuses={},
            )
        ),
        timeout=600,
    )

    # clean up relations
    juju.remove_relation(
        f"{REPLICATION_APP_NAME}:cluster",
        f"{MONGOS_APP_NAME}:cluster",
    )

    # Ensure all gets cleaned up completely
    juju.wait(
        lambda status: are_agents_idle(
            status, MONGOS_APP_NAME, SHARD_ONE_APP_NAME, REPLICATION_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )


def test_shard_mongos_relation(juju: jubilant.Juju) -> None:
    """Verifies connecting a shard to a mongos router fails."""
    # attempt to add a replication deployment as a shard to the config server.
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}",
        f"{MONGOS_APP_NAME}",
    )

    juju.wait(
        lambda status: (
            are_agents_idle(status, SHARD_ONE_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    SHARD_ONE_APP_NAME: [MongoDBStatuses.INVALID_MONGOS_REL.value]
                },
                expected_app_statuses={},
            )
        ),
        timeout=600,
    )

    # clean up relations
    juju.remove_relation(
        f"{MONGOS_APP_NAME}:cluster",
        f"{SHARD_ONE_APP_NAME}:cluster",
    )

    juju.wait(
        lambda status: are_agents_idle(status, SHARD_ONE_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )


def test_shard_s3_relation(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verifies integrating a shard to s3-integrator fails."""
    # attempt to add a replication deployment as a shard to the config server.
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}",
        f"{S3_APP_NAME}",
    )

    juju.wait(
        lambda status: (
            are_agents_idle(status, SHARD_ONE_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={SHARD_ONE_APP_NAME: [MongoDBStatuses.INVALID_S3_REL.value]},
                expected_app_statuses={},
            )
        ),
        timeout=600,
    )

    # clean up relations
    juju.remove_relation(
        f"{S3_APP_NAME}:s3-credentials",
        f"{SHARD_ONE_APP_NAME}:s3-credentials",
    )

    juju.wait(
        lambda status: are_agents_idle(status, SHARD_ONE_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
def test_config_server_tls_replication_relation(juju: jubilant.Juju) -> None:
    """Verifies that using a replica as a shard fails even when TLS is integrated."""
    # attempt to add a shard to a replication deployment as a config server.
    integrate_apps_with_tls(juju, REPLICATION_APP_NAME)

    juju.integrate(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: (
            are_agents_idle(status, REPLICATION_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    REPLICATION_APP_NAME: [MongoDBStatuses.INVALID_SHARDING_REL.value]
                },
                expected_app_statuses={},
            )
        ),
        timeout=600,
    )

    # clean up relations
    remove_tls_integrations(juju, REPLICATION_APP_NAME)

    juju.remove_relation(
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
    )

    juju.wait(
        lambda status: are_agents_idle(status, REPLICATION_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )
