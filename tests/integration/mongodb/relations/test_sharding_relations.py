#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from juju.errors import JujuAPIError
from pytest_operator.plugin import OpsTest

from ...helpers.backups import S3_APP_NAME
from ...helpers.common import (
    DATA_INTEGRATOR_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    MONGOS_APP_NAME,
    TIMEOUT,
    check_status_detail,
    deploy_application,
    deploy_charm,
    wait_for_mongodb_units_blocked,
)
from ...helpers.relations import (
    APPLICATION_APP_NAME,
    FIRST_DATABASE_RELATION_NAME,
    REPLICATION_APP_NAME,
)
from ...helpers.sharding import (
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    CONFIG_SERVER_TWO_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    integrate_with_tls,
    remove_tls_integrations,
)
from ...helpers.tls import TLS_CERTIFICATES_APP_NAME
from ...helpers.types import Substrate

SHARDING_COMPONENTS = [SHARD_ONE_APP_NAME, CONFIG_SERVER_APP_NAME]

RELATION_LIMIT_MESSAGE = 'cannot add relation "shard-one:sharding config-server-two:config-server": establishing a new relation for shard-one:sharding would exceed its maximum relation limit of 1'


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    mongos_charm: str,
    substrate: Substrate,
    mongod_resource,
    mongos_resource,
    client_relation_charm_path: str,
) -> None:
    """Build and deploy 2 config servers, one shard and one mongos."""
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
        config={"role": "config-server"},
    )
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=CONFIG_SERVER_TWO_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
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
        num_units=(1 if substrate == "microk8s" else 0),
    )
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel="latest/stable", base="ubuntu@22.04"
    )
    await ops_test.model.deploy(S3_APP_NAME, channel="edge")

    await ops_test.model.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        series="noble",
        config={"extra-user-roles": "admin"},
    )

    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=REPLICATION_APP_NAME,
        mongod_resource=mongod_resource,
        num_units=1,
    )
    await deploy_application(ops_test, client_relation_charm_path, APPLICATION_APP_NAME)

    await ops_test.model.wait_for_idle(
        apps=[
            CONFIG_SERVER_APP_NAME,
            CONFIG_SERVER_TWO_APP_NAME,
            SHARD_ONE_APP_NAME,
            TLS_CERTIFICATES_APP_NAME,
        ],
        idle_period=20,
        raise_on_blocked=False,
        timeout=DEPLOYMENT_TIMEOUT,
    )

    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}",
        f"{DATA_INTEGRATOR_APP_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[DATA_INTEGRATOR_APP_NAME, MONGOS_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
        raise_on_error=False,
    )


@pytest.mark.abort_on_fail
async def test_only_one_config_server_relation(ops_test: OpsTest) -> None:
    """Verify that a shard can only be related to one config server."""
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    with pytest.raises(JujuAPIError) as juju_error:
        await ops_test.model.integrate(
            f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
            f"{CONFIG_SERVER_TWO_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        )

    assert (
        juju_error.value.args[0] == RELATION_LIMIT_MESSAGE
    ), "Shard can relate to multiple config servers."

    # clean up relation
    await ops_test.model.applications[SHARD_ONE_APP_NAME].remove_relation(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_cannot_use_db_relation(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify that sharding components cannot use the DB relation."""
    for sharded_component in SHARDING_COMPONENTS:
        await ops_test.model.integrate(
            f"{APPLICATION_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}", sharded_component
        )

    for sharded_component in SHARDING_COMPONENTS:
        await wait_for_mongodb_units_blocked(
            ops_test,
            substrate,
            sharded_component,
            status="The database relation cannot be used by sharding components (shards or config servers).",
            timeout=300,
        )

    # clean up relations
    for sharded_component in SHARDING_COMPONENTS:
        await ops_test.model.applications[sharded_component].remove_relation(
            f"{APPLICATION_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}",
            sharded_component,
        )

    await ops_test.model.wait_for_idle(
        apps=SHARDING_COMPONENTS,
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_replication_config_server_relation(ops_test: OpsTest, substrate: Substrate):
    """Verifies that using a replica as a shard fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        REPLICATION_APP_NAME,
        status="The sharding interface cannot be used by replica sets.",
        timeout=300,
    )

    # clean up relations
    await ops_test.model.applications[REPLICATION_APP_NAME].remove_relation(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )


@pytest.mark.abort_on_fail
async def test_replication_shard_relation(ops_test: OpsTest, substrate: Substrate):
    """Verifies that using a replica as a config-server fails."""
    # attempt to add a shard to a replication deployment as a config server.
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        REPLICATION_APP_NAME,
        status="The sharding interface cannot be used by replica sets.",
        timeout=300,
    )

    # clean up relation
    await ops_test.model.applications[REPLICATION_APP_NAME].remove_relation(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_replication_mongos_relation(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verifies connecting a replica to a mongos router fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{REPLICATION_APP_NAME}",
        f"{MONGOS_APP_NAME}",
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        REPLICATION_APP_NAME,
        status="The cluster relation can only be used by config servers.",
        timeout=300,
    )

    # clean up relations
    await ops_test.model.applications[REPLICATION_APP_NAME].remove_relation(
        f"{REPLICATION_APP_NAME}:cluster",
        f"{MONGOS_APP_NAME}:cluster",
    )

    await ops_test.model.wait_for_idle(
        apps=[SHARD_ONE_APP_NAME, SHARD_ONE_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_shard_mongos_relation(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verifies connecting a shard to a mongos router fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}",
        f"{MONGOS_APP_NAME}",
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        SHARD_ONE_APP_NAME,
        status="Invalid cluster relation.",
        timeout=300,
    )
    await check_status_detail(
        ops_test,
        SHARD_ONE_APP_NAME,
        status="blocked",
        message="The cluster relation can only be used by config servers.",
    )

    # clean up relations
    await ops_test.model.applications[SHARD_ONE_APP_NAME].remove_relation(
        f"{MONGOS_APP_NAME}:cluster",
        f"{SHARD_ONE_APP_NAME}:cluster",
    )


@pytest.mark.abort_on_fail
async def test_shard_s3_relation(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verifies integrating a shard to s3-integrator fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}",
        f"{S3_APP_NAME}",
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        SHARD_ONE_APP_NAME,
        status="Invalid s3-credentials relation.",
        timeout=300,
    )
    await check_status_detail(
        ops_test,
        SHARD_ONE_APP_NAME,
        status="blocked",
        message="The s3-credentials relation can only be used by config servers or replica sets.",
    )

    # clean up relations
    await ops_test.model.applications[SHARD_ONE_APP_NAME].remove_relation(
        f"{S3_APP_NAME}:s3-credentials",
        f"{SHARD_ONE_APP_NAME}:s3-credentials",
    )


@pytest.mark.abort_on_fail
async def test_config_server_tls_replication_relation(
    ops_test: OpsTest, substrate: Substrate
) -> None:
    """Verifies that using a replica as a shard fails even when TLS is integrated."""
    # attempt to add a shard to a replication deployment as a config server.
    await integrate_with_tls(ops_test, [REPLICATION_APP_NAME])

    await ops_test.model.integrate(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        REPLICATION_APP_NAME,
        status="The sharding interface cannot be used by replica sets.",
        timeout=300,
    )

    # clean up relations
    await remove_tls_integrations(ops_test, [REPLICATION_APP_NAME])

    await ops_test.model.applications[REPLICATION_APP_NAME].remove_relation(
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )
