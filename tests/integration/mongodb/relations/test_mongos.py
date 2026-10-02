#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest
from pymongo import MongoClient
from pymongo.errors import OperationFailure
from tenacity import Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.constants import (
    BASE,
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    DATA_INTEGRATOR_APP_NAME,
    MONGOS_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    find_leader,
    get_ip_from_unit,
    get_relation_username_password,
    mongos_uri,
)
from tests.integration.helpers.jubilant_sharding import build_mongos_client, count_users
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
) -> None:
    """Build and deploy a sharded cluster."""
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
        num_units=(1 if substrate == Substrate.k8s else 0),
    )
    juju.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        base=BASE,
        config={"extra-user-roles": "admin", "database-name": "test-database"},
    )


def test_connect_to_cluster_creates_user(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verifies that when the cluster is formed a new user is created."""
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
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
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)
    num_users = count_users(mongos_client)

    juju.integrate(
        f"{MONGOS_APP_NAME}",
        f"{CONFIG_SERVER_APP_NAME}",
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            MONGOS_APP_NAME,
            CONFIG_SERVER_APP_NAME,
            SHARD_ONE_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    num_users_after_integration = count_users(mongos_client)

    assert (
        num_users_after_integration > num_users
    ), "Cluster did not create new users after integration."

    (username, password) = get_relation_username_password(
        juju, app_name=MONGOS_APP_NAME, relation_name=CLUSTER_REL_NAME
    )
    _, leader_status = find_leader(juju, app_name=CONFIG_SERVER_APP_NAME)
    host = get_ip_from_unit(substrate=substrate, unit_info=leader_status)

    _mongos_uri = mongos_uri(username, password, ip_addresses=[host])
    mongos_user_client = MongoClient(_mongos_uri, directConnection=True)

    mongos_user_client.admin.command("dbStats")


def test_disconnect_from_cluster_removes_user(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verifies that when the cluster is formed a the user is removed."""
    # generate URI for new mongos user
    (username, password) = get_relation_username_password(
        juju, app_name=MONGOS_APP_NAME, relation_name=CLUSTER_REL_NAME
    )
    _, leader_status = find_leader(juju, app_name=CONFIG_SERVER_APP_NAME)
    host = get_ip_from_unit(substrate=substrate, unit_info=leader_status)

    _mongos_uri = mongos_uri(username, password, ip_addresses=[host])
    mongos_user_client = MongoClient(_mongos_uri, directConnection=True)

    # generate URI for operator mongos user (i.e. admin)
    mongos_client = build_mongos_client(juju, substrate, CONFIG_SERVER_APP_NAME)
    num_users = count_users(mongos_client)

    juju.remove_relation(
        f"{MONGOS_APP_NAME}:cluster",
        f"{CONFIG_SERVER_APP_NAME}:cluster",
    )
    juju.wait(
        lambda status: are_agents_idle(
            status, CONFIG_SERVER_APP_NAME, MONGOS_APP_NAME, idle_period=30
        ),
        timeout=TIMEOUT,
    )

    for attempt in Retrying(stop=stop_after_delay(300), wait=wait_fixed(10), reraise=True):
        with attempt:
            num_users_after_removal = count_users(mongos_client)
            assert (
                num_users > num_users_after_removal
            ), "Cluster did not remove user after integration removal."

    with pytest.raises(OperationFailure) as pymongo_error:
        mongos_user_client.admin.command("dbStats")

    assert pymongo_error.value.code == 18, "User still exists after relation was removed."
