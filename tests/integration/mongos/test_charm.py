#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import jubilant

from single_kernel_mongo.config.statuses import ConfigServerStatuses, MongosStatuses, ShardStatuses
from tests.integration.helpers.constants import (
    CLUSTER_REL_NAME,
    CONFIG_SERVER_APP_NAME,
    CONFIG_SERVER_REL_NAME,
    MONGOS_APP_NAME,
    MONGOS_CLIENT_APPLICATION,
    MONGOS_PORT,
    MONGOS_SOCKET,
    SHARD_ONE_APP_NAME,
    SHARD_REL_NAME,
    TEST_DB_NAME,
    TEST_USER_NAME,
    TEST_USER_PWD,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    ensure_app_number_units,
    execute_on_mongod,
    find_leader,
    get_mongodb_hostname_for_unit,
    remove_number_units,
)
from tests.integration.helpers.jubilant_mongos import (
    deploy_cluster_components,
    generate_mongos_uri,
    is_mongos_running,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    mongos_client_application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    deploy_cluster_components(
        juju,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        mongos_client_application_path,
    )


def test_waits_for_config_server(juju: jubilant.Juju) -> None:
    """Verifies that the application and unit are active."""
    juju.integrate(MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME)

    # verify that Charmed Mongos is blocked and reports incorrect credentials
    juju.wait(
        lambda status: (
            are_agents_idle(
                status, MONGOS_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, idle_period=20
            )
            and does_status_match(
                status,
                expected_unit_statuses={
                    MONGOS_APP_NAME: [MongosStatuses.MISSING_CONF_SERVER_REL.value],
                    CONFIG_SERVER_APP_NAME: [ConfigServerStatuses.MISSING_CONF_SERVER_REL.value],
                    SHARD_ONE_APP_NAME: [ShardStatuses.MISSING_CONF_SERVER_REL.value],
                },
                expected_app_statuses={
                    CONFIG_SERVER_APP_NAME: [ConfigServerStatuses.MISSING_CONF_SERVER_REL.value],
                },
            )
        ),
        timeout=TIMEOUT,
    )


def test_mongos_starts_with_config_server(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Integrate the cluster and checks that mongos starts."""
    # prepare sharded cluster
    juju.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    # connect sharded cluster to mongos
    juju.integrate(
        f"{MONGOS_APP_NAME}:{CLUSTER_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CLUSTER_REL_NAME}",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    leader_name, _ = find_leader(juju, MONGOS_APP_NAME)
    uri = generate_mongos_uri(juju, substrate, MONGOS_APP_NAME, auth=False)
    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=leader_name,
        uri=uri,
    )
    assert mongos_running, "Mongos is not currently running."


def test_mongos_has_user(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that mongos has user by running a check with authentication."""
    leader_name, _ = find_leader(juju, MONGOS_APP_NAME)
    uri = generate_mongos_uri(juju, substrate, MONGOS_CLIENT_APPLICATION, auth=True)
    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=leader_name,
        uri=uri,
    )
    assert mongos_running, "Mongos is not currently running."


def test_mongos_updates_config_db(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Checks that mongos supports scale up and down of config server."""
    # completely change the hosts that mongos was connected to
    n_units = len(juju.status().get_units(CONFIG_SERVER_APP_NAME))

    ensure_app_number_units(
        juju, substrate, app_name=CONFIG_SERVER_APP_NAME, required_units=n_units + 1, wait=True
    )

    # destroy the unit we were initially connected to
    config_server_unit = next(iter(juju.status().get_units(CONFIG_SERVER_APP_NAME)))

    # Remove units by number.
    remove_number_units(
        juju, substrate, CONFIG_SERVER_APP_NAME, specific_units=[config_server_unit]
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            MONGOS_APP_NAME,
            unit_count={CONFIG_SERVER_APP_NAME: n_units, MONGOS_APP_NAME: 1},
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    leader_name, _ = find_leader(juju, MONGOS_APP_NAME)
    uri = generate_mongos_uri(juju, substrate, MONGOS_CLIENT_APPLICATION, auth=True)
    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=leader_name,
        uri=uri,
    )
    assert mongos_running, "Mongos is not currently running."


def test_user_with_extra_roles(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Check that we can create user with extra roles, and that it is accessible."""
    cmd = f"db.createUser({{user: '{TEST_USER_NAME}', pwd: '{TEST_USER_PWD}', roles: [{{'role': 'readWrite', 'db': '{TEST_DB_NAME}'}}]}})"
    uri = generate_mongos_uri(juju, substrate, MONGOS_CLIENT_APPLICATION, auth=True)
    res = execute_on_mongod(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        uri=uri,
        command=cmd,
        container_name="mongos",
    )
    assert (
        res.succeeded
    ), f"mongos user does not have correct permissions to create new user, error: {res.stderr}"

    leader_name, leader_status = find_leader(juju, MONGOS_APP_NAME)

    if substrate == Substrate.lxd:
        test_user_uri = f"mongodb://{TEST_USER_NAME}:{TEST_USER_PWD}@{MONGOS_SOCKET}/{TEST_DB_NAME}"
    else:
        hostname = get_mongodb_hostname_for_unit(juju, substrate, leader_name, leader_status)
        test_user_uri = (
            f"mongodb://{TEST_USER_NAME}:{TEST_USER_PWD}@{hostname}:{MONGOS_PORT}/{TEST_DB_NAME}"
        )

    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=leader_name,
        uri=test_user_uri,
    )
    assert mongos_running, "User created is not accessible."


def test_mongos_can_scale(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that mongos powers down when no config server is accessible."""
    app_name = MONGOS_CLIENT_APPLICATION if substrate == Substrate.lxd else MONGOS_APP_NAME

    n_units = len(juju.status().get_units(app_name))

    ensure_app_number_units(juju, substrate, app_name, required_units=n_units + 1, wait=False)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    for mongos_unit, mongos_unit_status in juju.status().get_units(MONGOS_APP_NAME).items():
        uri = generate_mongos_uri(
            juju,
            substrate,
            MONGOS_CLIENT_APPLICATION,
            auth=True,
            mongos_unit_status=mongos_unit_status,
        )
        mongos_running = is_mongos_running(juju, substrate, MONGOS_APP_NAME, mongos_unit, uri)
        assert mongos_running, "Mongos is not currently running."

    # destroy the unit we were initially connected to
    remove_number_units(juju, substrate, app_name, specific_units=[f"{app_name}/0"])

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    leader_name, _ = find_leader(juju, MONGOS_APP_NAME)
    uri = generate_mongos_uri(
        juju,
        substrate,
        MONGOS_CLIENT_APPLICATION,
        auth=True,
    )
    mongos_running = is_mongos_running(juju, substrate, MONGOS_APP_NAME, leader_name, uri)
    assert mongos_running, "Mongos is not currently running."
