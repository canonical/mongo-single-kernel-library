#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CLIENT_RELATION,
    MONGOS_APP_NAME,
    MONGOS_CLIENT_APPLICATION,
    MONGOS_PORT,
    MONGOS_RELATION,
    TEST_DB_NAME,
    TEST_USER_NAME,
    TEST_USER_PWD,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_common import (
    execute_on_mongod,
    find_leader,
    get_connection_string,
    get_ip_from_unit,
    get_mongodb_hostname_for_unit,
    get_relation_username_password,
)
from tests.integration.helpers.jubilant_mongos import (
    build_cluster,
    deploy_cluster_components,
    generate_mongos_uri,
    is_mongos_running,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate


@pytest.mark.skip_if_substrate(Substrate.lxd)
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
    build_cluster(juju, substrate, integrate_with_mongos=True, integrate_with_client=False)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_integrate_with_internal_client(juju: jubilant.Juju):
    """Tests that when a client is integrated with mongos, it receives the connection info."""
    juju.integrate(
        f"{MONGOS_CLIENT_APPLICATION}:{CLIENT_RELATION}", f"{MONGOS_APP_NAME}:{MONGOS_RELATION}"
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    connection_string = get_connection_string(juju, MONGOS_CLIENT_APPLICATION, CLIENT_RELATION)
    username, password = get_relation_username_password(
        juju, MONGOS_CLIENT_APPLICATION, relation_name=CLIENT_RELATION
    )
    assert connection_string, "Connection string not provided to client."
    assert username, "Username not provided to client."
    assert password, "Username not provided to client."


def test_user_can_connect(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that the user created by mongos can connect with auth."""
    username, password = get_relation_username_password(
        juju, app_name=MONGOS_CLIENT_APPLICATION, relation_name=CLIENT_RELATION
    )
    assert username, "Username not provided to client"
    assert password, "Password not provided to client"

    leader_name, _ = find_leader(juju, MONGOS_APP_NAME)
    uri = generate_mongos_uri(juju, substrate, MONGOS_APP_NAME, auth=True)
    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_CLIENT_APPLICATION,
        unit_name=leader_name,
        uri=uri,
    )
    assert mongos_running, "Mongos is not running."

    mongos_unit, unit_status = next(iter(juju.status().get_units(MONGOS_APP_NAME).items()))

    mongos_host = get_ip_from_unit(substrate, unit_status)
    client_user_uri = f"mongodb://{username}:{password}@{mongos_host}:{MONGOS_PORT}"
    mongos_can_connect_with_auth = is_mongos_running(
        juju, substrate, app_name=MONGOS_APP_NAME, unit_name=mongos_unit, uri=client_user_uri
    )
    assert mongos_can_connect_with_auth, "User created cannot connect with auth."


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_user_with_extra_roles(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Check that we can create user with extra roles, and that it is accessible."""
    cmd = f"db.createUser({{user: '{TEST_USER_NAME}', pwd: '{TEST_USER_PWD}', roles: [{{'role': 'readWrite', 'db': '{TEST_DB_NAME}'}}]}})"
    mongos_unit, unit_status = next(iter(juju.status().get_units(MONGOS_APP_NAME).items()))

    uri = generate_mongos_uri(juju, substrate, auth=True, app_name=MONGOS_CLIENT_APPLICATION)
    res = execute_on_mongod(
        juju, substrate, MONGOS_APP_NAME, uri=uri, command=cmd, container_name="mongos"
    )
    assert (
        res.succeeded
    ), f"mongos user does not have correct permissions to create new user, error: {res.stderr}"

    hostname = get_mongodb_hostname_for_unit(juju, substrate, mongos_unit, unit_status)
    test_user_uri = (
        f"mongodb://{TEST_USER_NAME}:{TEST_USER_PWD}@{hostname}:{MONGOS_PORT}/{TEST_DB_NAME}"
    )
    mongos_running = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=mongos_unit,
        uri=test_user_uri,
    )
    assert mongos_running, "User created is not accessible."


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_removed_relation_no_longer_has_access(juju: jubilant.Juju, substrate: Substrate):
    """Verify removed applications no longer have access to the database."""
    # before removing relation we need its authorisation via connection string
    mongos_unit, unit_status = next(iter(juju.status().get_units(MONGOS_APP_NAME).items()))

    uri = generate_mongos_uri(juju, substrate, auth=True, app_name=MONGOS_CLIENT_APPLICATION)

    juju.remove_relation(f"{MONGOS_CLIENT_APPLICATION}:{CLIENT_RELATION}", f"{MONGOS_APP_NAME}")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGOS_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )

    mongos_can_connect_with_auth = is_mongos_running(
        juju,
        substrate,
        app_name=MONGOS_APP_NAME,
        unit_name=mongos_unit,
        uri=uri,
    )

    assert not mongos_can_connect_with_auth, "Client can still connect after relation broken."
