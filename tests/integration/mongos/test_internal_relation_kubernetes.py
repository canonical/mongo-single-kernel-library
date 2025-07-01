#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    MONGOS_APP_NAME,
    MONGOS_PORT,
    execute_on_mongod,
    get_address_of_unit,
    get_connection_string,
    get_mongodb_hostname_for_unit,
    get_relation_username_password,
    is_relation_joined,
)
from ..helpers.mongos import (
    CLIENT_RELATION,
    MONGOS_CLIENT_APPLICATION,
    MONGOS_RELATION,
    TEST_DB_NAME,
    TEST_USER_NAME,
    TEST_USER_PWD,
    build_cluster,
    check_mongos,
    deploy_cluster_components,
    generate_mongos_uri,
    get_mongos_user_password,
)
from ..helpers.types import Substrate


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_build_and_deploy(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict,
    mongos_resource: dict,
    mongos_client_application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        mongos_client_application_path,
    )
    await build_cluster(
        ops_test, substrate, integrate_with_mongos=True, integrate_with_client=False
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_integrate_with_internal_client(ops_test: OpsTest):
    """Tests that when a client is integrated with mongos, it receives the connection info."""
    await ops_test.model.integrate(
        f"{MONGOS_CLIENT_APPLICATION}:{CLIENT_RELATION}", f"{MONGOS_APP_NAME}:{MONGOS_RELATION}"
    )
    await ops_test.model.wait_for_idle(
        apps=[MONGOS_CLIENT_APPLICATION, MONGOS_APP_NAME], status="active", idle_period=20
    )
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, MONGOS_RELATION, CLIENT_RELATION) is True, timeout=600
    )

    connection_string = await get_connection_string(
        ops_test, MONGOS_CLIENT_APPLICATION, CLIENT_RELATION
    )
    username, password = await get_relation_username_password(
        ops_test, MONGOS_CLIENT_APPLICATION, relation_name=CLIENT_RELATION
    )
    assert connection_string, "Connection string not provided to client."
    assert username, "Username not provided to client."
    assert password, "Username not provided to client."


@pytest.mark.abort_on_fail
async def test_user_can_connect(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that the user created by mongos can connect with auth."""
    username, password = await get_mongos_user_password(
        ops_test, app_name=MONGOS_CLIENT_APPLICATION, relation_name=CLIENT_RELATION
    )
    assert username, "Username not provided to client"
    assert password, "Password not provided to client"

    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]
    assert await check_mongos(
        ops_test, substrate, mongos_unit, app_name=MONGOS_CLIENT_APPLICATION, auth=True
    ), "Mongos is not running."

    mongos_host = await get_address_of_unit(
        ops_test, substrate, app_name=MONGOS_APP_NAME, unit_id=0
    )
    client_user_uri = f"mongodb://{username}:{password}@{mongos_host}:{MONGOS_PORT}"
    mongos_can_connect_with_auth = await check_mongos(
        ops_test, substrate, mongos_unit, auth=True, app_name=MONGOS_APP_NAME, uri=client_user_uri
    )
    assert mongos_can_connect_with_auth, "User created cannot connect with auth."


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_user_with_extra_roles(ops_test: OpsTest, substrate: Substrate) -> None:
    """Check that we can create user with extra roles, and that it is accessible."""
    cmd = f"db.createUser({{user: '{TEST_USER_NAME}', pwd: '{TEST_USER_PWD}', roles: [{{'role': 'readWrite', 'db': '{TEST_DB_NAME}'}}]}})"
    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]

    uri = await generate_mongos_uri(
        ops_test, substrate, auth=True, app_name=MONGOS_CLIENT_APPLICATION
    )
    res = await execute_on_mongod(
        ops_test, MONGOS_APP_NAME, substrate, uri, cmd, container_name="mongos"
    )
    assert (
        res.succeeded
    ), f"mongos user does not have correct permissions to create new user, error: {res.stderr}"

    hostname = await get_mongodb_hostname_for_unit(ops_test, substrate, mongos_unit.name)
    test_user_uri = (
        f"mongodb://{TEST_USER_NAME}:{TEST_USER_PWD}@{hostname}:{MONGOS_PORT}/{TEST_DB_NAME}"
    )
    mongos_running = await check_mongos(
        ops_test,
        substrate,
        mongos_unit,
        app_name=MONGOS_APP_NAME,
        auth=True,
        uri=test_user_uri,
    )
    assert mongos_running, "User created is not accessible."


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")
async def test_removed_relation_no_longer_has_access(ops_test: OpsTest, substrate: Substrate):
    """Verify removed applications no longer have access to the database."""
    # before removing relation we need its authorisation via connection string
    mongos_unit = ops_test.model.applications[MONGOS_APP_NAME].units[0]

    uri = await generate_mongos_uri(
        ops_test, substrate, auth=True, app_name=MONGOS_CLIENT_APPLICATION
    )

    await ops_test.model.applications[MONGOS_APP_NAME].remove_relation(
        f"{MONGOS_CLIENT_APPLICATION}:{CLIENT_RELATION}", f"{MONGOS_APP_NAME}"
    )
    await ops_test.model.wait_for_idle(apps=[MONGOS_APP_NAME], status="active", idle_period=20)

    mongos_can_connect_with_auth = await check_mongos(
        ops_test,
        substrate,
        unit=mongos_unit,
        app_name=MONGOS_APP_NAME,
        auth=True,
        uri=uri,
    )

    assert not mongos_can_connect_with_auth, "Client can still connect after relation broken."
