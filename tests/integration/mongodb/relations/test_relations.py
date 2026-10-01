#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import time

import jubilant
import pytest
from tenacity import RetryError

from tests.integration.helpers.constants import (
    APPLICATION_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    FIRST_DATABASE_RELATION_NAME,
    MEDIAN_REELECTION_TIME,
    SECOND_DATABASE_RELATION_NAME,
    TIMEOUT,
)
from tests.integration.helpers.continuous_writes_helpers import replica_set_primary
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    execute_on_mongod,
    existing_app,
    get_application_relation_data,
    get_connection_string,
    get_mongodb_hostname_for_unit,
    get_relation_id_for,
)
from tests.integration.helpers.jubilant_relations import (
    assert_created_user_can_connect,
    verify_application_data,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

DATABASE_RELATION_NAME = "database"
ANOTHER_DATABASE_APP_NAME = "another-database"
ANOTHER_APPLICATION_NAME = "another-application"

USER_CREATED_FROM_APP1 = "test_user_1"
PW_CREATED_FROM_APP1 = "test_user_pass_1"

MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME = "multiple-database-clusters"
ALIASED_MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME = "aliased-multiple-database-clusters"


@pytest.mark.abort_on_fail
def test_deploy_charms(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
    client_relation_charm_path: str,
):
    """Deploy both charms (application and database) to use in the tests."""
    # Deploy both charms (2 units for each application to test that later they correctly
    # set data in the relation application databag using only the leader unit).
    required_units = 2
    app_name = existing_app(juju)
    if app_name == ANOTHER_DATABASE_APP_NAME:
        assert False, f"provided MongoDB application, cannot be named {ANOTHER_DATABASE_APP_NAME}, this name is reserved for this test."

    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units)
    else:
        app_name = base_app_name
        deploy_charm(
            juju=juju,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=app_name,
            num_units=required_units,
        )
    juju.deploy(
        charm=client_relation_charm_path, app=APPLICATION_APP_NAME, num_units=required_units
    )
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=ANOTHER_DATABASE_APP_NAME,
        num_units=1,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            APPLICATION_APP_NAME,
            ANOTHER_DATABASE_APP_NAME,
            idle_period=30,
            unit_count={
                app_name: 2,
                APPLICATION_APP_NAME: 2,
                ANOTHER_DATABASE_APP_NAME: 1,
            },
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_database_relation_with_charm_libraries(juju: jubilant.Juju):
    """Test basic functionality of database relation interface."""
    # Relate the charms and wait for them exchanging some connection data.
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name
    juju.integrate(f"{APPLICATION_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}", app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            APPLICATION_APP_NAME,
            ANOTHER_DATABASE_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    database = get_application_relation_data(
        juju, APPLICATION_APP_NAME, FIRST_DATABASE_RELATION_NAME, "database"
    )

    app_unit = next(iter(juju.status().get_units(APPLICATION_APP_NAME)))
    juju.run(app_unit, "write-releases", {"database": database})


def test_app_relation_metadata_change(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verifies that the app metadata changes with db relation joined and departed events."""
    # verify application metadata is correct before adding/removing units.
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    try:
        verify_application_data(
            juju, substrate, APPLICATION_APP_NAME, app_name, FIRST_DATABASE_RELATION_NAME
        )
    except RetryError:
        assert False, "Hosts are not correct in application data."

    # verify application metadata is correct after adding units.
    ensure_app_number_units(juju, substrate, app_name, required_units=4)

    try:
        verify_application_data(
            juju, substrate, APPLICATION_APP_NAME, app_name, FIRST_DATABASE_RELATION_NAME
        )
    except RetryError:
        assert False, "Hosts not updated in application data after adding units."

    # verify application metadata is correct after adding units.
    ensure_app_number_units(juju, substrate, app_name, required_units=2)

    try:
        verify_application_data(
            juju, substrate, APPLICATION_APP_NAME, app_name, FIRST_DATABASE_RELATION_NAME
        )
    except RetryError:
        assert False, "Hosts not updated in application data after removing units."

    # verify primary is present in hosts provided to application
    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)
    endpoints_str = get_application_relation_data(
        juju, APPLICATION_APP_NAME, FIRST_DATABASE_RELATION_NAME, "endpoints"
    )
    assert endpoints_str, "No endpoints provided in databag."

    databag_hosts = endpoints_str.split(",")

    try:
        primary_name, primary_status = replica_set_primary(juju, substrate, app_name=app_name)
    except RetryError:
        assert False, "replica set has no primary"

    mongodb_hostname = get_mongodb_hostname_for_unit(juju, substrate, primary_name, primary_status)
    assert mongodb_hostname in databag_hosts, "Primary is not present in DB endpoints."

    database = get_application_relation_data(
        juju, APPLICATION_APP_NAME, FIRST_DATABASE_RELATION_NAME, "database"
    )

    app_unit = next(iter(juju.status().get_units(APPLICATION_APP_NAME)))
    juju.run(app_unit, "write-releases", {"database": database})


def test_user_with_extra_roles(juju: jubilant.Juju, substrate: Substrate):
    """Test superuser actions (ie creating a new user and creating a new database)."""
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    database = get_application_relation_data(
        juju, APPLICATION_APP_NAME, FIRST_DATABASE_RELATION_NAME, "database"
    )

    app_unit = next(iter(juju.status().get_units(APPLICATION_APP_NAME)))
    juju.run(
        app_unit,
        "create-user",
        {
            "database": database,
            "username": USER_CREATED_FROM_APP1,
            "password": PW_CREATED_FROM_APP1,
        },
    )

    assert_created_user_can_connect(
        juju,
        substrate,
        app_name,
        username=USER_CREATED_FROM_APP1,
        password=PW_CREATED_FROM_APP1,
    )


def test_two_applications_doesnt_share_the_same_relation_data(
    juju: jubilant.Juju, client_relation_charm_path: str
):
    """Test that two different application connect to the database with different credentials."""
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    app_names = [
        app_name,
        APPLICATION_APP_NAME,
        ANOTHER_APPLICATION_NAME,
        ANOTHER_DATABASE_APP_NAME,
    ]
    # Set some variables to use in this test.

    # Deploy another application.
    juju.deploy(
        charm=client_relation_charm_path,
        app=ANOTHER_APPLICATION_NAME,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *app_names,
            idle_period=30,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    # Relate the new application with the database
    # and wait for them exchanging some connection data.
    juju.integrate(f"{ANOTHER_APPLICATION_NAME}:{FIRST_DATABASE_RELATION_NAME}", app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *app_names,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Assert the two application have different relation (connection) data.
    application_connection_string = get_connection_string(
        juju, APPLICATION_APP_NAME, FIRST_DATABASE_RELATION_NAME
    )

    another_application_connection_string = get_connection_string(
        juju, ANOTHER_APPLICATION_NAME, FIRST_DATABASE_RELATION_NAME
    )
    assert application_connection_string != another_application_connection_string


def test_an_application_can_connect_to_multiple_database_clusters(juju: jubilant.Juju):
    """Test that an application can connect to different clusters of the same database."""
    # Relate the application with both database clusters
    # and wait for them exchanging some connection data.
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    app_names = [app_name, APPLICATION_APP_NAME, ANOTHER_DATABASE_APP_NAME]

    juju.integrate(
        f"{APPLICATION_APP_NAME}:{MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME}",
        app_name,
    )
    juju.integrate(
        f"{APPLICATION_APP_NAME}:{MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME}",
        ANOTHER_DATABASE_APP_NAME,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *app_names,
            idle_period=30,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Gather relation ids
    first_cluster_relation_id = get_relation_id_for(
        juju,
        app_name,
        local_endpoint="database",
        remote_endpoint=MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME,
    )
    second_cluster_relation_id = get_relation_id_for(
        juju,
        ANOTHER_DATABASE_APP_NAME,
        local_endpoint="database",
        remote_endpoint=MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME,
    )

    # Retrieve the connection string to both database clusters using the relation aliases
    # and assert they are different.
    application_connection_string = get_connection_string(
        juju,
        APPLICATION_APP_NAME,
        MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME,
        relation_id=first_cluster_relation_id,
    )

    another_application_connection_string = get_connection_string(
        juju,
        APPLICATION_APP_NAME,
        MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME,
        relation_id=second_cluster_relation_id,
    )

    assert application_connection_string != another_application_connection_string


def test_an_application_can_connect_to_multiple_aliased_database_clusters(juju: jubilant.Juju):
    """Test that an application can connect to different clusters of the same database.

    Relate the application with both database clusters
    and wait for them exchanging some connection data.
    """
    db_app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert db_app_name

    app_names = [db_app_name, APPLICATION_APP_NAME, ANOTHER_DATABASE_APP_NAME]

    juju.integrate(
        f"{APPLICATION_APP_NAME}:{ALIASED_MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME}",
        db_app_name,
    )
    juju.integrate(
        f"{APPLICATION_APP_NAME}:{ALIASED_MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME}",
        ANOTHER_DATABASE_APP_NAME,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *app_names,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )
    # Retrieve the connection string to both database clusters using the relation aliases
    # and assert they are different.
    application_connection_string = get_connection_string(
        juju,
        APPLICATION_APP_NAME,
        ALIASED_MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME,
        relation_alias="cluster1",
    )

    another_application_connection_string = get_connection_string(
        juju,
        APPLICATION_APP_NAME,
        ALIASED_MULTIPLE_DATABASE_CLUSTERS_RELATION_NAME,
        relation_alias="cluster2",
    )

    assert application_connection_string != another_application_connection_string


def test_an_application_can_request_multiple_databases(juju: jubilant.Juju):
    """Test that an application can request additional databases using the same interface."""
    # Relate the charms using another relation and wait for them exchanging some connection data.
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    app_names = [app_name, APPLICATION_APP_NAME, ANOTHER_DATABASE_APP_NAME]

    juju.integrate(f"{APPLICATION_APP_NAME}:{SECOND_DATABASE_RELATION_NAME}", app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *app_names,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    # Get the connection strings to connect to both databases.
    first_database_connection_string = get_connection_string(
        juju, APPLICATION_APP_NAME, FIRST_DATABASE_RELATION_NAME
    )
    second_database_connection_string = get_connection_string(
        juju, APPLICATION_APP_NAME, SECOND_DATABASE_RELATION_NAME
    )

    # Assert the two application have different relation (connection) data.
    assert first_database_connection_string != second_database_connection_string


def test_removed_relation_no_longer_has_access(juju: jubilant.Juju, substrate: Substrate):
    """Verify removed applications no longer have access to the database."""
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    app_names = [app_name, APPLICATION_APP_NAME, ANOTHER_DATABASE_APP_NAME]

    # before removing relation we need its authorisation via connection string
    connection_string = get_connection_string(
        juju, APPLICATION_APP_NAME, FIRST_DATABASE_RELATION_NAME
    )

    juju.remove_relation(
        f"{APPLICATION_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}",
        f"{app_name}:database",
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *app_names,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        connection_string,
        "rs.status()",
        expecting_output=False,
    )

    assert (
        result.failed
    ), f"application: {APPLICATION_APP_NAME} still has access to mongodb after relation removal."

    # mongodb should not clean up users it does not manage.
    assert_created_user_can_connect(
        juju,
        substrate,
        app_name,
        username=USER_CREATED_FROM_APP1,
        password=PW_CREATED_FROM_APP1,
    )
