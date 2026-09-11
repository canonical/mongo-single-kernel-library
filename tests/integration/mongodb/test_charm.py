#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import logging
import pathlib
import time

import jubilant
import pytest
import tomllib
from bson.json_util import loads as bson_loads
from pymongo import MongoClient
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
from tenacity import RetryError

from single_kernel_mongo.config.statuses import PasswordManagementStatuses
from tests.integration.helpers.common import (
    audit_log_line_sanity_check,
    generate_collection_id,
    get_unit_id,
)
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    CHARMED_STATS_USERNAME,
    CONTINUOUS_WRITE_APPLICATION,
    DEFAULT_COLLECTION_NAME,
    DEFAULT_DATABASE_NAME,
    DEPLOYMENT_TIMEOUT,
    INTERNAL_USER_PASSWORD_CONFIG,
    MONGOD_PORT,
    TEST_DOCUMENTS,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import (
    clear_continuous_writes,
    start_continuous_writes,
    stop_continuous_writes,
)
from tests.integration.helpers.jubilant_common import (
    check_if_test_documents_stored,
    count_primaries,
    deploy_application,
    deploy_charm,
    ensure_app_number_units,
    execute_on_mongod,
    existing_app,
    find_leader,
    get_ip_from_unit,
    get_password,
    relate_application,
    remove_number_units,
    replica_set_uri,
    run_command_on_server,
    secondary_mongo_uris_with_sync_delay,
    set_password,
    unit_has_file,
    unit_uri,
)
from tests.integration.helpers.status_helpers import (
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)

STATS_PASSWORD = "my-new-secret-password"
OPERATOR_PASSWORD = "SOMETHING"


@pytest.mark.abort_on_fail
@pytest.mark.juju_setup
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
) -> None:
    """Build the charm-under-test and deploy it with three units."""
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=len(UNIT_IDS))
        return

    app_name = base_app_name
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=app_name,
        num_units=len(UNIT_IDS),
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_consistency_between_workload_and_metadata(
    juju: jubilant.Juju, substrate: Substrate, mongod_base_path: str
):
    app_name = existing_app(juju)
    assert app_name

    _, leader_unit_info = find_leader(juju=juju, app_name=app_name)

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)

    ip_address = get_ip_from_unit(substrate=substrate, unit_info=leader_unit_info)

    client = MongoClient(
        unit_uri(
            username=CHARMED_OPERATOR_USERNAME,
            ip_address=ip_address,
            password=password,
            replica_set=app_name,
        ),
        directConnection=True,
    )

    mongod_version = client.server_info()["version"].split("-")[0]

    versions_file = pathlib.Path(mongod_base_path, "refresh_versions.toml").read_text().strip()
    local_version = tomllib.loads(versions_file)["workload"]

    assert (
        mongod_version == local_version
    ), f"Version of mongod running is invalid ({mongod_version}), should be {local_version}"


@pytest.mark.abort_on_fail
def test_status_is_active(juju: jubilant.Juju) -> None:
    """Verifies that the application and unit are active."""
    app_name = existing_app(juju)
    assert app_name
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=600,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_tmp_permissions(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verifies that every unit's temporary directory has the expected permissions."""
    app_name = existing_app(juju)
    assert app_name

    for unit_name in juju.status().get_units(app_name):
        permissions = run_command_on_server(
            juju, substrate=substrate, unit_name=unit_name, command="stat -c %a /tmp"
        )

        assert permissions.strip() == "1777", f"invalid /tmp permissions on {unit_name}"


@pytest.mark.abort_on_fail
def test_unit_is_running_as_replica_set(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that mongodb is running as a replica set for the application unit."""
    # connect to mongo replica set
    app_name = existing_app(juju)
    assert app_name
    for unit_info in juju.status().get_units(app_name).values():
        address = get_ip_from_unit(substrate, unit_info)
        connection = address + ":" + str(MONGOD_PORT)
        client = MongoClient(connection, replicaset=app_name, directConnection=True)
        # check mongo replica set is ready
        try:
            client.server_info()
        except ServerSelectionTimeoutError:
            assert False, "server is not ready"

        # close connection
        client.close()


@pytest.mark.abort_on_fail
def test_pbm_agent_log_file_exists(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Checks that all units have a PBM log file."""
    app_name = existing_app(juju)
    assert app_name

    if substrate == "lxd":
        dir_path = "/var/snap/charmed-mongodb/common/var/log/pbm/"
    else:
        dir_path = "/var/log/pbm/"

    for unit_name in juju.status().get_units(app_name):
        assert unit_has_file(
            juju,
            substrate=substrate,
            unit_name=unit_name,
            dir_path=dir_path,
            filename="pbm-agent.json",
        )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("microk8s")
def test_check_max_tasks(juju: jubilant.Juju, substrate: Substrate):
    app_name = existing_app(juju)
    assert app_name
    for unit_name in juju.status().get_units(app_name):
        output = run_command_on_server(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            command="systemctl show --property TasksMax snap.charmed-mongodb.mongod",
        )
        assert "infinity" in output, f"Unit {unit_name} has an invalid TasksMax value"


@pytest.mark.abort_on_fail
def test_exactly_one_primary(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that there is exactly one primary in the deployed units."""
    app_name = existing_app(juju)
    assert app_name

    try:
        number_of_primaries = count_primaries(juju, substrate, app_name=app_name)
    except RetryError:
        number_of_primaries = 0

    # check that exactly of the units is the leader
    assert (
        number_of_primaries == 1
    ), f"Expected one unit to be a primary: {number_of_primaries} != 1"


@pytest.mark.abort_on_fail
def test_get_primary_action(juju: jubilant.Juju, substrate: Substrate):
    """Tests that action get-primary outputs the correct unit with the primary replica."""
    app_name = existing_app(juju)
    assert app_name

    units = juju.status().get_units(app_name)

    expected_primary = None
    for unit_name, unit_info in units.items():
        ip_address = get_ip_from_unit(substrate, unit_info)
        # connect to mongod
        password = get_password(juju, app_name, CHARMED_OPERATOR_USERNAME)

        client = MongoClient(
            unit_uri(
                username=CHARMED_OPERATOR_USERNAME,
                password=password,
                ip_address=ip_address,
                replica_set=app_name,
            ),
            directConnection=True,
        )

        # check primary status
        if client.is_primary:
            expected_primary = unit_name
            break

    # verify that there is a primary
    assert expected_primary

    # check if get-primary returns the correct primary unit regardless of
    # which unit the action is run on
    for unit_name in units.keys():
        # use get-primary action to find primary
        action = juju.run(unit_name, "get-primary")
        identified_primary = action.results["replica-set-primary"]

        # assert get-primary returned the right primary
        assert identified_primary == expected_primary


@pytest.mark.abort_on_fail
def test_update_operator_password(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that update config sets the new password in app data and mongod."""
    app_name = existing_app(juju)
    assert app_name

    set_password(
        juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME, password=OPERATOR_PASSWORD
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    new_password_reported = get_password(
        juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME
    )

    assert OPERATOR_PASSWORD == new_password_reported

    _, unit_info = find_leader(juju, app_name=app_name)
    ip_address = get_ip_from_unit(substrate, unit_info=unit_info)

    # verify that the password is updated in mongod by inserting into the collection.
    try:
        client = MongoClient(
            unit_uri(
                username=CHARMED_OPERATOR_USERNAME,
                password=OPERATOR_PASSWORD,
                ip_address=ip_address,
                replica_set=app_name,
            ),
            directConnection=True,
        )
        client[DEFAULT_DATABASE_NAME].list_collection_names()
    except PyMongoError as e:
        assert False, f"Failed to access collection with new password, error: {e}"
    finally:
        client.close()


@pytest.mark.abort_on_fail
def test_not_granted_secret_for_password_update(juju: jubilant.Juju) -> None:
    """Test password update for a secret not granted to the application."""
    app_name = existing_app(juju)
    assert app_name

    new_password = "NEW-PASSWORD"
    secret_name = "test-secret"

    current_password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)

    secret_id = juju.add_secret(name=secret_name, content={CHARMED_OPERATOR_USERNAME: new_password})

    juju.config(app_name, {INTERNAL_USER_PASSWORD_CONFIG: secret_id})

    juju.wait(
        lambda status: does_status_match(
            status,
            expected_unit_statuses=None,
            expected_app_statuses={app_name: [PasswordManagementStatuses.SECRET_NOT_GRANTED.value]},
        ),
        timeout=TIMEOUT,
    )

    reported_password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)
    # The password remained unchanged
    assert current_password == reported_password

    juju.grant_secret(identifier=secret_id, app=app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    reported_password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)
    assert new_password == reported_password


@pytest.mark.abort_on_fail
def test_update_password_for_charmed_stats_user(juju: jubilant.Juju) -> None:
    """Test password is updated for the charmed-stats user."""
    app_name = existing_app(juju)
    assert app_name

    new_password = STATS_PASSWORD
    set_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME, password=new_password)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    reported_password = get_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME)
    assert reported_password == new_password


@pytest.mark.abort_on_fail
def test_charmed_stats_user(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Test verifies that the charmed stats user can perform operations such as 'rs.conf()'."""
    app_name = existing_app(juju)
    assert app_name

    password = STATS_PASSWORD
    replica_set_hosts = [
        get_ip_from_unit(substrate, unit_info=unit_info)
        for unit_info in juju.status().get_units(app_name).values()
    ]

    rs_uri = replica_set_uri(
        username=CHARMED_STATS_USERNAME,
        password=password,
        ip_addresses=replica_set_hosts,
        replica_set=app_name,
    )

    admin_mongod_cmd = "rs.conf()"

    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri=rs_uri,
        command=admin_mongod_cmd,
        expecting_output=False,
    )
    assert result.succeeded, f"Failed to get conf with {CHARMED_STATS_USERNAME} user."


@pytest.mark.abort_on_fail
def test_empty_password(juju: jubilant.Juju) -> None:
    """Test that the password can't be set to an empty string."""
    app_name = existing_app(juju)
    assert app_name

    current_password = get_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME)
    set_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME, password=" ")
    juju.wait(
        lambda status: does_status_match(
            status,
            expected_unit_statuses=None,
            expected_app_statuses={
                app_name: [PasswordManagementStatuses.INVALID_SYSTEM_USERS.value]
            },
        ),
        timeout=TIMEOUT,
    )

    reported_password = get_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME)
    # The password remained unchanged
    assert current_password == reported_password

    # Restore valid password
    set_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME, password=STATS_PASSWORD)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_no_password_change_on_invalid_password(juju: jubilant.Juju) -> None:
    """Test that in general, there is no change when password validation fails."""
    app_name = existing_app(juju)
    assert app_name

    current_password = get_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME)
    set_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME, password="c" * 4097)

    juju.wait(
        lambda status: does_status_match(
            status,
            expected_unit_statuses=None,
            expected_app_statuses={
                app_name: [PasswordManagementStatuses.INVALID_SYSTEM_USERS.value]
            },
        ),
        timeout=TIMEOUT,
    )

    reported_password = get_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME)
    # The password remained unchanged
    assert current_password == reported_password

    # Restore valid password
    set_password(juju, app_name=app_name, username=CHARMED_STATS_USERNAME, password=STATS_PASSWORD)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_audit_log(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Test that audit log was created and contains actual audit data."""
    app_name = existing_app(juju)
    assert app_name

    match substrate:
        case "lxd":
            audit_log_path = "/var/snap/charmed-mongodb/common/var/log/mongodb/audit.log"
        case "microk8s":
            audit_log_path = "/var/log/mongodb/audit.log"

    audit_log = run_command_on_server(
        juju, substrate, f"{app_name}/leader", f"cat {audit_log_path}"
    )

    for line in audit_log.splitlines():
        if not len(line):
            continue
        item = json.loads(line)
        # basic sanity check
        assert audit_log_line_sanity_check(item), "Audit sanity log check failed for first line"


@pytest.mark.abort_on_fail
def test_log_rotate(juju: jubilant.Juju, substrate: Substrate, application_path: str) -> None:
    """Test that log are being rotated."""
    app_name = existing_app(juju)
    assert app_name

    deploy_application(juju, application_path, app_name=CONTINUOUS_WRITE_APPLICATION)
    relate_application(
        juju, mongodb_application_name=app_name, client_app_name=CONTINUOUS_WRITE_APPLICATION
    )

    time_to_write_200m_of_data = 60 * 25
    logrotate_timeout = 61

    match substrate:
        case "lxd":
            audit_log_path = "/var/snap/charmed-mongodb/common/var/log/mongodb/"
        case "microk8s":
            audit_log_path = "/var/log/mongodb/"

    assert not unit_has_file(
        juju, substrate, f"{app_name}/leader", audit_log_path, "audit.log.1"
    ), "Found rotated log in log files"

    # We want to speed up the test because it requires a lot of writing to
    # ensure a log rotation so we write on 10 concurrent jobs.
    for i in range(10):
        start_continuous_writes(
            juju,
            client_app_name=CONTINUOUS_WRITE_APPLICATION,
            coll_name=f"{DEFAULT_COLLECTION_NAME}_{i}",
        )
    time.sleep(time_to_write_200m_of_data)
    for i in range(10):
        stop_continuous_writes(
            juju,
            client_app_name=CONTINUOUS_WRITE_APPLICATION,
            coll_name=f"{DEFAULT_COLLECTION_NAME}_{i}",
        )

    time.sleep(logrotate_timeout)  # Just to make sure that logrotate will run
    for i in range(10):
        clear_continuous_writes(
            juju,
            client_app_name=CONTINUOUS_WRITE_APPLICATION,
            coll_name=f"{DEFAULT_COLLECTION_NAME}_{i}",
        )

    assert unit_has_file(
        juju, substrate, f"{app_name}/leader", audit_log_path, "audit.log.1"
    ), "Could not find audit.log.1 in log files"
    assert unit_has_file(
        juju, substrate, f"{app_name}/leader", audit_log_path, "audit.log"
    ), "Could not find audit.log in log files"


@pytest.mark.abort_on_fail
def test_scale_up(juju: jubilant.Juju, substrate: Substrate):
    """Tests juju add-unit functionality.

    Verifies that when a new unit is added to the MongoDB application that it is added to the
    MongoDB replica set configuration.
    """
    assert juju.model
    app_name = existing_app(juju)
    assert app_name

    n_units = len(juju.status().get_units(app_name))

    # add two units and wait for idle
    juju.add_unit(app_name, num_units=2)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=n_units + 2
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )
    num_units = len(juju.status().get_units(app_name))
    assert num_units == n_units + 2

    match substrate:
        case "lxd":
            hosts = [
                get_ip_from_unit(substrate, unit_info)
                for unit_info in juju.status().get_units(app_name).values()
            ]
            juju_hosts = [f"{host}:{MONGOD_PORT}" for host in hosts]
        case "microk8s":
            model_name = juju.model
            hosts = [
                f"mongodb-k8s-{unit_id}.mongodb-k8s-endpoints.{model_name}.svc.cluster.local:27017"
                for unit_id in range(num_units)
            ]
            juju_hosts = [f"{host}:{MONGOD_PORT}" for host in hosts]

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)
    uri = replica_set_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=password,
        ip_addresses=hosts,
        replica_set=app_name,
    )

    # connect to replica set uri and get replica set members
    rs_status = execute_on_mongod(
        juju, substrate=substrate, app_name=app_name, uri=uri, command="rs.status()"
    )

    assert rs_status.succeeded, "Failed to get status from replica set."

    mongodb_hosts = [member["name"] for member in rs_status.data["members"]]

    # verify that the replica set members have the correct units
    assert set(mongodb_hosts) == set(juju_hosts), (
        "hosts for mongodb: "
        + str(set(mongodb_hosts))
        + " and juju: "
        + str(set(juju_hosts))
        + " don't match"
    )


@pytest.mark.abort_on_fail
async def test_scale_down(juju: jubilant.Juju, substrate: Substrate):
    """Tests juju remove-unit functionality.

    This test verifies:
    1. multiple units can be removed while still maintaining a majority (ie remove a minority)
    2. Replica set hosts are properly updated on unit removal
    """
    assert juju.model
    app_name = existing_app(juju)
    assert app_name

    initial_n_units = len(juju.status().get_units(app_name))

    # remove two units and wait for idle
    remove_number_units(juju, substrate, app_name, 2)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=initial_n_units - 2
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    post_scale_n_units = len(juju.status().get_units(app_name))
    assert post_scale_n_units == initial_n_units - 2

    # grab juju hosts
    match substrate:
        case "lxd":
            hosts = [
                get_ip_from_unit(substrate, unit_info)
                for unit_info in juju.status().get_units(app_name).values()
            ]
        case "microk8s":
            model_name = juju.model
            hosts = [
                f"mongodb-k8s-{unit_id}.mongodb-k8s-endpoints.{model_name}.svc.cluster.local"
                for unit_id in range(post_scale_n_units)
            ]

    juju_hosts = [f"{host}:{MONGOD_PORT}" for host in hosts]

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)
    uri = replica_set_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=password,
        ip_addresses=hosts,
        replica_set=app_name,
    )

    # connect to replica set uri and get replica set members
    rs_status = execute_on_mongod(
        juju, substrate=substrate, app_name=app_name, uri=uri, command="rs.status()"
    )

    assert rs_status.succeeded, "Failed to get status from replica set."

    mongodb_hosts = [member["name"] for member in rs_status.data["members"]]

    # verify that the replica set members have the correct units
    assert set(mongodb_hosts) == set(juju_hosts), (
        "hosts for mongodb: "
        + str(set(mongodb_hosts))
        + " and juju: "
        + str(set(juju_hosts))
        + " don't match"
    )

    # verify that the set maintains a primary
    primary = [
        member["name"] for member in rs_status.data["members"] if member["stateStr"] == "PRIMARY"
    ][0]

    assert primary in juju_hosts, "no primary after scaling down"


@pytest.mark.abort_on_fail
async def test_replication_data_consistency(juju: jubilant.Juju, substrate: Substrate):
    """Test the data consistency between the primary and secondaries.

    Verifies that after writing data to the primary the data on
    the secondaries match.
    """
    app_name = existing_app(juju)
    assert app_name

    # generate a collection id
    collection_id = generate_collection_id()

    # grab juju hosts
    match substrate:
        case "lxd":
            hosts = [
                get_ip_from_unit(substrate, unit_info)
                for unit_info in juju.status().get_units(app_name).values()
            ]
        case "microk8s":
            hosts = [
                f"mongodb-k8s-{get_unit_id(unit_name)}.mongodb-k8s-endpoints"
                for unit_name in juju.status().get_units(app_name)
            ]

    username = CHARMED_OPERATOR_USERNAME
    password = get_password(juju=juju, app_name=app_name, username=username)

    uri = replica_set_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=password,
        ip_addresses=hosts,
        replica_set=app_name,
    )

    # Create a database and a collection (lazily)
    create_collection = execute_on_mongod(
        juju,
        substrate=substrate,
        app_name=app_name,
        uri=uri,
        command=f"db.createCollection('{collection_id}')",
    )

    assert create_collection.succeeded, "Failed to create collection."
    assert create_collection.data["ok"] == 1

    # Store a few test documents
    insert_many_docs = execute_on_mongod(
        juju,
        substrate=substrate,
        app_name=app_name,
        uri=uri,
        command=f"db.{collection_id}.insertMany({bson_loads(TEST_DOCUMENTS)})",
    )

    assert len(insert_many_docs.data["insertedIds"]) == 2

    # attempt ensuring that the replication happened on all secondaries
    # 24sec is an arbitrary number that worked well locally in a couple of tests
    # 12 sec being the median time for primary reelection, so I randomly chose a factor
    time.sleep(24)

    # query the primary only
    result = execute_on_mongod(
        juju,
        substrate=substrate,
        app_name=app_name,
        uri=uri,
        command="db.getMongo().setReadPref('primary')",
        expecting_output=True,
    )
    assert result.succeeded, "Failed to set read preference to primary."
    check_if_test_documents_stored(
        juju, substrate=substrate, app_name=app_name, uri=uri, collection=collection_id
    )

    # query only from the secondaries
    result = execute_on_mongod(
        juju,
        substrate=substrate,
        app_name=app_name,
        uri=uri,
        command="db.getMongo().setReadPref('secondary')",
        expecting_output=True,
    )
    assert result.succeeded, "Failed to set read preference to secondary."
    check_if_test_documents_stored(
        juju, substrate=substrate, app_name=app_name, uri=uri, collection=collection_id
    )

    # query the secondaries by targeting units
    # connect to replica set uri and get replica set members
    rs_status = execute_on_mongod(
        juju,
        substrate=substrate,
        app_name=app_name,
        uri=uri,
        command="JSON.stringify(rs.status())",
        stringify=False,
    )
    assert rs_status.succeeded, "Failed to get rs status on secondary."

    # get the secondaries ordered ASC by the least amount of data sync delay
    # compared to the primary, so that we can attempt to delay the documents
    # query until after the said delay is elapsed (using time.sleep)
    secondaries = secondary_mongo_uris_with_sync_delay(
        juju,
        app_name,
        rs_status.data,
    )

    # verify that each secondary contains the data
    synced_secondaries_count = 0
    for secondary in secondaries:
        time.sleep(secondary.delay + 2)  # probably useless, but attempting
        try:
            check_if_test_documents_stored(
                juju,
                substrate=substrate,
                app_name=app_name,
                uri=secondary.uri,
                collection=collection_id,
            )
        except Exception:
            # there may need some time to finish replicating to this specific secondary
            continue

        synced_secondaries_count += 1

    logger.info(
        f"{synced_secondaries_count}/{len(secondaries)} secondaries fully synced with primary."
    )
    assert synced_secondaries_count > 0
