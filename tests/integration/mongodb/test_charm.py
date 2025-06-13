#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import pathlib
import subprocess
import time
from pathlib import Path
from subprocess import check_output
from uuid import uuid4

import pytest
from bson.json_util import loads as bson_loads
from more_itertools import one
from pymongo import MongoClient
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
from pytest_operator.plugin import OpsTest
from tenacity import RetryError

from ..helpers.common import (
    DEPLOYMENT_TIMEOUT,
    MONGOD_PORT,
    TEST_DOCUMENTS,
    UNIT_IDS,
    audit_log_line_sanity_check,
    check_if_test_documents_stored,
    check_or_scale_app,
    clear_continous_writes,
    count_primaries,
    deploy_application,
    deploy_charm,
    execute_on_mongod,
    find_unit,
    generate_collection_id,
    generate_mongodb_client,
    get_address_of_unit,
    get_app_name,
    get_leader_id,
    get_password,
    relate_mongodb_and_application,
    secondary_mongo_uris_with_sync_delay,
    set_password,
    start_continous_writes,
    stop_continous_writes,
    unit_uri,
)
from ..helpers.types import Substrate

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, mongodb_charm: Path, substrate: Substrate, mongod_resource, base_app_name
):
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, app_name, len(UNIT_IDS))
        return

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
    )
    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


@pytest.mark.abort_on_fail
async def test_consistency_between_workload_and_metadata(
    ops_test: OpsTest, substrate: Substrate, mongod_base_path: str
):
    app_name = await get_app_name(ops_test)
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    password = await get_password(ops_test, app_name=app_name)
    ip_address = await get_address_of_unit(
        ops_test, substrate, int(leader_unit.name.split("/")[1]), app_name
    )

    client = MongoClient(unit_uri(ip_address, password, app_name), directConnection=True)

    mongod_version = client.server_info()["version"].split("-")[0]

    local_version = pathlib.Path(mongod_base_path, "workload_version").read_text().strip()

    assert (
        mongod_version == local_version
    ), f"Version of mongod running is invalid ({mongod_version}), should be {local_version}"


async def test_status(ops_test: OpsTest) -> None:
    """Verifies that the application and unit are active."""
    app_name = await get_app_name(ops_test)
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=1000)
    assert len(ops_test.model.applications[app_name].units) == len(UNIT_IDS)


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("unit_id", UNIT_IDS)
async def test_unit_is_running_as_replica_set(
    ops_test: OpsTest, substrate: Substrate, unit_id: int
) -> None:
    """Tests that mongodb is running as a replica set for the application unit."""
    # connect to mongo replica set
    app_name = await get_app_name(ops_test)
    address = await get_address_of_unit(ops_test, substrate, unit_id, app_name)
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
async def test_exactly_one_primary(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that there is exactly one primary in the deployed units."""
    app_name = await get_app_name(ops_test)
    try:
        password = await get_password(ops_test, app_name=app_name)
        number_of_primaries = await count_primaries(
            ops_test, substrate, password, app_name=app_name
        )
    except RetryError:
        number_of_primaries = 0

    # check that exactly of the units is the leader
    assert (
        number_of_primaries == 1
    ), f"Expected one unit to be a primary: {number_of_primaries} != 1"


@pytest.mark.abort_on_fail
async def test_get_primary_action(ops_test: OpsTest, substrate: Substrate):
    """Tests that action get-primary outputs the correct unit with the primary replica."""
    app_name = await get_app_name(ops_test)
    expected_primary = None
    for unit in ops_test.model.applications[app_name].units:
        unit_id = int(unit.name.split("/")[1])
        ip_address = await get_address_of_unit(ops_test, substrate, unit_id, app_name)
        # connect to mongod
        password = await get_password(ops_test)
        client = MongoClient(unit_uri(ip_address, password, app_name), directConnection=True)

        # check primary status
        if client.is_primary:
            expected_primary = unit.name
            break

    # verify that there is a primary
    assert expected_primary

    # check if get-primary returns the correct primary unit regardless of
    # which unit the action is run on
    for unit in ops_test.model.applications[app_name].units:
        # use get-primary action to find primary
        action = await unit.run_action("get-primary")
        action = await action.wait()
        identified_primary = action.results["replica-set-primary"]

        # assert get-primary returned the right primary
        assert identified_primary == expected_primary


@pytest.mark.abort_on_fail
async def test_set_password_action(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that action set-password outputs resets the password on app data and mongod."""
    # verify that password is correctly rotated by comparing old password with rotated one.
    old_password = await get_password(ops_test)
    unit = await find_unit(ops_test, leader=True)
    action = await unit.run_action("set-password")
    action = await action.wait()
    new_password = action.results["password"]
    assert new_password != old_password
    new_password_reported = await get_password(ops_test)
    assert new_password == new_password_reported
    user_app_name = await get_app_name(ops_test)
    unit_id = int(unit.name.split("/")[1])
    ip_address = await get_address_of_unit(ops_test, substrate, unit_id, user_app_name)

    # verify that the password is updated in mongod by inserting into the collection.
    try:
        client = MongoClient(
            unit_uri(ip_address, new_password, user_app_name),
            directConnection=True,
        )
        client["new-db"].list_collection_names()
    except PyMongoError as e:
        assert False, f"Failed to access collection with new password, error: {e}"
    finally:
        client.close()

    # perform the same tests as above but with a user provided password.
    old_password = await get_password(ops_test)
    action = await unit.run_action("set-password", **{"password": "safe_pass"})
    action = await action.wait()
    new_password = action.results["password"]
    assert new_password != old_password
    new_password_reported = await get_password(ops_test)
    assert "safe_pass" == new_password_reported

    # verify that the password is updated in mongod by inserting into the collection.
    try:
        client = MongoClient(
            unit_uri(ip_address, "safe_pass", user_app_name),
            directConnection=True,
        )
        client["new-db"].list_collection_names()
    except PyMongoError as e:
        assert False, f"Failed to access collection with new password, error: {e}"
    finally:
        client.close()


@pytest.mark.abort_on_fail
async def test_monitor_user(ops_test: OpsTest, substrate: Substrate) -> None:
    """Test verifies that the monitor user can perform operations such as 'rs.conf()'."""
    app_name = await get_app_name(ops_test)
    password = await get_password(ops_test, username="monitor")
    replica_set_hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    hosts = ",".join(replica_set_hosts)
    replica_set_uri = f"mongodb://monitor:{password}@{hosts}/admin?replicaSet={app_name}"

    admin_mongod_cmd = "rs.conf()"

    result = await execute_on_mongod(
        ops_test, app_name, substrate, replica_set_uri, admin_mongod_cmd
    )
    assert result.succeeded, "Failed to get conf with monitor user."


async def test_only_leader_can_set_while_all_can_read_password_secret(
    ops_test: OpsTest,
) -> None:
    """Test verifies that only the leader can set a password, while all units can read it."""
    # Setting existing password
    leader_id = await get_leader_id(ops_test)
    non_leaders = list(UNIT_IDS)
    non_leaders.remove(leader_id)

    password = "blablabla"
    await set_password(ops_test, unit_id=non_leaders[0], username="monitor", password=password)
    password1 = await get_password(ops_test, username="monitor")
    assert password1 != password

    await set_password(ops_test, unit_id=leader_id, username="monitor", password=password)
    for _ in UNIT_IDS:
        password2 = await get_password(ops_test, username="monitor")
        assert password2 == password


@pytest.mark.abort_on_fail
async def test_reset_and_get_password_secret_same_as_cli(ops_test: OpsTest) -> None:
    """Test verifies that we can set and retrieve the correct password using Juju 3.x secrets."""
    app_name = await get_app_name(ops_test)
    new_password = str(uuid4())

    # Resetting existing password
    leader_id = await get_leader_id(ops_test)
    await set_password(ops_test, unit_id=leader_id, username="monitor", password=new_password)

    # Getting back the pw programmatically
    password = await get_password(ops_test, username="monitor")

    secret_label = f"{app_name}.app"

    # Getting back the pw from juju CLI
    complete_command = f"show-secret {secret_label} --reveal --format=json"
    _, stdout, _ = await ops_test.juju(*complete_command.split())
    data = one(json.loads(stdout).values())

    assert password == new_password

    assert data["content"]["Data"]["monitor-password"] == password


async def test_empty_password(ops_test: OpsTest) -> None:
    """Test that the password can't be set to an empty string."""
    leader_id = await get_leader_id(ops_test)

    password1 = await get_password(ops_test, username="monitor")
    await set_password(ops_test, unit_id=leader_id, username="monitor", password="")
    password2 = await get_password(ops_test, username="monitor")

    # The password remained unchanged
    assert password1 == password2


@pytest.mark.abort_on_fail
async def test_no_password_change_on_invalid_password(ops_test: OpsTest) -> None:
    """Test that in general, there is no change when password validation fails."""
    leader_id = await get_leader_id(ops_test)
    password1 = await get_password(ops_test, username="monitor")

    # The password has to be minimum 3 characters
    await set_password(ops_test, unit_id=leader_id, username="monitor", password="ca" * 1000000)
    password2 = await get_password(ops_test, username="monitor")

    # The password didn't change
    assert password1 == password2


async def test_audit_log(ops_test: OpsTest, substrate: Substrate) -> None:
    """Test that audit log was created and contains actual audit data."""
    app_name = await get_app_name(ops_test)
    match substrate:
        case "lxd":
            audit_log_path = "/var/snap/charmed-mongodb/common/var/log/mongodb/audit.log"
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh {app_name}/leader sudo"
        case "microk8s":
            audit_log_path = "/var/log/mongodb/audit.log"
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh --container mongod {app_name}/leader"
        case _:
            raise Exception(f"Invalid substrate {substrate}")

    audit_log = check_output(
        f"{base_command} cat {audit_log_path}",
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True,
    )

    for line in audit_log.splitlines():
        if not len(line):
            continue
        item = json.loads(line)
        # basic sanity check
        assert audit_log_line_sanity_check(item), "Audit sanity log check failed for first line"


@pytest.mark.abort_on_fail
async def test_log_rotate(ops_test: OpsTest, substrate: Substrate, application_path: str) -> None:
    """Test that log are being rotated."""
    app_name = await get_app_name(ops_test)
    application_name = "application"
    await deploy_application(ops_test, application_path=application_path, app_name=application_name)
    await relate_mongodb_and_application(ops_test, app_name, application_name)

    time_to_write_50m_of_data = 60 * 10
    logrotate_timeout = 61

    match substrate:
        case "lxd":
            audit_log_path = "/var/snap/charmed-mongodb/common/var/log/mongodb/"
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh {app_name}/leader sudo"
        case "microk8s":
            audit_log_path = "/var/log/mongodb/"
            base_command = f"JUJU_MODEL={ops_test.model_full_name} juju ssh --container mongod {app_name}/leader"
        case _:
            raise Exception(f"Invalid substrate {substrate}")

    log_files = check_output(
        f"{base_command} ls {audit_log_path}",
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True,
    )

    log_not_rotated = "audit.log.1" not in log_files
    assert log_not_rotated, f"Found rotated log in {log_files}"

    await start_continous_writes(ops_test, client_app_name=application_name)
    time.sleep(time_to_write_50m_of_data)
    await stop_continous_writes(ops_test, client_app_name=application_name)
    time.sleep(logrotate_timeout)  # Just to make sure that logrotate will run
    await clear_continous_writes(ops_test, client_app_name=application_name)

    log_files = check_output(
        f"{base_command} ls {audit_log_path}",
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True,
    )

    log_rotated = "audit.log.1" in log_files
    assert log_rotated, f"Could not find rotated log in {log_files}"

    audit_log_exists = "audit.log" in log_files
    assert audit_log_exists, f"Could not find audit.log log in {log_files}"


@pytest.mark.abort_on_fail
async def test_scale_up(ops_test: OpsTest, substrate):
    """Tests juju add-unit functionality.

    Verifies that when a new unit is added to the MongoDB application that it is added to the
    MongoDB replica set configuration.
    """
    app_name = await get_app_name(ops_test)
    n_units = len(ops_test.model.applications[app_name].units)
    # add two units and wait for idle
    await ops_test.model.applications[app_name].add_unit(2)
    # TODO: Remove the `raise_on_error` when we move to juju 3.5 (DPE-4996)
    await ops_test.model.wait_for_idle(
        apps=[app_name],
        status="active",
        timeout=1000,
        wait_for_exact_units=n_units + 2,
        raise_on_error=False,
    )
    num_units = len(ops_test.model.applications[app_name].units)
    assert num_units == 5

    match substrate:
        case "lxd":
            hosts = [
                await get_address_of_unit(
                    ops_test, substrate, int(unit.name.split("/")[1]), app_name
                )
                for unit in ops_test.model.applications[app_name].units
            ]

            juju_hosts = [f"{host}:{MONGOD_PORT}" for host in hosts]
        case "microk8s":
            juju_hosts = [
                f"mongodb-k8s-{unit_id}.mongodb-k8s-endpoints:27017" for unit_id in range(num_units)
            ]
        case _:
            raise Exception("Invalid substrate")

    uri = await generate_mongodb_client(ops_test, substrate, app_name, mongos=False)

    # connect to replica set uri and get replica set members
    rs_status = await execute_on_mongod(ops_test, app_name, substrate, uri, "rs.status()")

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
async def test_scale_down(ops_test: OpsTest, substrate: Substrate):
    """Tests juju remove-unit functionality.

    This test verifies:
    1. multiple units can be removed while still maintaining a majority (ie remove a minority)
    2. Replica set hosts are properly updated on unit removal
    """
    app_name = await get_app_name(ops_test)
    n_units = len(ops_test.model.applications[app_name].units)
    units = ops_test.model.applications[app_name].units[-2:]
    # add two units and wait for idle
    await ops_test.model.applications[app_name].destroy_unit(*(unit.name for unit in units))
    # TODO: Remove the `raise_on_error` when we move to juju 3.5 (DPE-4996)
    await ops_test.model.wait_for_idle(
        apps=[app_name],
        status="active",
        timeout=1000,
        wait_for_exact_units=n_units - 2,
        raise_on_error=False,
    )
    num_units = len(ops_test.model.applications[app_name].units)
    assert num_units == n_units - 2

    # grab juju hosts
    match substrate:
        case "lxd":
            hosts = [
                await get_address_of_unit(
                    ops_test, substrate, int(unit.name.split("/")[1]), app_name
                )
                for unit in ops_test.model.applications[app_name].units
            ]

            juju_hosts = [f"{host}:{MONGOD_PORT}" for host in hosts]
        case "microk8s":
            juju_hosts = [
                f"mongodb-k8s-{unit_id}.mongodb-k8s-endpoints:27017" for unit_id in range(num_units)
            ]
        case _:
            raise Exception("Invalid substrate")

    uri = await generate_mongodb_client(ops_test, substrate, app_name, mongos=False)

    # connect to replica set uri and get replica set members
    rs_status = await execute_on_mongod(ops_test, app_name, substrate, uri, "rs.status()")

    assert rs_status.succeeded, "Failed to get replica set status."

    # connect to replica set uri and get replica set members
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
async def test_replication_data_consistency(ops_test: OpsTest, substrate: Substrate):
    """Test the data consistency between the primary and secondaries.

    Verifies that after writing data to the primary the data on
    the secondaries match.
    """
    app_name = await get_app_name(ops_test)
    # generate a collection id
    collection_id = generate_collection_id()

    uri = await generate_mongodb_client(ops_test, substrate, app_name, mongos=False)

    # Create a database and a collection (lazily)
    create_collection = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        f"db.createCollection('{collection_id}')",
    )

    assert create_collection.succeeded, "Failed to create collection."
    assert create_collection.data["ok"] == 1

    # Store a few test documents
    insert_many_docs = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        f"db.{collection_id}.insertMany({bson_loads(TEST_DOCUMENTS)})",
    )

    assert len(insert_many_docs.data["insertedIds"]) == 2

    # attempt ensuring that the replication happened on all secondaries
    # 24sec is an arbitrary number that worked well locally in a couple of tests
    # 12 sec being the median time for primary reelection, so I randomly chose a factor
    time.sleep(24)

    # query the primary only
    result = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        "db.getMongo().setReadPref('primary')",
        expecting_output=False,
    )
    assert result.succeeded, "Failed to set read preference to primary."
    await check_if_test_documents_stored(ops_test, app_name, substrate, uri, collection_id)

    # query only from the secondaries
    result = await execute_on_mongod(
        ops_test,
        app_name,
        substrate,
        uri,
        "db.getMongo().setReadPref('secondary')",
    )
    assert result.succeeded, "Failed to set read preference to secondary."
    await check_if_test_documents_stored(ops_test, app_name, substrate, uri, collection_id)

    # query the secondaries by targeting units
    rs_status = await execute_on_mongod(
        ops_test, app_name, substrate, uri, "JSON.stringify(rs.status())", stringify=False
    )
    assert rs_status.succeeded, "Failed to get rs status on secondary."

    # get the secondaries ordered ASC by the least amount of data sync delay
    # compared to the primary, so that we can attempt to delay the documents
    # query until after the said delay is elapsed (using time.sleep)
    secondaries = await secondary_mongo_uris_with_sync_delay(
        ops_test, substrate, app_name, rs_status.data
    )

    # verify that each secondary contains the data
    synced_secondaries_count = 0
    for secondary in secondaries:
        time.sleep(secondary["delay"] + 2)  # probably useless, but attempting
        try:
            await check_if_test_documents_stored(
                ops_test, app_name, substrate, secondary["uri"], collection_id
            )
        except Exception:
            # there may need some time to finish replicating to this specific secondary
            continue

        synced_secondaries_count += 1

    logger.info(
        f"{synced_secondaries_count}/{len(secondaries)} secondaries fully synced with primary."
    )
    assert synced_secondaries_count > 0
