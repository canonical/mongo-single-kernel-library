#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import time
from datetime import datetime, timezone
from logging import getLogger

import jubilant
import pytest
from jubilant.statustypes import UnitStatus
from pymongo import MongoClient
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    CONTINUOUS_WRITE_APPLICATION,
    DB_PROCESS,
    DEFAULT_DATABASE_NAME,
    DEFAULT_REPLICATION_COLL_NAME,
    DEPLOYMENT_TIMEOUT,
    MEDIAN_REELECTION_TIME,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import (
    count_writes,
    replica_set_primary,
    replica_set_secondary,
    stop_continuous_writes,
    verify_writes,
)
from tests.integration.helpers.jubilant_common import (
    count_primaries,
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    find_leader,
    get_highest_unit,
    get_ip_from_unit,
    get_ips_for_app,
    get_mongodb_hostnames_for_app,
    get_password,
    mongod_ready,
    remove_number_units,
    unit_uri,
    verify_cluster_ip_source_allowlist,
)
from tests.integration.helpers.jubilant_ha import (
    all_db_processes_down,
    db_step_down,
    delete_pod,
    fetch_replica_set_members,
    host_to_unit,
    insert_release_to_cluster,
    patch_restart_delay,
    retrieve_entries,
    reused_storage,
    send_process_control_signal,
    storage_id,
    storage_type,
    verify_replica_set_configuration,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

ANOTHER_DATABASE_APP_NAME = "another-database-a"
RESTART_DELAY = 60 * 3

logger = getLogger(__name__)


def test_build_and_deploy(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
):
    """Build and deploy three units of MongoDB."""
    if substrate == Substrate.lxd:
        logger.info("Create storage pool on VM")
        juju.cli("create-storage-pool", "mongodb-storage", "lxd")
        storage = {"data": "mongodb-storage,2G"}
    else:
        storage = None

    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
        storage=storage,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, base_app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_cluster_ip_source_allowlist_contains_all_replica_set_ips(
    juju: jubilant.Juju,
    substrate: Substrate,
):
    """Verify every unit allows all replica-set member IPs for internal authentication."""
    app_name = existing_app(juju)
    assert app_name
    verify_cluster_ip_source_allowlist(juju, substrate, app_name)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_storage_re_use_lxd(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
):
    """Verifies that database units with attached storage correctly repurpose storage.

    It is not enough to verify that Juju attaches the storage. Hence test checks that the mongod
    properly uses the storage that was provided. (ie. doesn't just re-sync everything from
    primary, but instead computes a diff between current storage and primary storage.)
    """
    app_name = existing_app(juju)
    assert app_name
    if storage_type(juju, app_name) == "rootfs":
        pytest.skip(
            "reuse of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    # remove a unit and attach it's storage to a new unit
    unit_name = next(iter(juju.status().get_units(app_name)))
    data_storage_id = storage_id(juju, unit_name, "data")

    assert data_storage_id, "Did not find a data storage for unit."

    expected_units = len(juju.status().get_units(app_name)) - 1
    removal_time = time.time()

    juju.remove_unit(unit_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=expected_units
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    current_units = set(juju.status().get_units(app_name).keys())
    juju.add_unit(app_name, attach_storage=data_storage_id, num_units=1)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=expected_units + 1
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )
    new_units = set(juju.status().get_units(app_name).keys())

    added_units = new_units - current_units

    assert len(added_units) == 1

    new_unit = next(iter(added_units))

    assert reused_storage(
        juju, substrate, new_unit, removal_time
    ), "attached storage not properly reused by MongoDB."

    verify_writes(juju, substrate, app_name)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_storage_re_use_k8s(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
):
    """Verifies that database units with attached storage correctly repurpose storage.

    It is not enough to verify that Juju attaches the storage. Hence test checks that the mongod
    properly uses the storage that was provided. (ie. doesn't just re-sync everything from
    primary, but instead computes a diff between current storage and primary storage.)
    """
    app_name = existing_app(juju)
    assert app_name

    # remove a unit and attach it's storage to a new unit
    current_number_units = len(juju.status().get_units(app_name))

    remove_number_units(juju, substrate, app_name, num_units=1)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=10, unit_count=current_number_units - 1
        ),
        timeout=TIMEOUT,
    )

    # k8s will automatically use the old storage from the storage pool
    removal_time = datetime.now(timezone.utc).timestamp()

    juju.add_unit(app_name, num_units=1)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=10, unit_count=current_number_units
        ),
        timeout=TIMEOUT,
    )

    # for this test, we only scaled up the application by one unit. So it the highest unit will be
    # the newest unit.
    new_unit = get_highest_unit(juju, app_name)
    assert new_unit, "No highest unit found"

    assert reused_storage(
        juju, substrate, new_unit, removal_time
    ), "attached storage not properly reused by MongoDB."

    # verify presence of primary, replica set member configuration, and number of primaries
    assert (
        count_primaries(juju, substrate, app_name) == 1
    ), "there is more than one primary in the replica set."

    # verify all units are up to date.
    verify_writes(juju, substrate, app_name)


@pytest.mark.skip("This is currently unsupported on MongoDB charm.")
@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_storage_re_use_different_cluster(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
):
    """Tests that we can reuse storage from a different cluster.

    For that, we completely remove the application while keeping the storages,
    and then we deploy a new application with storage reuse and check that the
    storage has been reused.
    """
    app_name = existing_app(juju)
    assert app_name
    if storage_type(juju, app_name) == "rootfs":
        pytest.skip(
            "reuse of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    writes_results = stop_continuous_writes(juju, client_app_name=CONTINUOUS_WRITE_APPLICATION)
    unit_ids = list(juju.status().get_units(app_name).keys())
    storage_ids = {}

    remaining_units = len(unit_ids)
    for unit_id in unit_ids:
        storage_ids[unit_id] = storage_id(juju, unit_id, "data")
        juju.remove_unit(unit_id)
        # Give some time to remove the unit. We don't use asyncio.sleep here to
        # leave time for each unit to be removed before removing the next one.
        # time.sleep(60)
        remaining_units -= 1
        juju.wait(
            lambda status: are_apps_active_and_agents_idle(
                status, app_name, idle_period=10, unit_count=remaining_units
            ),
            timeout=TIMEOUT,
        )

    # Wait until all apps are cleaned up
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=10, unit_count=0
        ),
        timeout=TIMEOUT,
    )

    for unit_id in unit_ids:
        n_units = len(juju.status().get_units(app_name))
        juju.add_unit(app_name, num_units=1, attach_storage=storage_ids[unit_id])
        juju.wait(
            lambda status: are_apps_active_and_agents_idle(
                status, app_name, idle_period=10, unit_count=n_units + 1
            ),
            timeout=TIMEOUT,
        )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=10, unit_count=len(unit_ids)
        ),
        timeout=TIMEOUT,
    )

    leader_unit_name, leader_unit_status = find_leader(juju, app_name)

    actual_writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=leader_unit_name, unit_info=leader_unit_status
    )
    assert writes_results == actual_writes


def test_scale_up_capabilities(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
) -> None:
    """Tests juju add-unit functionality.

    Verifies that when a new unit is added to the MongoDB application that it is added to the
    MongoDB replica set configuration.
    """
    # add units and wait for idle
    app_name = existing_app(juju)
    assert app_name

    current_units = len(juju.status().get_units(app_name))

    ensure_app_number_units(
        juju,
        substrate,
        app_name,
        required_units=current_units + 2,
        wait=True,
    )

    # grab unit hosts
    hosts = get_mongodb_hostnames_for_app(juju, substrate, app_name)

    # connect to replica set uri and get replica set members
    member_hosts = fetch_replica_set_members(juju, substrate, app_name)

    # verify that the replica set members have the correct units
    assert set(member_hosts) == set(hosts), "all members not running under the same replset"

    verify_cluster_ip_source_allowlist(juju, substrate, app_name)

    # verify that the no writes were skipped
    verify_writes(juju, substrate, app_name)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_scale_down_capabilities_lxd(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
) -> None:
    """Tests clusters behavior when scaling down a minority and removing a primary replica.

    - NOTE: on a provided cluster this calculates the largest set of minority members and removes
    them, the primary is guaranteed to be one of those minority members.

    This test verifies that the behavior of:
    1.  when a leader is deleted that the new leader, on calling leader_elected will reconfigure
    the replicaset.
    2. primary stepping down leads to a replica set with a new primary.
    3. removing a minority of units (2 out of 5) is feasiable.
    4. race conditions due to removing multiple units is handled.
    5. deleting a non-leader unit is properly handled.
    """
    app_name = existing_app(juju)
    assert app_name

    deleted_unit_ips = []
    units_to_remove = []
    current_units = len(juju.status().get_units(app_name))
    minority_count = current_units // 2

    # find leader unit
    leader_unit_name, leader_unit_status = find_leader(juju, app_name)

    # verify that we have a leader
    assert leader_unit_name is not None, "No unit is leader"
    deleted_unit_ips.append(leader_unit_status.public_address)
    units_to_remove.append(leader_unit_name)

    # find non-leader units to remove such that the largest minority possible is removed.
    avail_units: list[tuple[str, UnitStatus]] = []
    for unit_name, unit_status in juju.status().get_units(app_name).items():
        if not unit_name == leader_unit_name:
            avail_units.append((unit_name, unit_status))

    for _ in range(minority_count):
        unit_name, unit_status = avail_units.pop()
        deleted_unit_ips.append(unit_status.public_address)
        units_to_remove.append(unit_name)

    # destroy units simultaneously
    expected_units = current_units - len(units_to_remove)
    juju.remove_unit(*units_to_remove)

    # wait for app to be active after removal of units
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=10, unit_count=expected_units
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    hosts = get_ips_for_app(juju, substrate, app_name)
    # check that the replica set with the remaining units has a primary
    try:
        primary_name, primary_status = replica_set_primary(juju, substrate, app_name)
    except RetryError:
        primary_name, primary_status = None, None

    # verify that the primary is not None
    assert primary_name, "replica set has no primary"
    assert primary_status, "replica set has no primary status information"

    # check that the primary is one of the remaining units
    assert (
        primary_status.public_address in hosts
    ), "replica set primary is not one of the available units"

    # verify that the configuration of mongodb no longer has the deleted ip
    member_ips = fetch_replica_set_members(juju, substrate, app_name=app_name)

    assert set(member_ips) == set(hosts), "mongod config contains deleted units"

    verify_cluster_ip_source_allowlist(
        juju, substrate, app_name, excluded_addresses=set(deleted_unit_ips)
    )

    verify_writes(juju, substrate, app_name)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_scale_down_capabilities_k8s(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
) -> None:
    """Tests clusters behavior when scaling down a minority and removing a primary replica."""
    app_name = existing_app(juju)
    assert app_name
    assert juju.model

    addresses_before_scale_down = get_ips_for_app(juju, substrate, app_name)

    current_units = len(juju.status().get_units(app_name))
    minority_count = current_units // 2
    expected_units = current_units - minority_count

    # find leader unit
    leader_unit_name, _ = find_leader(juju, app_name)

    # verify that we have a leader
    assert leader_unit_name is not None, "No unit is leader"

    # Force delete the leader and scale down
    delete_pod(leader_unit_name.replace("/", "-"), namespace=juju.model)
    ensure_app_number_units(
        juju,
        substrate,
        app_name,
        expected_units,
        wait=True,
    )

    hosts = get_ips_for_app(juju, substrate, app_name)
    # grab unit hosts
    hostnames = get_mongodb_hostnames_for_app(juju, substrate, app_name)

    # check that the replica set with the remaining units has a primary
    primary, primary_status = replica_set_primary(juju, substrate, app_name)

    # verify that the primary is not None
    assert primary is not None, "replica set has no primary"

    # check that the primary is one of the remaining units
    assert primary in [
        host_to_unit(hostname) for hostname in hostnames
    ], "replica set primary is not one of the available units"

    # verify that the configuration of mongodb no longer has the deleted ip
    member_hosts = fetch_replica_set_members(juju, substrate, app_name)

    # verify that the replica set members have the correct units
    assert set(member_hosts) == set(hostnames), "mongod config contains deleted units"

    addresses_after_scale_down = set(hosts)
    verify_cluster_ip_source_allowlist(
        juju,
        substrate,
        app_name,
        excluded_addresses=addresses_before_scale_down - addresses_after_scale_down,
    )

    # verify that the no writes were skipped
    verify_writes(juju, substrate, app_name)


def test_replication_across_members(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
) -> None:
    """Check consistency, ie write to primary, read data from secondaries."""
    app_name = existing_app(juju)
    assert app_name

    # first find primary, write to primary, then read from each unit
    insert_release_to_cluster(juju, substrate, app_name)

    ip_addresses = get_ips_for_app(juju, substrate, app_name)
    _, primary_status = replica_set_primary(juju, substrate, app_name=app_name)

    password = get_password(juju, username=CHARMED_OPERATOR_USERNAME, app_name=app_name)

    secondaries = set(ip_addresses) - {primary_status.public_address}
    for secondary in secondaries:
        client = MongoClient(
            unit_uri(
                CHARMED_OPERATOR_USERNAME, password, ip_address=secondary, replica_set=app_name
            ),
            directConnection=True,
        )

        db = client[DEFAULT_DATABASE_NAME]
        test_collection = db[DEFAULT_REPLICATION_COLL_NAME]
        query = test_collection.find({}, {"release_name": 1})
        assert query[0]["release_name"] == "Focal Fossa"

        client.close()

    # verify that the no writes were skipped
    verify_writes(juju, substrate, app_name)


def test_unique_cluster_dbs(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    jubilant_continuous_writes_to_db,
) -> None:
    """Verify unique clusters do not share DBs."""
    # first find primary, write to primary,
    app_name = existing_app(juju)
    assert app_name
    insert_release_to_cluster(juju, substrate, app_name=app_name)

    # deploy new cluster
    if ANOTHER_DATABASE_APP_NAME not in juju.status().apps:
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
            status, ANOTHER_DATABASE_APP_NAME, idle_period=10
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    insert_release_to_cluster(juju, substrate, app_name, release="jammy")

    cluster_1_entries = retrieve_entries(
        juju,
        substrate,
        app_name=ANOTHER_DATABASE_APP_NAME,
        db_name=DEFAULT_DATABASE_NAME,
        collection_name=DEFAULT_REPLICATION_COLL_NAME,
        query_field="release_name",
    )

    cluster_2_entries = retrieve_entries(
        juju,
        substrate,
        app_name=app_name,
        db_name=DEFAULT_DATABASE_NAME,
        collection_name=DEFAULT_REPLICATION_COLL_NAME,
        query_field="release_name",
    )

    common_entries = cluster_2_entries & cluster_1_entries
    assert len(common_entries) == 0, "Writes from one cluster are replicated to another cluster."

    # verify that the no writes were skipped
    verify_writes(juju, substrate, app_name)


def test_replication_member_scaling(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
) -> None:
    """Verify newly added and newly removed members properly replica data.

    Verify newly members have replicated data and newly removed members are gone without data.
    """
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    # first find primary, write to primary,
    insert_release_to_cluster(juju, substrate, app_name=app_name)
    original_ip_addresses = get_ips_for_app(juju, substrate, app_name)

    current_units = len(juju.status().get_units(app_name))

    ensure_app_number_units(juju, substrate, app_name, current_units + 1, wait=True)

    new_ip_addresses = get_ips_for_app(juju, substrate, app_name)

    new_member_ip = list(set(new_ip_addresses) - set(original_ip_addresses))[0]

    password = get_password(juju, username=CHARMED_OPERATOR_USERNAME, app_name=app_name)

    uri = unit_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=password,
        ip_address=new_member_ip,
        replica_set=app_name,
    )
    client = MongoClient(uri, directConnection=True)

    # check for replicated data while retrying to give time for replica to copy over data.
    try:
        for attempt in Retrying(stop=stop_after_delay(2 * 60), wait=wait_fixed(3)):
            with attempt:
                db = client[DEFAULT_DATABASE_NAME]
                test_collection = db[DEFAULT_REPLICATION_COLL_NAME]
                query = test_collection.find({}, {"release_name": 1})
                assert query[0]["release_name"] == "Focal Fossa"

    except RetryError:
        assert False, "Newly added unit doesn't replicate data."

    client.close()

    # verify that the no writes were skipped
    verify_writes(juju, substrate, app_name)


def test_kill_db_process(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
):
    # locate primary unit
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    primary_name, primary_status = replica_set_primary(juju, substrate, app_name=app_name)

    assert primary_name, "No primary found"

    other_unit_name, other_unit_info = replica_set_secondary(juju, substrate, app_name=app_name)
    assert other_unit_name, "No secondary unit found"

    send_process_control_signal(
        juju, substrate, primary_name, signal="SIGKILL", db_process=DB_PROCESS
    )

    # verify new writes are continuing by counting the number of writes before
    # and after a 10 second wait
    writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    time.sleep(10)
    more_writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    assert more_writes > writes, "writes not continuing to DB"

    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # verify that db service got restarted and is ready
    primary_address = get_ip_from_unit(substrate, primary_status)
    assert mongod_ready(juju, primary_address, app_name)

    # verify that a new primary gets elected (ie old primary is secondary)
    new_primary_name, _ = replica_set_primary(juju, substrate, app_name=app_name)
    assert new_primary_name, "No new primary found"

    assert (
        new_primary_name != primary_name
    ), f"New primary {new_primary_name=} is equal to old primary {primary_name=}"

    # verify that no writes were missed
    total_expected_writes = verify_writes(juju, substrate, app_name)

    secondary_writes = count_writes(
        juju, substrate, app_name, unit_name=primary_name, unit_info=primary_status
    )
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."


def test_freeze_db_process(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
):
    # locate primary unit
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    primary_name, primary_status = replica_set_primary(juju, substrate, app_name=app_name)

    assert primary_name, "No primary found"

    other_unit_name, other_unit_info = replica_set_secondary(juju, substrate, app_name=app_name)
    assert other_unit_name, "No secondary unit found"

    send_process_control_signal(
        juju, substrate, primary_name, signal="SIGKILL", db_process=DB_PROCESS
    )

    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # verify that a new primary gets elected
    # verify that a new primary gets elected (ie old primary is secondary)
    new_primary_name, _ = replica_set_primary(juju, substrate, app_name=app_name)
    assert new_primary_name, "No new primary found"

    assert (
        new_primary_name != primary_name
    ), f"New primary {new_primary_name=} is equal to old primary {primary_name=}"
    # verify new writes are continuing by counting the number of writes before
    # and after a 5 second wait
    writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    time.sleep(5)
    more_writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )

    # un-freeze the old primary
    send_process_control_signal(
        juju, substrate, primary_name, signal="SIGCONT", db_process=DB_PROCESS
    )

    # check this after un-freezing the old primary so that if this check fails we still "turned
    # back on" the mongod process
    assert more_writes > writes, "writes not continuing to DB"

    # verify that db service got restarted and is ready
    primary_address = get_ip_from_unit(substrate, primary_status)
    assert mongod_ready(juju, primary_address, app_name)

    # verify all units are running under the same replset
    unit_hostnames = get_mongodb_hostnames_for_app(juju, substrate, app_name)
    member_ips = fetch_replica_set_members(juju, substrate, app_name=app_name)
    assert set(member_ips) == set(unit_hostnames), "all members not running under the same replset"

    # verify there is only one primary after un-freezing old primary
    assert (
        count_primaries(juju, substrate, app_name=app_name) == 1
    ), "there are more than one primary in the replica set."

    # verify that the old primary does not "reclaim" primary status after un-freezing old primary
    new_primary_name, _ = replica_set_primary(juju, substrate, app_name=app_name)
    assert new_primary_name, "No new primary found"

    assert (
        new_primary_name != primary_name
    ), f"New primary {new_primary_name=} is equal to old primary {primary_name=}"

    # verify that no writes were missed
    total_expected_writes = verify_writes(juju, substrate, app_name)

    secondary_writes = count_writes(
        juju, substrate, app_name, unit_name=primary_name, unit_info=primary_status
    )
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."


def test_restart_db_process(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
):
    # locate primary unit
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    primary_name, primary_status = replica_set_primary(juju, substrate, app_name=app_name)

    assert primary_name, "No primary found"

    other_unit_name, other_unit_info = replica_set_secondary(juju, substrate, app_name=app_name)
    assert other_unit_name, "No secondary unit found"

    # send SIGTERM, we expect `systemd` to restart the process
    sig_term_dt = datetime.now(timezone.utc)
    sig_term_time = sig_term_dt.timestamp()
    logger.info("SIGTERM TIME is %s", sig_term_dt)
    send_process_control_signal(
        juju, substrate, primary_name, signal="SIGTERM", db_process=DB_PROCESS
    )

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    # verify new writes are continuing by counting the number of writes before
    # and after a 5 second wait
    writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    time.sleep(5)
    more_writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    assert more_writes > writes, "writes not continuing to DB"

    # verify that db service got restarted and is ready
    primary_address = get_ip_from_unit(substrate, primary_status)
    assert mongod_ready(juju, primary_address, app_name)

    # verify that a new primary gets elected
    new_primary_name, _ = replica_set_primary(juju, substrate, app_name=app_name)
    assert new_primary_name, "No new primary found"

    assert (
        new_primary_name != primary_name
    ), f"New primary {new_primary_name=} is equal to old primary {primary_name=}"

    # verify that a stepdown was performed on restart. SIGTERM should send a graceful restart and
    # send a replica step down signal.
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(3)):
            with attempt:
                assert db_step_down(
                    juju, substrate, sig_term_time, app_name
                ), "old primary departed without stepping down."
    except RetryError:
        assert False, "old primary departed without stepping down."

    # verify that no writes were missed
    total_expected_writes = verify_writes(juju, substrate, app_name)

    secondary_writes = count_writes(
        juju, substrate, app_name, unit_name=primary_name, unit_info=primary_status
    )
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."


def test_full_cluster_crash(
    juju: jubilant.Juju,
    substrate: Substrate,
    jubilant_continuous_writes_to_db,
):
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    other_unit_name, other_unit_info = replica_set_secondary(juju, substrate, app_name=app_name)
    assert other_unit_name, "No secondary unit found"

    # update all units to have a new RESTART_DELAY,  Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    for unit_name in juju.status().get_units(app_name):
        patch_restart_delay(juju, substrate=substrate, unit_name=unit_name, delay=RESTART_DELAY)

    for unit_name in juju.status().get_units(app_name):
        send_process_control_signal(
            juju, substrate, unit_name=unit_name, signal="SIGKILL", db_process=DB_PROCESS
        )

    # This test serves to verify behavior when all replicas are down at the same time that when
    # they come back online they operate as expected. This check verifies that we meet the criteria
    # of all replicas being down at the same time.
    assert all_db_processes_down(
        juju, substrate, app_name=app_name
    ), "Not all units down at the same time."

    logger.info(f"Sleeping for {MEDIAN_REELECTION_TIME * 2 + RESTART_DELAY} seconds")
    # sleep for twice the median election time and the restart delay
    time.sleep(MEDIAN_REELECTION_TIME * 2 + RESTART_DELAY)

    # verify all units are up and running
    for unit_name, unit_status in juju.status().get_units(app_name).items():
        ip_address = get_ip_from_unit(substrate, unit_status)
        assert mongod_ready(
            juju, ip_address, app_name=app_name
        ), f"unit {unit_name} not restarted after cluster crash."

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    time.sleep(5)
    more_writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    assert more_writes > writes, "writes not continuing to DB"

    # verify presence of primary, replica set member configuration, and number of primaries
    verify_replica_set_configuration(juju, substrate, app_name=app_name)

    # verify that no writes to the db were missed
    verify_writes(juju, substrate, app_name)

    for unit_name in juju.status().get_units(app_name):
        patch_restart_delay(juju, substrate, unit_name=unit_name, delay=None)


def test_full_cluster_restart(
    juju: jubilant.Juju, substrate: Substrate, jubilant_continuous_writes_to_db
):
    app_name = existing_app(juju, test_deployments=[ANOTHER_DATABASE_APP_NAME])
    assert app_name

    other_unit_name, other_unit_info = replica_set_secondary(juju, substrate, app_name=app_name)
    assert other_unit_name, "No secondary unit found"

    # update all units to have a new RESTART_DELAY,  Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    for unit_name in juju.status().get_units(app_name):
        patch_restart_delay(juju, substrate=substrate, unit_name=unit_name, delay=RESTART_DELAY)

    for unit_name in juju.status().get_units(app_name):
        send_process_control_signal(
            juju, substrate, unit_name=unit_name, signal="SIGTERM", db_process=DB_PROCESS
        )

    # This test serves to verify behavior when all replicas are down at the same time that when
    # they come back online they operate as expected. This check verifies that we meet the criteria
    # of all replicas being down at the same time.
    assert all_db_processes_down(
        juju, substrate, app_name=app_name
    ), "Not all units down at the same time."

    # sleep for twice the median election time and the restart delay
    logger.info(f"Sleeping for {MEDIAN_REELECTION_TIME * 2 + RESTART_DELAY} seconds")
    time.sleep(MEDIAN_REELECTION_TIME * 2 + RESTART_DELAY)

    # verify all units are up and running
    for unit_name, unit_status in juju.status().get_units(app_name).items():
        ip_address = get_ip_from_unit(substrate, unit_status)
        assert mongod_ready(
            juju, ip_address, app_name=app_name
        ), f"unit {unit_name} not restarted after cluster crash."

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    time.sleep(5)
    more_writes = count_writes(
        juju, substrate, app_name=app_name, unit_name=other_unit_name, unit_info=other_unit_info
    )
    assert more_writes > writes, "writes not continuing to DB"

    # verify presence of primary, replica set member configuration, and number of primaries
    verify_replica_set_configuration(juju, substrate, app_name=app_name)

    # verify that no writes to the db were missed
    verify_writes(juju, substrate, app_name)

    for unit_name in juju.status().get_units(app_name):
        patch_restart_delay(juju, substrate, unit_name=unit_name, delay=None)
