#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import time
from pathlib import Path

import pytest
from juju import tag
from pymongo import MongoClient
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_delay, wait_fixed

from ..helpers.common import (
    DEPLOYMENT_TIMEOUT,
    MEDIAN_REELECTION_TIME,
    UNIT_IDS,
    check_or_scale_app,
    count_primaries,
    count_writes,
    deploy_charm,
    find_unit,
    get_address_of_unit,
    get_app_name,
    get_password,
    get_unit_hostnames,
    get_unit_id,
    get_unit_ip,
    instance_ip,
    mongod_ready,
    unit_hostname,
    unit_uri,
)
from ..helpers.ha import (
    all_db_processes_down,
    cut_network_from_unit,
    db_step_down,
    fetch_replica_set_members,
    get_controller_machine,
    insert_release_to_cluster,
    is_machine_reachable_from,
    kill_unit_process,
    kubectl_delete,
    replica_set_primary,
    replica_set_secondary,
    restore_network_for_unit,
    retrieve_entries,
    reused_storage,
    scale_application,
    storage_id,
    storage_type,
    update_restart_delay,
    verify_replica_set_configuration,
    verify_writes,
    wait_network_restore,
)
from ..helpers.types import Substrate

ANOTHER_DATABASE_APP_NAME = "another-database-a"
RESTART_DELAY = 60 * 3


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

    storage = {"mongodb": {"pool": "lxd", "size": 2048}}

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
        storage=storage,
    )
    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


@pytest.mark.abort_on_fail
async def test_storage_re_use(ops_test, substrate: Substrate, continuous_writes_to_db):
    """Verifies that database units with attached storage correctly repurpose storage.

    It is not enough to verify that Juju attaches the storage. Hence test checks that the mongod
    properly uses the storage that was provided. (ie. doesn't just re-sync everything from
    primary, but instead computes a diff between current storage and primary storage.)
    """
    app_name = await get_app_name(ops_test)
    if storage_type(ops_test, app_name) == "rootfs":
        pytest.skip(
            "reuse of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    # removing the only replica can be disastrous
    if len(ops_test.model.applications[app_name].units) < 2:
        await ops_test.model.applications[app_name].add_unit(count=1)
        await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=1000)

    # remove a unit and attach it's storage to a new unit
    unit = ops_test.model.applications[app_name].units[0]
    unit_storage_id = storage_id(ops_test, unit.name)

    assert unit_storage_id, "Did not find a storage for unit."

    expected_units = len(ops_test.model.applications[app_name].units) - 1
    removal_time = time.time()

    await ops_test.model.destroy_unit(unit.name)
    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, wait_for_exact_units=expected_units
    )

    new_unit = (
        await ops_test.model.applications[app_name].add_unit(
            count=1, attach_storage=[tag.storage(unit_storage_id)]
        )
    )[0]

    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=1000)

    assert await reused_storage(
        ops_test, substrate, new_unit.name, removal_time
    ), "attached storage not properly reused by MongoDB."

    await verify_writes(ops_test, substrate, app_name)


async def test_scale_up_capablities(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db
) -> None:
    """Tests juju add-unit functionality.

    Verifies that when a new unit is added to the MongoDB application that it is added to the
    MongoDB replica set configuration.
    """
    # add units and wait for idle
    app_name = await get_app_name(ops_test)
    await scale_application(ops_test, substrate, app_name, 2)

    # grab unit hosts
    hostnames = await get_unit_hostnames(ops_test, substrate, app_name)

    # connect to replica set uri and get replica set members
    member_hosts = await fetch_replica_set_members(ops_test, substrate, app_name)

    # verify that the replica set members have the correct units
    assert set(member_hosts) == set(hostnames), "all members not running under the same replset"

    # verify that the no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_scale_down_capablities_lxd(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db
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
    # Those tests are so different that we run per substrate
    if substrate == "microk8s":
        pytest.skip("This runs for LXD charms only.")

    deleted_unit_ips = []
    app_name = await get_app_name(ops_test)
    units_to_remove = []
    minority_count = int(len(ops_test.model.applications[app_name].units) / 2)

    # find leader unit
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    minority_count -= 1

    # verify that we have a leader
    assert leader_unit is not None, "No unit is leader"
    deleted_unit_ips.append(leader_unit.public_address)
    units_to_remove.append(leader_unit.name)

    # find non-leader units to remove such that the largest minority possible is removed.
    avail_units = []
    for unit in ops_test.model.applications[app_name].units:
        if not unit.name == leader_unit.name:
            avail_units.append(unit)

    for _ in range(minority_count):
        unit_to_remove = avail_units.pop()
        deleted_unit_ips.append(unit_to_remove.public_address)
        units_to_remove.append(unit_to_remove.name)

    # destroy units simultaneously
    expected_units = len(ops_test.model.applications[app_name].units) - len(units_to_remove)
    await ops_test.model.destroy_units(*units_to_remove)

    # wait for app to be active after removal of units
    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, wait_for_exact_units=expected_units
    )

    # grab unit ips
    hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    # check that the replica set with the remaining units has a primary
    try:
        primary = await replica_set_primary(
            ops_test, substrate, app_name=app_name, replica_set_hosts=hosts
        )
    except RetryError:
        primary = None

    # verify that the primary is not None
    assert primary is not None, "replica set has no primary"

    # check that the primary is one of the remaining units
    assert primary.public_address in hosts, "replica set primary is not one of the available units"

    # verify that the configuration of mongodb no longer has the deleted ip
    member_ips = await fetch_replica_set_members(ops_test, substrate, app_name=app_name)

    assert set(member_ips) == set(hosts), "mongod config contains deleted units"

    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_scale_down_capablities_microk8s(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db
) -> None:
    """Tests clusters behavior when scaling down a minority and removing a primary replica."""
    if substrate == "lxd":
        pytest.skip("This runs only on microk8s.")

    app_name = await get_app_name(ops_test)

    minority_count = int(len(ops_test.model.applications[app_name].units) // 2)
    expected_units = len(ops_test.model.applications[app_name].units) - minority_count

    # find leader unit
    leader_unit = await find_unit(ops_test, leader=True)

    # verify that we have a leader
    assert leader_unit is not None, "No unit is leader"

    # Force delete the leader and scale down
    await kubectl_delete(ops_test, leader_unit, False)
    await scale_application(ops_test, substrate, app_name, expected_units, raise_on_blocked=False)

    # grab unit hosts
    hostnames = await get_unit_hostnames(ops_test, substrate, app_name)

    hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    # check that the replica set with the remaining units has a primary
    primary = await replica_set_primary(ops_test, substrate, app_name, hosts)

    # verify that the primary is not None
    assert primary is not None, "replica set has no primary"

    # check that the primary is one of the remaining units
    assert (
        f"{primary.name.replace('/', '-')}.mongodb-k8s-endpoints" in hostnames
    ), "replica set primary is not one of the available units"

    # verify that the configuration of mongodb no longer has the deleted ip
    member_hosts = await fetch_replica_set_members(ops_test, substrate, app_name)

    # verify that the replica set members have the correct units
    assert set(member_hosts) == set(hostnames), "mongod config contains deleted units"

    # verify that the no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_replication_across_members(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db
) -> None:
    """Check consistency, ie write to primary, read data from secondaries."""
    app_name = await get_app_name(ops_test)
    # first find primary, write to primary, then read from each unit
    await insert_release_to_cluster(ops_test, substrate, app_name)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )

    password = await get_password(ops_test, app_name)

    secondaries = set(ip_addresses) - {primary.public_address}
    for secondary in secondaries:
        client = MongoClient(unit_uri(secondary, password, app_name), directConnection=True)

        db = client["new-db"]
        test_collection = db["test_ubuntu_collection"]
        query = test_collection.find({}, {"release_name": 1})
        assert query[0]["release_name"] == "Focal Fossa"

        client.close()

    # verify that the no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_unique_cluster_dbs(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource,
    continuous_writes_to_db,
) -> None:
    """Verify unique clusters do not share DBs."""
    # first find primary, write to primary,
    app_name = await get_app_name(ops_test)
    await insert_release_to_cluster(ops_test, substrate, app_name=app_name)

    # deploy new cluster
    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=ANOTHER_DATABASE_APP_NAME,
        num_units=1,
    )

    await ops_test.model.wait_for_idle(
        apps=[ANOTHER_DATABASE_APP_NAME], status="active", timeout=DEPLOYMENT_TIMEOUT
    )

    await insert_release_to_cluster(ops_test, substrate, app_name, release="jammy")

    cluster_1_entries = await retrieve_entries(
        ops_test,
        substrate,
        app_name=ANOTHER_DATABASE_APP_NAME,
        db_name="new-db",
        collection_name="test_ubuntu_collection",
        query_field="release_name",
    )

    cluster_2_entries = await retrieve_entries(
        ops_test,
        substrate,
        app_name=app_name,
        db_name="new-db",
        collection_name="test_ubuntu_collection",
        query_field="release_name",
    )

    common_entries = cluster_2_entries.intersection(cluster_1_entries)
    assert len(common_entries) == 0, "Writes from one cluster are replicated to another cluster."

    # verify that the no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_replication_member_scaling(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db
) -> None:
    """Verify newly added and newly removed members properly replica data.

    Verify newly members have replicated data and newly removed members are gone without data.
    """
    app_name = await get_app_name(ops_test)

    # first find primary, write to primary,
    await insert_release_to_cluster(ops_test, substrate, app_name=app_name)
    original_ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    await scale_application(ops_test, substrate, app_name, 1, wait=True)

    new_ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    new_member_ip = list(set(new_ip_addresses) - set(original_ip_addresses))[0]

    password = await get_password(ops_test, app_name)

    client = MongoClient(unit_uri(new_member_ip, password, app_name), directConnection=True)

    # check for replicated data while retrying to give time for replica to copy over data.
    try:
        for attempt in Retrying(stop=stop_after_delay(2 * 60), wait=wait_fixed(3)):
            with attempt:
                db = client["new-db"]
                test_collection = db["test_ubuntu_collection"]
                query = test_collection.find({}, {"release_name": 1})
                assert query[0]["release_name"] == "Focal Fossa"

    except RetryError:
        assert False, "Newly added unit doesn't replicate data."

    client.close()

    # verify that the no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


async def test_kill_db_process(ops_test, substrate: Substrate, continuous_writes_to_db):
    # locate primary unit
    app_name = await get_app_name(ops_test)

    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )

    assert primary, "No primary found"

    other_unit = await replica_set_secondary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert other_unit, "No secondary unit found"

    await kill_unit_process(
        ops_test, substrate, primary.name, kill_code="SIGKILL", app_name=app_name
    )

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    time.sleep(5)
    more_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    assert more_writes > writes, "writes not continuing to DB"

    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # verify that db service got restarted and is ready
    primary_address = await get_address_of_unit(
        ops_test, substrate, get_unit_id(primary.name), app_name
    )
    assert await mongod_ready(ops_test, primary_address, app_name)

    # verify that a new primary gets elected (ie old primary is secondary)
    new_primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert new_primary.name != primary.name

    # verify that no writes were missed
    total_expected_writes = await verify_writes(ops_test, substrate, app_name)

    secondary_writes = await count_writes(ops_test, substrate, app_name, unit=primary)
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."


async def test_freeze_db_process(ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db):
    # locate primary unit
    app_name = await get_app_name(ops_test)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )

    assert primary, "No primary found"

    other_unit = await replica_set_secondary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert other_unit, "No secondary unit found"

    await kill_unit_process(
        ops_test, substrate, primary.name, kill_code="SIGSTOP", app_name=app_name
    )

    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # verify that a new primary gets elected
    new_primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert new_primary.name != primary.name
    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    time.sleep(5)
    more_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)

    # un-freeze the old primary
    await kill_unit_process(
        ops_test, substrate, primary.name, kill_code="SIGCONT", app_name=app_name
    )

    # check this after un-freezing the old primary so that if this check fails we still "turned
    # back on" the mongod process
    assert more_writes > writes, "writes not continuing to DB"

    # verify that db service got restarted and is ready
    primary_address = await get_address_of_unit(
        ops_test, substrate, get_unit_id(primary.name), app_name
    )
    assert await mongod_ready(ops_test, primary_address, app_name)

    # verify all units are running under the same replset
    member_ips = await fetch_replica_set_members(ops_test, substrate, app_name=app_name)
    assert set(member_ips) == set(ip_addresses), "all members not running under the same replset"

    # verify there is only one primary after un-freezing old primary
    password = await get_password(ops_test, app_name=app_name)
    assert (
        await count_primaries(ops_test, substrate, password=password, app_name=app_name) == 1
    ), "there are more than one primary in the replica set."

    # verify that the old primary does not "reclaim" primary status after un-freezing old primary
    new_primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert new_primary.name != primary.name

    # verify that no writes were missed
    total_expected_writes = await verify_writes(ops_test, substrate, app_name)

    secondary_writes = await count_writes(ops_test, substrate, app_name, unit=primary)
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."


@pytest.mark.abort_on_fail
async def test_restart_db_process(ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db):
    # locate primary unit
    app_name = await get_app_name(ops_test)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]

    primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )

    assert primary, "No primary found"

    other_unit = await replica_set_secondary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert other_unit, "No secondary unit found"

    # send SIGTERM, we expect `systemd` to restart the process
    sig_term_time = time.time()
    await kill_unit_process(
        ops_test, substrate, primary.name, kill_code="SIGTERM", app_name=app_name
    )

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    time.sleep(5)
    more_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    assert more_writes > writes, "writes not continuing to DB"

    # verify that db service got restarted and is ready
    primary_address = await get_address_of_unit(
        ops_test, substrate, get_unit_id(primary.name), app_name
    )
    assert await mongod_ready(ops_test, primary_address, app_name)

    # verify that a new primary gets elected
    new_primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert new_primary.name != primary.name

    # verify that a stepdown was performed on restart. SIGTERM should send a graceful restart and
    # send a replica step down signal. Performed with a retry to give time for the logs to update.
    try:
        for attempt in Retrying(stop=stop_after_delay(30), wait=wait_fixed(3)):
            with attempt:
                assert await db_step_down(
                    ops_test, substrate, primary.name, sig_term_time, app_name=app_name
                ), "old primary departed without stepping down."
    except RetryError:
        assert False, "old primary departed without stepping down."

    # verify that no writes were missed
    total_expected_writes = await verify_writes(ops_test, substrate, app_name)

    secondary_writes = await count_writes(ops_test, substrate, app_name, unit=primary)
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."


@pytest.mark.abort_on_fail
async def test_full_cluster_crash(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db, reset_restart_delay, tmp_path
):
    app_name = await get_app_name(ops_test)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    other_unit = await replica_set_secondary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert other_unit, "No secondary unit found"

    # update all units to have a new RESTART_DELAY,  Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    for unit in ops_test.model.applications[app_name].units:
        await update_restart_delay(ops_test, substrate, unit, RESTART_DELAY, tmp_path)

    # kill all units "simultaneously"
    await asyncio.gather(
        *[
            kill_unit_process(
                ops_test, substrate, unit.name, kill_code="SIGKILL", app_name=app_name
            )
            for unit in ops_test.model.applications[app_name].units
        ]
    )

    # This test serves to verify behavior when all replicas are down at the same time that when
    # they come back online they operate as expected. This check verifies that we meet the criteria
    # of all replicas being down at the same time.
    assert await all_db_processes_down(
        ops_test, substrate, app_name=app_name
    ), "Not all units down at the same time."

    # sleep for twice the median election time and the restart delay
    time.sleep(MEDIAN_REELECTION_TIME * 2 + RESTART_DELAY)

    # verify all units are up and running
    for unit in ops_test.model.applications[app_name].units:
        ip_address = await get_address_of_unit(
            ops_test, substrate, get_unit_id(unit.name), app_name
        )
        assert await mongod_ready(
            ops_test, ip_address, app_name=app_name
        ), f"unit {unit.name} not restarted after cluster crash."

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    time.sleep(5)
    more_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    assert more_writes > writes, "writes not continuing to DB"

    # verify presence of primary, replica set member configuration, and number of primaries
    await verify_replica_set_configuration(ops_test, substrate, app_name=app_name)

    # verify that no writes to the db were missed
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_full_cluster_restart(
    ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db, reset_restart_delay, tmp_path
):
    app_name = await get_app_name(ops_test)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    other_unit = await replica_set_secondary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert other_unit, "No secondary unit found"

    # update all units to have a new RESTART_DELAY,  Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    for unit in ops_test.model.applications[app_name].units:
        await update_restart_delay(ops_test, substrate, unit, RESTART_DELAY, tmp_path)

    # kill all units "simultaneously"
    await asyncio.gather(
        *[
            kill_unit_process(
                ops_test, substrate, unit.name, kill_code="SIGTERM", app_name=app_name
            )
            for unit in ops_test.model.applications[app_name].units
        ]
    )

    # This test serves to verify behavior when all replicas are down at the same time that when
    # they come back online they operate as expected. This check verifies that we meet the criteria
    # of all replicas being down at the same time.
    assert await all_db_processes_down(
        ops_test, substrate, app_name=app_name
    ), "Not all units down at the same time."

    # sleep for twice the median election time and the restart delay
    time.sleep(MEDIAN_REELECTION_TIME * 2 + RESTART_DELAY)

    # verify all units are up and running
    for unit in ops_test.model.applications[app_name].units:
        ip_address = await get_address_of_unit(
            ops_test, substrate, get_unit_id(unit.name), app_name
        )
        assert await mongod_ready(
            ops_test, ip_address, app_name=app_name
        ), f"unit {unit.name} not restarted after cluster crash."

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    time.sleep(5)
    more_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    assert more_writes > writes, "writes not continuing to DB"

    # verify presence of primary, replica set member configuration, and number of primaries
    await verify_replica_set_configuration(ops_test, substrate, app_name=app_name)

    # verify that no writes to the db were missed
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_network_cut(ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db):
    # locate primary unit
    app_name = await get_app_name(ops_test)
    ip_addresses = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )

    assert primary, "No primary unit found"

    other_unit = await replica_set_secondary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert other_unit, "No secondary unit found"

    all_units = ops_test.model.applications[app_name].units

    model_name = ops_test.model.info.name

    primary_hostname = await unit_hostname(ops_test, primary.name)
    primary_unit_ip = await get_unit_ip(ops_test, primary.name)

    # before cutting network verify that connection is possible
    assert await mongod_ready(
        ops_test, primary_unit_ip, app_name=app_name
    ), f"Connection to host {primary_unit_ip} is not possible"

    cut_network_from_unit(ops_test, substrate, primary_hostname)

    # verify machine is not reachable from peer units
    for unit in set(all_units) - {primary}:
        hostname = await unit_hostname(ops_test, unit.name)
        assert not is_machine_reachable_from(
            hostname, primary_hostname
        ), "unit is reachable from peer"

    # verify machine is not reachable from controller
    controller = await get_controller_machine(ops_test)
    assert not is_machine_reachable_from(
        controller, primary_hostname
    ), "unit is reachable from controller"

    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    time.sleep(5)
    more_writes = await count_writes(ops_test, substrate, app_name=app_name, unit=other_unit)
    assert more_writes > writes, "writes not continuing to DB"

    # verify that a new primary gets elected
    new_primary = await replica_set_primary(
        ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
    )
    assert new_primary.name != primary.name

    # verify that no writes to the db were missed
    total_expected_writes = await verify_writes(ops_test, substrate, app_name)

    # restore network connectivity to old primary
    restore_network_for_unit(ops_test, substrate, primary_hostname)

    # wait until network is reestablished for the unit
    await wait_network_restore(
        ops_test, substrate, model_name, app_name, primary_hostname, primary_unit_ip
    )

    # self healing is performed with update status hook
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=1000)

    # verify we have connection to the old primary
    new_ip = instance_ip(model_name, primary_hostname)
    assert await mongod_ready(
        ops_test, new_ip, app_name=app_name
    ), f"Connection to host {new_ip} is not possible"

    # verify presence of primary, replica set member configuration, and number of primaries
    await verify_replica_set_configuration(ops_test, substrate, app_name=app_name)

    # verify that no writes were missed.
    secondary_writes = await count_writes(ops_test, substrate, app_name, unit=primary)
    assert (
        total_expected_writes == secondary_writes
    ), "secondary not up to date with the cluster after restarting."


@pytest.mark.abort_on_fail
@pytest.mark.unstable
async def test_scale_up_down(ops_test: OpsTest, substrate: Substrate, continuous_writes_to_db):
    """Scale up and down the application and verify the replica set is healthy."""
    app_name = await get_app_name(ops_test)
    scales = [3, -3, 4, -4, 5, -5]
    for count in scales:
        await scale_application(ops_test, substrate, app_name, count=count, wait=True)
        ip_addresses = [
            await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
            for unit in ops_test.model.applications[app_name].units
        ]
        primary = await replica_set_primary(
            ops_test, substrate, app_name=app_name, replica_set_hosts=ip_addresses
        )
        assert primary is not None, "Replica set has no primary"

    await verify_writes(ops_test, substrate, app_name)
