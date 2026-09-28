#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from tests.integration.helpers.backups import (
    GCS_APP_NAME,
    GCS_ENDPOINT,
    NEW_CLUSTER,
    CloudConfigs,
    configure_gcs,
    count_failed_backups,
    count_logical_backups,
    create_and_verify_backup,
    insert_unwanted_data,
)
from tests.integration.helpers.common import (
    CHARMED_BACKUP_USERNAME,
    CHARMED_OPERATOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    check_status_detail,
    count_writes,
    deploy_charm,
    destroy_cluster,
    find_unit,
    get_app_name,
    get_password,
    is_relation_joined,
    set_password,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_deploy_charms(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
):
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, substrate, app_name, len(UNIT_IDS))
        return

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
    )
    # deploy the GCS integrator charm
    await ops_test.model.deploy(GCS_APP_NAME, channel="1/edge")

    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


@pytest.mark.abort_on_fail
async def test_blocked_missing_config(ops_test: OpsTest, substrate: Substrate) -> None:
    """Test that when charm is missing pbm information that it reports that."""
    db_app_name = await get_app_name(ops_test)
    await ops_test.model.integrate(GCS_APP_NAME, db_app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, GCS_ENDPOINT, GCS_ENDPOINT) is True,
        timeout=TIMEOUT,
    )

    await wait_for_mongodb_units_blocked(
        ops_test,
        substrate,
        db_app_name,
        status="Missing configurations in the gcs-credentials relation.",
        timeout=300,
    )

    await check_status_detail(
        ops_test,
        db_app_name,
        status="blocked",
        message="Missing configurations in the gcs-credentials relation.",
    )


@pytest.mark.abort_on_fail
async def test_blocked_incorrect_creds(
    ops_test: OpsTest,
    substrate: Substrate,
    cloud_configs: CloudConfigs,
) -> None:
    """Verifies that the charm goes into blocked status when GCS creds are incorrect."""
    db_app_name = await get_app_name(ops_test)
    # set incorrect GCS credentials
    configuration_parameters, _ = cloud_configs["GCS"]

    await configure_gcs(
        ops_test,
        configuration_parameters,
        {"secret-key": '{"client_email": "invalid", "private_key": "invalid"}'},
    )

    # apply new configuration options
    await wait_for_mongodb_units_blocked(
        ops_test, substrate, db_app_name, status="Incorrect GCS credentials.", timeout=300
    )


@pytest.mark.abort_on_fail
async def test_ready_correct_conf(ops_test: OpsTest, cloud_configs: CloudConfigs) -> None:
    """Verifies charm goes into active status when GCS config and creds options are correct."""
    db_app_name = await get_app_name(ops_test)

    configuration_parameters, credentials = cloud_configs["GCS"]
    await configure_gcs(ops_test, configuration_parameters, credentials)

    # after applying correct config options and creds the applications should both be active
    await ops_test.model.wait_for_idle(apps=[GCS_APP_NAME], status="active", timeout=TIMEOUT)
    await ops_test.model.wait_for_idle(
        apps=[db_app_name], status="active", timeout=TIMEOUT, idle_period=60
    )


@pytest.mark.abort_on_fail
async def test_create_and_list_backups(ops_test: OpsTest, cloud_configs: CloudConfigs) -> None:
    """Tests that we can create a backup, and that it is listed in the backups."""
    db_app_name = await get_app_name(ops_test)
    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)
    # verify backup list works
    logger.info("!!!!! test_create_and_list_backups >>>  %s", leader_unit)
    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    logger.info("!!!!! test_create_and_list_backups >>>  %s", list_result.results)
    backups = list_result.results["backups"]
    assert backups, "backups not outputted"

    # verify backup is started
    action = await leader_unit.run_action(action_name="create-backup")
    backup_result = await action.wait()
    logger.info(f"Create backup result {backup_result.results=}")
    assert "backup started" in backup_result.results["backup-status"], "backup didn't start"

    # verify backup is present in the list of backups
    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore we should retry listing the backup several times
    try:
        for attempt in Retrying(stop=stop_after_delay(30), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1
    except RetryError:
        assert backups == 1, "Backup not created."


@pytest.mark.abort_on_fail
async def test_restore(ops_test: OpsTest, add_writes_to_db, substrate: Substrate) -> None:
    """Simple backup tests that verifies that writes are correctly restored."""
    number_writes_restored = -1
    db_app_name = await get_app_name(ops_test)
    # create a backup in the AWS bucket
    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)
    # count total writes
    number_writes = await count_writes(ops_test, substrate, db_app_name, leader_unit)
    assert number_writes > 0, "no writes to backup"

    prev_backups = await count_logical_backups(leader_unit)
    action = await leader_unit.run_action(action_name="create-backup")
    first_backup = await action.wait()
    assert first_backup.status == "completed", "First backup not started."

    # verify that backup was made on the bucket
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == prev_backups + 1, "Backup not created."
    except RetryError:
        assert backups == prev_backups + 1, "Backup not created."

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # add writes to be cleared after restoring the backup. Note these are written to the same
    # collection that was backed up.
    await insert_unwanted_data(ops_test, substrate, db_app_name, leader_unit)
    new_number_of_writes = await count_writes(ops_test, substrate, db_app_name, leader_unit)
    assert new_number_of_writes > number_writes, "No writes to be cleared after restoring."

    # find most recent backup id and restore
    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]
    backup_id = most_recent_backup.split()[0]
    action = await leader_unit.run_action(action_name="restore", **{"backup-id": backup_id})
    restore = await action.wait()
    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # verify all writes are present
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
            with attempt:
                number_writes_restored = await count_writes(
                    ops_test, substrate, db_app_name, leader_unit
                )
                assert number_writes == number_writes_restored, "writes not correctly restored"
    except RetryError:
        assert number_writes == number_writes_restored, "writes not correctly restored"


async def test_restore_new_cluster(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    add_writes_to_db,
):
    # configure test for the cloud provider
    db_app_name = await get_app_name(ops_test)
    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)
    new_cluster_app_name = f"{NEW_CLUSTER}-gcs"
    await asyncio.gather(
        ops_test.model.wait_for_idle(apps=[GCS_APP_NAME], status="active"),
        ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15),
    )

    # create a backup
    writes_in_old_cluster = await count_writes(ops_test, substrate, db_app_name, leader_unit)

    assert writes_in_old_cluster > 0, "old cluster has no writes."

    await create_and_verify_backup(ops_test, db_app_name)

    # save old password, since after restoring we will need this password to authenticate.
    old_password = await get_password(
        ops_test, username=CHARMED_OPERATOR_USERNAME, app_name=db_app_name
    )

    # deploy a new cluster with a different name
    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=new_cluster_app_name,
        num_units=len(UNIT_IDS),
    )

    await ops_test.model.wait_for_idle(
        apps=[new_cluster_app_name],
        status="active",
        idle_period=15,
        timeout=DEPLOYMENT_TIMEOUT,
    )

    await set_password(
        ops_test,
        username=CHARMED_OPERATOR_USERNAME,
        password=old_password,
        app_name=new_cluster_app_name,
    )
    await ops_test.model.wait_for_idle(
        apps=[new_cluster_app_name], status="active", timeout=TIMEOUT
    )

    # relate to GCS - GCS has the necessary configurations
    await ops_test.model.integrate(GCS_APP_NAME, new_cluster_app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, GCS_ENDPOINT, GCS_ENDPOINT) is True,
        timeout=TIMEOUT,
    )

    # wait for new cluster to sync
    await ops_test.model.wait_for_idle(
        apps=[new_cluster_app_name], status="active", idle_period=15, timeout=TIMEOUT
    )

    # verify that the listed backups from the old cluster are not listed as failed.
    db_unit = await find_unit(ops_test, leader=True, app_name=new_cluster_app_name)
    assert await count_failed_backups(db_unit) == 0, "Backups from old cluster are listed as failed"

    # find most recent backup id and restore
    action = await db_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]
    backup_id = most_recent_backup.split()[0]

    # Restore the backup
    action = await db_unit.run_action(action_name="restore", **{"backup-id": backup_id})
    restore = await action.wait()
    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    # verify all writes are present
    try:
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(20)):
            with attempt:
                writes_in_new_cluster = await count_writes(
                    ops_test, substrate, new_cluster_app_name, db_unit
                )
                assert (
                    writes_in_new_cluster == writes_in_old_cluster
                ), "new cluster writes do not match old cluster writes after restore"
    except RetryError:
        assert (
            writes_in_new_cluster == writes_in_old_cluster
        ), "new cluster writes do not match old cluster writes after restore"

    await destroy_cluster(ops_test, applications=[new_cluster_app_name])


@pytest.mark.abort_on_fail
async def test_update_backup_password(
    ops_test: OpsTest,
) -> None:
    """Verifies that after changing the backup password the pbm tool is updated and functional."""
    db_app_name = await get_app_name(ops_test)
    db_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)

    # wait for charm to be idle before setting password
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    await set_password(
        ops_test, username=CHARMED_BACKUP_USERNAME, password="new-password", app_name=db_app_name
    )

    # wait for charm to be idle after setting password
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # verify we still have connection to pbm via creating a backup
    action = await db_unit.run_action(action_name="create-backup")
    backup_result = await action.wait()
    logger.info(f"Create backup result {backup_result.results=}")
    assert "backup started" in backup_result.results["backup-status"], "backup didn't start"
