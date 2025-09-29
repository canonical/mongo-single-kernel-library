#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from ...helpers.backups import (
    NEW_CLUSTER,
    S3_APP_NAME,
    S3_ENDPOINT,
    count_failed_backups,
    count_logical_backups,
    create_and_verify_backup,
    insert_unwanted_data,
    set_credentials,
)
from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    OPERATOR_USERNAME,
    TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
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
from ...helpers.types import Substrate

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
    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="edge")

    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


@pytest.mark.abort_on_fail
async def test_blocked_missing_config(ops_test: OpsTest, substrate: Substrate) -> None:
    """Test that when charm is missing pbm information that it reports that."""
    db_app_name = await get_app_name(ops_test)
    await ops_test.model.integrate(S3_APP_NAME, db_app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, S3_ENDPOINT, S3_ENDPOINT) is True,
        timeout=TIMEOUT,
    )

    await wait_for_mongodb_units_blocked(
        ops_test, substrate, db_app_name, status="s3 configurations missing.", timeout=300
    )


@pytest.mark.abort_on_fail
async def test_blocked_incorrect_creds(
    ops_test: OpsTest, substrate: Substrate, cloud_configs
) -> None:
    """Verifies that the charm goes into blocked status when s3 creds are incorrect."""
    db_app_name = await get_app_name(ops_test)
    s3_integrator_unit = ops_test.model.applications[S3_APP_NAME].units[0]

    # set incorrect s3 credentials
    configuration_parameters, _ = cloud_configs["AWS"]

    # apply new configuration options
    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)

    # Set invalid credentials
    parameters = {"access-key": "user", "secret-key": "doesnt-exist"}
    action = await s3_integrator_unit.run_action(action_name="sync-s3-credentials", **parameters)
    await action.wait()

    # verify that Charmed MongoDB is blocked and reports incorrect credentials
    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], status="active")

    await wait_for_mongodb_units_blocked(
        ops_test, substrate, db_app_name, status="s3 credentials are incorrect.", timeout=300
    )


@pytest.mark.abort_on_fail
async def test_ready_correct_conf(ops_test: OpsTest, cloud_configs) -> None:
    """Verifies charm goes into active status when s3 config and creds options are correct."""
    db_app_name = await get_app_name(ops_test)
    s3_integrator_unit = ops_test.model.applications[S3_APP_NAME].units[0]

    _, credentials = cloud_configs["AWS"]
    action = await s3_integrator_unit.run_action(action_name="sync-s3-credentials", **credentials)
    await action.wait()

    # after applying correct config options and creds the applications should both be active
    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], status="active", timeout=TIMEOUT)
    await ops_test.model.wait_for_idle(
        apps=[db_app_name], status="active", timeout=TIMEOUT, idle_period=60
    )


@pytest.mark.abort_on_fail
async def test_create_and_list_backups(ops_test: OpsTest, cloud_configs) -> None:
    """Tests that we can create a backup, and that it is listed in the backups."""
    db_app_name = await get_app_name(ops_test)
    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)
    await set_credentials(ops_test, cloud_configs, cloud="AWS")
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
        for attempt in Retrying(stop=stop_after_delay(20), wait=wait_fixed(3)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1
    except RetryError:
        assert backups == 1, "Backup not created."


@pytest.mark.abort_on_fail
async def test_multi_backup(ops_test: OpsTest, continuous_writes_to_db, cloud_configs) -> None:
    """With writes in the DB test creating a backup while another one is running.

    Note that before creating the second backup we change the bucket and change the s3 storage
    from AWS to GCP. This test verifies that the first backup in AWS is made, the second backup
    in GCP is made, and that before the second backup is made that pbm correctly resyncs.
    """
    db_app_name = await get_app_name(ops_test)

    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)

    # create first backup once ready
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    action = await leader_unit.run_action(action_name="create-backup")
    first_backup = await action.wait()
    assert first_backup.status == "completed", "First backup not started."

    # while first backup is running change access key, secret keys, and bucket name
    # for GCP
    await set_credentials(ops_test, cloud_configs, cloud="GCP")

    # change to GCP configs and wait for PBM to resync
    configuration_parameters, _ = cloud_configs["GCP"]
    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # create a backup as soon as possible. might not be immediately possible since only one backup
    # can happen at a time.
    try:
        for attempt in Retrying(stop=stop_after_delay(40), wait=wait_fixed(5)):
            with attempt:
                action = await leader_unit.run_action(action_name="create-backup")
                second_backup = await action.wait()
                assert second_backup.status == "completed"
    except RetryError:
        assert second_backup.status == "completed", "Second backup not started."

    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore before checking, wait for Charmed MongoDB to finish creating the
    # backup
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # verify that backups was made in GCP bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1, "Backup not created in bucket on GCP."
    except RetryError:
        assert backups == 1, "Backup not created in first bucket on GCP."

    # set AWS credentials, set configs for s3 storage, and wait to resync
    await set_credentials(ops_test, cloud_configs, cloud="AWS")
    configuration_parameters, _ = cloud_configs["AWS"]

    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)
    await asyncio.gather(
        ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15),
    )

    # verify that backups was made on the AWS bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 2, "Backup not created in bucket on AWS."
    except RetryError:
        assert backups == 2, "Backup not created in bucket on AWS."


@pytest.mark.abort_on_fail
async def test_restore(ops_test: OpsTest, add_writes_to_db, substrate: Substrate) -> None:
    """Simple backup tests that verifies that writes are correctly restored."""
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
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == prev_backups + 1, "Backup not created."
    except RetryError:
        assert backups == prev_backups + 1, "Backup not created."

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

    await asyncio.gather(
        ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15),
    )

    # verify all writes are present
    try:
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(20)):
            with attempt:
                number_writes_restored = await count_writes(
                    ops_test, substrate, db_app_name, leader_unit
                )
                assert number_writes == number_writes_restored, "writes not correctly restored"
    except RetryError:
        assert number_writes == number_writes_restored, "writes not correctly restored"


@pytest.mark.parametrize("cloud_provider", ["AWS", "GCP"])
async def test_restore_new_cluster(
    ops_test: OpsTest,
    substrate: Substrate,
    cloud_configs,
    mongodb_charm: str,
    mongod_resource,
    cloud_provider,
    add_writes_to_db,
):
    # configure test for the cloud provider
    db_app_name = await get_app_name(ops_test)
    new_cluster_app_name = f"{NEW_CLUSTER}-{cloud_provider.lower()}"

    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)

    await set_credentials(ops_test, cloud_configs, cloud=cloud_provider)

    configuration_parameters, _ = cloud_configs[cloud_provider]

    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)
    await asyncio.gather(
        ops_test.model.wait_for_idle(apps=[S3_APP_NAME], status="active"),
        ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15),
    )

    # create a backup
    writes_in_old_cluster = await count_writes(ops_test, substrate, db_app_name, leader_unit)

    assert writes_in_old_cluster > 0, "old cluster has no writes."

    await create_and_verify_backup(ops_test, db_app_name)

    # save old password, since after restoring we will need this password to authenticate.
    old_password = await get_password(ops_test, username=OPERATOR_USERNAME, app_name=db_app_name)

    # deploy a new cluster with a different name
    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=new_cluster_app_name,
        num_units=len(UNIT_IDS),
    )

    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[new_cluster_app_name],
            status="active",
            idle_period=15,
            timeout=DEPLOYMENT_TIMEOUT,
        ),
    )

    await set_password(
        ops_test, username=OPERATOR_USERNAME, password=old_password, app_name=new_cluster_app_name
    )
    await ops_test.model.wait_for_idle(
        apps=[new_cluster_app_name], status="active", timeout=TIMEOUT
    )

    # relate to s3 - s3 has the necessary configurations
    await ops_test.model.integrate(S3_APP_NAME, new_cluster_app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, S3_ENDPOINT, S3_ENDPOINT) is True,
        timeout=TIMEOUT,
    )

    # wait for new cluster to sync
    await asyncio.gather(
        ops_test.model.wait_for_idle(apps=[new_cluster_app_name], status="active", idle_period=15),
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
async def test_update_backup_password(ops_test: OpsTest) -> None:
    """Verifies that after changing the backup password the pbm tool is updated and functional."""
    db_app_name = await get_app_name(ops_test)

    db_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)

    # wait for charm to be idle before setting password
    await asyncio.gather(
        ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15),
    )

    await set_password(ops_test, username="backup", password="new-password", app_name=db_app_name)

    # wait for charm to be idle after setting password
    (ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15),)

    # verify we still have connection to pbm via creating a backup
    action = await db_unit.run_action(action_name="create-backup")
    backup_result = await action.wait()
    logger.info(f"Create backup result {backup_result.results=}")
    assert "backup started" in backup_result.results["backup-status"], "backup didn't start"
