#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from tests.integration.helpers.backups import (
    S3_APP_NAME,
    S3_ENDPOINT,
    CloudConfigs,
    count_logical_backups,
    insert_unwanted_data,
)
from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    count_writes,
    deploy_charm,
    find_unit,
    get_app_name,
    is_relation_joined,
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
    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="edge")

    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


@pytest.mark.abort_on_fail
async def test_ready_correct_conf(ops_test: OpsTest, cloud_configs: CloudConfigs) -> None:
    """Verifies charm goes into active status when s3 config and creds options are correct."""
    db_app_name = await get_app_name(ops_test)
    s3_integrator_unit = ops_test.model.applications[S3_APP_NAME].units[0]

    configuration_parameters, credentials = cloud_configs["GCP"]

    await ops_test.model.integrate(S3_APP_NAME, db_app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, S3_ENDPOINT, S3_ENDPOINT) is True,
        timeout=TIMEOUT,
    )

    # apply new configuration options
    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)
    action = await s3_integrator_unit.run_action(action_name="sync-s3-credentials", **credentials)
    await action.wait()

    # after applying correct config options and creds the applications should both be active
    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], status="active", timeout=TIMEOUT)
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
        for attempt in Retrying(stop=stop_after_delay(20), wait=wait_fixed(3)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1
    except RetryError:
        assert backups == 1, "Backup not created."


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
