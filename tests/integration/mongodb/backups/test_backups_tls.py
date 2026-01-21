#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

from ...helpers.backups import (
    S3_APP_NAME,
    S3_ENDPOINT,
    count_logical_backups,
    insert_unwanted_data,
)
from ...helpers.common import (
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
from ...helpers.types import Substrate

logger = getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_deploy_charms(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
    # workaround for https://bugs.launchpad.net/snapd/+bug/2127244
    await ops_test.model.set_config({"image-stream": "daily"})
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, substrate, app_name, len(UNIT_IDS))
        return

    app_name = base_app_name

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
    )
    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="1/edge")

    logger.info(f"Configure {S3_APP_NAME}")
    await ops_test.model.applications[S3_APP_NAME].set_config(storage_config)

    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], timeout=DEPLOYMENT_TIMEOUT)

    s3_unit = ops_test.model.applications[S3_APP_NAME].units[0]
    set_credentials_action = await s3_unit.run_action(
        "sync-s3-credentials",
        **storage_credentials,
    )
    await set_credentials_action.wait()

    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, app_name], timeout=DEPLOYMENT_TIMEOUT, status="active"
    )


@pytest.mark.abort_on_fail
async def test_s3_integration(ops_test: OpsTest, substrate: Substrate, s3_bucket) -> None:
    """Integrate charm and s3-integrator."""
    app_name = await get_app_name(ops_test)
    await ops_test.model.integrate(S3_APP_NAME, app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, S3_ENDPOINT, S3_ENDPOINT) is True,
        timeout=TIMEOUT,
    )

    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, app_name], timeout=TIMEOUT, status="active"
    )
    # bucket should be created when integrating both
    assert s3_bucket.meta.client.head_bucket(Bucket=s3_bucket.name)


@pytest.mark.abort_on_fail
async def test_backup_restore(ops_test: OpsTest, substrate: Substrate, add_writes_to_db) -> None:
    """Simple backup tests that verifies that writes are correctly restored."""
    db_app_name = await get_app_name(ops_test)
    # create a backup in the AWS bucket
    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)
    # count total writes
    number_writes = await count_writes(ops_test, substrate, db_app_name, leader_unit)
    assert number_writes > 0, "no writes to backup"

    # create first backup once ready
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    action = await leader_unit.run_action(action_name="create-backup")
    first_backup = await action.wait()
    assert first_backup.status == "completed", "First backup not started."

    # verify that backup was made on the bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1, "Backup not created."
    except RetryError:
        assert backups == 1, "Backup not created."

    # add writes to be cleared after restoring the backup. Note these are written to the same
    # collection that was backed up.
    await insert_unwanted_data(ops_test, substrate, db_app_name, leader_unit)
    new_number_of_writes = await count_writes(ops_test, substrate, db_app_name, leader_unit)
    assert new_number_of_writes > number_writes, "No writes to be cleared after restoring."

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
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(20)):
            with attempt:
                number_writes_restored = await count_writes(
                    ops_test, substrate, db_app_name, leader_unit
                )
                assert number_writes == number_writes_restored, "writes not correctly restored"
    except RetryError:
        assert number_writes == number_writes_restored, "writes not correctly restored"
