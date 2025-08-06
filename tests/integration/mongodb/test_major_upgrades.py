#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import time
from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

from single_kernel_mongo.utils.mongodb_users import CharmUsers

from ..helpers.backups import S3_APP_NAME, count_logical_backups
from ..helpers.common import (
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    deploy_application,
    deploy_charm,
    find_unit,
    get_password,
    get_unit_id,
    relate_mongodb_and_application,
    set_password,
    start_continous_writes,
    stop_continous_writes,
)
from ..helpers.types import Substrate
from ..helpers.upgrade import set_fcv

MONGODB_SIX = "mongodb-six"
MONGODB_SEVEN = "mongodb-seven"
MONGODB_EIGHT = "mongodb-eight"

logger = getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_deploy_mongodb_6(
    ops_test: OpsTest,
    substrate: Substrate,
    application_path: str,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == "lxd" else "mongodb-k8s"
    await deploy_charm(
        ops_test,
        mongodb_charm_name,
        substrate,
        app_name=MONGODB_SIX,
        mongod_resource={},  # unused
        channel="6/edge",
        num_units=3,
        series="jammy",
    )
    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="edge", config=storage_config)

    await ops_test.model.wait_for_idle(
        apps=[MONGODB_SIX, S3_APP_NAME],
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )

    s3_unit = ops_test.model.applications[S3_APP_NAME].units[0]
    set_credentials_action = await s3_unit.run_action(
        "sync-s3-credentials",
        **storage_credentials,
    )
    await set_credentials_action.wait()

    application_name = "application"
    await deploy_application(ops_test, application_path=application_path, app_name=application_name)
    await relate_mongodb_and_application(ops_test, MONGODB_SIX, application_name)

    await start_continous_writes(ops_test, client_app_name=application_name)
    time.sleep(20)
    await stop_continous_writes(ops_test, client_app_name=application_name)


async def test_backup_mongodb_6(ops_test: OpsTest, s3_bucket):
    """Relates, takes a backup."""
    await ops_test.model.integrate(S3_APP_NAME, MONGODB_SIX)
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, MONGODB_SIX], timeout=TIMEOUT, status="active"
    )
    # bucket should be created when integrating both
    assert s3_bucket.meta.client.head_bucket(Bucket=s3_bucket.name)

    # create a backup in the AWS bucket
    leader_unit = await find_unit(ops_test, leader=True, app_name=MONGODB_SIX)

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


@pytest.mark.abort_on_fail
async def test_deploy_mongodb_7(
    ops_test: OpsTest,
    substrate: Substrate,
):
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == "lxd" else "mongodb-k8s"
    await deploy_charm(
        ops_test,
        mongodb_charm_name,
        substrate,
        app_name=MONGODB_SEVEN,
        mongod_resource={},  # unused
        channel="8-transition/edge",
        num_units=3,
    )

    await ops_test.model.wait_for_idle(
        apps=[MONGODB_SEVEN],
        status="active",
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )

    await ops_test.model.integrate(S3_APP_NAME, MONGODB_SEVEN)
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, MONGODB_SEVEN], timeout=TIMEOUT, status="active"
    )

    for user in CharmUsers:
        password = await get_password(ops_test, username=user, app_name=MONGODB_SIX)
        leader_unit = await find_unit(ops_test, leader=True, app_name=MONGODB_SEVEN)
        await set_password(
            ops_test,
            unit_id=get_unit_id(leader_unit.name),
            username=user,
            password=password,
            app_name=MONGODB_SEVEN,
        )

    await ops_test.model.wait_for_idle(apps=[MONGODB_SEVEN], timeout=TIMEOUT, status="active")


@pytest.mark.abort_on_fail
async def test_restore_backup_6_to_7(
    ops_test: OpsTest,
    substrate: Substrate,
):
    leader_unit = await find_unit(ops_test, leader=True, app_name=MONGODB_SIX)
    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    backup_id = most_recent_backup.split()[0]

    await set_fcv(ops_test, substrate, MONGODB_SEVEN, "6.0")

    leader_unit_seven = await find_unit(ops_test, leader=True, app_name=MONGODB_SEVEN)
    action = await leader_unit_seven.run_action(action_name="restore", **{"backup-id": backup_id})
    restore = await action.wait()

    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    await ops_test.model.wait_for_idle(apps=[MONGODB_SEVEN], timeout=TIMEOUT, status="active")

    await set_fcv(ops_test, substrate, MONGODB_SEVEN, "7.0")


@pytest.mark.abort_on_fail
async def test_backup_mongodb_7(
    ops_test: OpsTest,
):
    # create a backup in the AWS bucket
    leader_unit = await find_unit(ops_test, leader=True, app_name=MONGODB_SEVEN)

    action = await leader_unit.run_action(action_name="create-backup")
    second_backup = await action.wait()
    assert second_backup.status == "completed", "Second backup not started."

    # verify that backup was made on the bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 2, "Backup not created."
    except RetryError:
        assert backups == 2, "Backup not created."


@pytest.mark.abort_on_fail
async def test_deploy_mongodb_8(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict,
):
    """Build and deploy one unit of MongoDB."""
    await deploy_charm(
        ops_test,
        mongodb_charm,
        substrate,
        app_name=MONGODB_EIGHT,
        mongod_resource=mongod_resource,
        num_units=3,
    )

    await ops_test.model.wait_for_idle(
        apps=[MONGODB_EIGHT],
        status="active",
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )

    await ops_test.model.integrate(S3_APP_NAME, MONGODB_SEVEN)
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, MONGODB_EIGHT], timeout=TIMEOUT, status="active"
    )

    for user in CharmUsers:
        password = await get_password(ops_test, username=user, app_name=MONGODB_SIX)
        leader_unit = await find_unit(ops_test, leader=True, app_name=MONGODB_EIGHT)
        await set_password(
            ops_test,
            unit_id=get_unit_id(leader_unit.name),
            username=user,
            password=password,
            app_name=MONGODB_EIGHT,
        )

    await ops_test.model.wait_for_idle(apps=[MONGODB_EIGHT], timeout=TIMEOUT, status="active")


@pytest.mark.abort_on_fail
async def test_restore_backup_7_to_8(
    ops_test: OpsTest,
    substrate: Substrate,
):
    leader_unit = await find_unit(ops_test, leader=True, app_name=MONGODB_SEVEN)

    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    backup_id = most_recent_backup.split()[0]

    await set_fcv(ops_test, substrate, MONGODB_EIGHT, "7.0")

    leader_unit_eight = await find_unit(ops_test, leader=True, app_name=MONGODB_EIGHT)
    action = await leader_unit_eight.run_action(action_name="restore", **{"backup-id": backup_id})
    restore = await action.wait()

    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    await ops_test.model.wait_for_idle(apps=[MONGODB_EIGHT], timeout=TIMEOUT, status="active")

    await set_fcv(ops_test, substrate, MONGODB_EIGHT, "8.0")
