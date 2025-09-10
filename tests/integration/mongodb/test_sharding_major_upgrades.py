#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import time
from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

from single_kernel_mongo.utils.mongodb_users import CharmUsernames
from tests.integration.helpers.sharding import (
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.upgrade import get_password_action, set_fcv, set_password_action

from ..helpers.backups import S3_APP_NAME, count_logical_backups
from ..helpers.common import (
    DEPLOYMENT_TIMEOUT,
    MONGOS_PORT,
    TIMEOUT,
    count_writes,
    deploy_application,
    find_unit,
    get_password,
    get_unit_id,
    mongodb_uri,
    set_password,
    start_continous_writes,
    stop_continous_writes,
)
from ..helpers.types import Substrate

CONFIG_SERVER_SIX = "config-server-six"
SHARD_ONE_SIX = "shard-one-six"
SHARD_TWO_SIX = "shard-two-six"

CONFIG_SERVER_SEVEN = "config-server-seven"
SHARD_ONE_SEVEN = "shard-one-seven"
SHARD_TWO_SEVEN = "shard-two-seven"

CONFIG_SERVER_EIGHT = "config-server-eight"
SHARD_ONE_EIGHT = "shard-one-eight"
SHARD_TWO_EIGHT = "shard-two-eight"

logger = getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_deploy_mongodb_6(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict,
    application_path: str,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
    """Build and deploy one unit of MongoDB."""
    num_units_cluster_config = {
        CONFIG_SERVER_SIX: 1,
        SHARD_ONE_SIX: 1,
        SHARD_TWO_SIX: 1,
    }
    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongod_resource,
        num_units_cluster_config=num_units_cluster_config,
        channel="6/edge",
        config_server_name=CONFIG_SERVER_SIX,
        shard_one_name=SHARD_ONE_SIX,
        shard_two_name=SHARD_TWO_SIX,
        series="jammy",
    )
    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="edge", config=storage_config)

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_SIX, SHARD_ONE_SIX, SHARD_TWO_SIX, S3_APP_NAME],
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )

    await integrate_sharding_components(
        ops_test,
        config_server_name=CONFIG_SERVER_SIX,
        shard_one_name=SHARD_ONE_SIX,
        shard_two_name=SHARD_TWO_SIX,
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_SIX, SHARD_ONE_SIX, SHARD_TWO_SIX],
        timeout=DEPLOYMENT_TIMEOUT,
        status="active",
        idle_period=20,
        raise_on_blocked=False,
        raise_on_error=False,
    )

    s3_unit = ops_test.model.applications[S3_APP_NAME].units[0]
    set_credentials_action = await s3_unit.run_action(
        "sync-s3-credentials",
        **storage_credentials,
    )
    await set_credentials_action.wait()

    application_name = "application"
    await deploy_application(ops_test, application_path=application_path, app_name=application_name)

    mongos_uri: str = await mongodb_uri(
        ops_test, substrate, app_name=CONFIG_SERVER_SIX, port=MONGOS_PORT
    )
    await ops_test.model.applications[application_name].set_config({"mongos-uri": mongos_uri})

    await start_continous_writes(ops_test, client_app_name=application_name)
    time.sleep(20)
    await stop_continous_writes(ops_test, client_app_name=application_name)


async def test_backup_mongodb_6(ops_test: OpsTest, s3_bucket):
    """Relates, takes a backup."""
    await ops_test.model.integrate(S3_APP_NAME, CONFIG_SERVER_SIX)
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, CONFIG_SERVER_SIX], timeout=TIMEOUT, status="active"
    )
    # bucket should be created when integrating both
    assert s3_bucket.meta.client.head_bucket(Bucket=s3_bucket.name)

    # create a backup in the AWS bucket
    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_SIX)

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
async def test_deploy_mongodb_7(ops_test: OpsTest, substrate: Substrate, mongodb_charm: str):
    """Build and deploy one unit of MongoDB."""
    num_units_cluster_config = {
        CONFIG_SERVER_SEVEN: 1,
        SHARD_ONE_SEVEN: 1,
        SHARD_TWO_SEVEN: 1,
    }
    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        {},
        num_units_cluster_config=num_units_cluster_config,
        channel="8-transition/edge",
        config_server_name=CONFIG_SERVER_SEVEN,
        shard_one_name=SHARD_ONE_SEVEN,
        shard_two_name=SHARD_TWO_SEVEN,
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_SEVEN, SHARD_ONE_SEVEN, SHARD_TWO_SEVEN],
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )

    await integrate_sharding_components(
        ops_test,
        config_server_name=CONFIG_SERVER_SEVEN,
        shard_one_name=SHARD_ONE_SEVEN,
        shard_two_name=SHARD_TWO_SEVEN,
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_SEVEN, SHARD_ONE_SEVEN, SHARD_TWO_SEVEN],
        timeout=DEPLOYMENT_TIMEOUT,
        status="active",
        idle_period=20,
        raise_on_blocked=False,
        raise_on_error=False,
    )

    await ops_test.model.integrate(S3_APP_NAME, CONFIG_SERVER_SEVEN)

    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, CONFIG_SERVER_SEVEN], timeout=TIMEOUT, status="active"
    )

    for username in CharmUsernames:
        password = await get_password_action(
            ops_test, username=username, app_name=CONFIG_SERVER_SIX
        )
        leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_SEVEN)
        await set_password_action(
            ops_test,
            unit_id=get_unit_id(leader_unit.name),
            username=username,
            password=password,
            app_name=CONFIG_SERVER_SEVEN,
        )

    await ops_test.model.wait_for_idle(apps=[CONFIG_SERVER_SEVEN], timeout=TIMEOUT, status="active")


@pytest.mark.abort_on_fail
async def test_restore_backup_6_to_7(
    ops_test: OpsTest,
    substrate: Substrate,
):
    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_SIX)
    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    backup_id = most_recent_backup.split()[0]

    await set_fcv(ops_test, substrate, CONFIG_SERVER_SEVEN, "6.0")

    leader_unit_seven = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_SEVEN)
    action = await leader_unit_seven.run_action(
        action_name="restore",
        **{
            "backup-id": backup_id,
            "remap-pattern": f"{CONFIG_SERVER_SEVEN}={CONFIG_SERVER_SIX},{SHARD_ONE_SEVEN}={SHARD_ONE_SIX},{SHARD_TWO_SEVEN}={SHARD_TWO_SIX}",
        },
    )
    restore = await action.wait()

    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    await ops_test.model.wait_for_idle(apps=[CONFIG_SERVER_SEVEN], timeout=TIMEOUT, status="active")

    await set_fcv(ops_test, substrate, CONFIG_SERVER_SEVEN, "7.0")


@pytest.mark.abort_on_fail
async def test_backup_mongodb_7(
    ops_test: OpsTest,
):
    # create a backup in the AWS bucket
    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_SEVEN)

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
    ops_test: OpsTest, substrate: Substrate, mongodb_charm: str, mongod_resource: dict
):
    """Build and deploy one unit of MongoDB."""
    num_units_cluster_config = {
        CONFIG_SERVER_EIGHT: 1,
        SHARD_ONE_EIGHT: 1,
        SHARD_TWO_EIGHT: 1,
    }
    await deploy_cluster_components(
        ops_test,
        substrate,
        mongodb_charm,
        mongod_resource,
        num_units_cluster_config=num_units_cluster_config,
        config_server_name=CONFIG_SERVER_EIGHT,
        shard_one_name=SHARD_ONE_EIGHT,
        shard_two_name=SHARD_TWO_EIGHT,
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_EIGHT, SHARD_ONE_EIGHT, SHARD_TWO_EIGHT],
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )

    await integrate_sharding_components(
        ops_test,
        config_server_name=CONFIG_SERVER_EIGHT,
        shard_one_name=SHARD_ONE_EIGHT,
        shard_two_name=SHARD_TWO_EIGHT,
    )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_EIGHT, SHARD_ONE_EIGHT, SHARD_TWO_EIGHT],
        timeout=DEPLOYMENT_TIMEOUT,
        status="active",
        idle_period=20,
        raise_on_blocked=False,
        raise_on_error=False,
    )

    await ops_test.model.integrate(S3_APP_NAME, CONFIG_SERVER_EIGHT)
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, CONFIG_SERVER_EIGHT], timeout=TIMEOUT, status="active"
    )

    for username in CharmUsernames:
        password = await get_password(ops_test, username=username, app_name=CONFIG_SERVER_SIX)
        await set_password(
            ops_test,
            username=username,
            password=password,
            app_name=CONFIG_SERVER_EIGHT,
        )

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_EIGHT, SHARD_ONE_EIGHT, SHARD_TWO_EIGHT],
        timeout=TIMEOUT,
        status="active",
    )


@pytest.mark.abort_on_fail
async def test_restore_backup_7_to_8(
    ops_test: OpsTest,
    substrate: Substrate,
):
    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_EIGHT)

    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    backup_id = most_recent_backup.split()[0]

    await set_fcv(ops_test, substrate, CONFIG_SERVER_EIGHT, "7.0")

    leader_unit_eight = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_EIGHT)
    action = await leader_unit_eight.run_action(
        action_name="restore",
        **{
            "backup-id": backup_id,
            "remap-pattern": f"{CONFIG_SERVER_EIGHT}={CONFIG_SERVER_SEVEN},{SHARD_ONE_EIGHT}={SHARD_ONE_SEVEN},{SHARD_TWO_EIGHT}={SHARD_TWO_SEVEN}",
        },
    )
    restore = await action.wait()

    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    await ops_test.model.wait_for_idle(apps=[CONFIG_SERVER_EIGHT], timeout=TIMEOUT, status="active")

    await set_fcv(ops_test, substrate, CONFIG_SERVER_EIGHT, "8.0")

    leader_unit_six = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_SIX)
    leader_unit_eight = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_SEVEN)
    # count total writes
    n_writes_six = await count_writes(
        ops_test, substrate, CONFIG_SERVER_SIX, leader_unit_six, mongos=True
    )
    n_writes_eight = await count_writes(
        ops_test, substrate, CONFIG_SERVER_EIGHT, leader_unit_eight, mongos=True
    )

    assert n_writes_six == n_writes_eight
