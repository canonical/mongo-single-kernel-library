#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.backups import (
    S3_APP_NAME,
    S3_ENDPOINT,
    count_logical_backups,
    get_backup_list,
    set_credentials,
)
from tests.integration.helpers.common import (
    CHARMED_BACKUP_USERNAME,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    find_unit,
    get_password,
    set_password,
)
from tests.integration.helpers.sharding import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    SHARD_APPS,
    SHARD_ONE_APP_NAME,
    SHARD_ONE_DB_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_TWO_DB_NAME,
    add_and_verify_unwanted_writes,
    deploy_cluster_components,
    get_cluster_writes_count,
    integrate_sharding_components,
    verify_writes_restored,
)
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource,
) -> None:
    """Build and deploy one unit of MongoDB."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    await deploy_cluster_components(
        ops_test,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
        num_units_cluster_config={
            CONFIG_SERVER_APP_NAME: 2,
            SHARD_ONE_APP_NAME: 2,
            SHARD_TWO_APP_NAME: 1,
        },
    )

    await ops_test.model.deploy(S3_APP_NAME, channel="2/edge", num_units=1)
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=DEPLOYMENT_TIMEOUT,
        raise_on_error=False,
    )


@pytest.mark.abort_on_fail
async def test_set_credentials_in_cluster(ops_test: OpsTest, cloud_configs) -> None:
    """Tests that sharded cluster can be configured for s3 configurations."""
    await set_credentials(ops_test, cloud_configs, cloud="AWS")

    configuration_parameters, _ = cloud_configs["AWS"]

    # apply new configuration options
    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)
    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], status="active", timeout=TIMEOUT)

    await ops_test.model.integrate(
        f"{S3_APP_NAME}:{S3_ENDPOINT}",
        f"{CONFIG_SERVER_APP_NAME}:{S3_ENDPOINT}",
    )
    await integrate_sharding_components(ops_test)

    await ops_test.model.wait_for_idle(
        apps=CLUSTER_COMPONENTS,
        idle_period=20,
        status="active",
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_create_and_list_backups_in_cluster(ops_test: OpsTest) -> None:
    """Tests that sharded cluster can successfully create and list backups."""
    # verify backup list works
    backups = await get_backup_list(ops_test, app_name=CONFIG_SERVER_APP_NAME)
    assert backups, "backups not outputted"

    # verify backup is started
    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_APP_NAME)
    action = await leader_unit.run_action(action_name="create-backup")
    backup_result = await action.wait()
    assert "backup started" in backup_result.results["backup-status"], "backup didn't start"

    # verify backup is present in the list of backups
    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore we should retry listing the backup several times
    for attempt in Retrying(stop=stop_after_delay(TIMEOUT), wait=wait_fixed(3), reraise=True):
        with attempt:
            backups = await count_logical_backups(leader_unit)
            assert backups == 1


@pytest.mark.abort_on_fail
async def test_shards_cannot_run_backup_actions(ops_test: OpsTest) -> None:
    shard_unit = await find_unit(ops_test, leader=True, app_name=SHARD_ONE_APP_NAME)
    action = await shard_unit.run_action(action_name="create-backup")
    attempted_backup = await action.wait()
    assert attempted_backup.status == "failed", "shard ran create-backup command."

    action = await shard_unit.run_action(action_name="list-backups")
    attempted_backup = await action.wait()
    assert attempted_backup.status == "failed", "shard ran list-backup command."

    action = await shard_unit.run_action(action_name="restore")
    attempted_backup = await action.wait()
    assert attempted_backup.status == "failed", "shard ran list-backup command."


@pytest.mark.abort_on_fail
async def test_rotate_backup_password(ops_test: OpsTest) -> None:
    """Tests that sharded cluster can successfully create and list backups."""
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        idle_period=20,
        timeout=TIMEOUT,
        status="active",
    )
    new_password = "new-password"

    shard_backup_password = await get_password(
        ops_test, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_ONE_APP_NAME
    )
    assert (
        shard_backup_password != new_password
    ), "shard-one is incorrectly already set to the new password."

    shard_backup_password = await get_password(
        ops_test, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_TWO_APP_NAME
    )
    assert (
        shard_backup_password != new_password
    ), "shard-two is incorrectly already set to the new password."

    await set_password(
        ops_test,
        username=CHARMED_BACKUP_USERNAME,
        password=new_password,
        app_name=CONFIG_SERVER_APP_NAME,
    )
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        idle_period=20,
        timeout=TIMEOUT,
        status="active",
    )
    config_svr_backup_password = await get_password(
        ops_test, username=CHARMED_BACKUP_USERNAME, app_name=CONFIG_SERVER_APP_NAME
    )

    assert (
        config_svr_backup_password == new_password
    ), "Application config-srver did not rotate password"

    shard_backup_password = await get_password(
        ops_test, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_ONE_APP_NAME
    )
    assert shard_backup_password == new_password, "Application shard-one did not rotate password"

    shard_backup_password = await get_password(
        ops_test, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_TWO_APP_NAME
    )
    assert shard_backup_password == new_password, "Application shard-two did not rotate password"

    # verify backup actions work after password rotation
    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_APP_NAME)
    action = await leader_unit.run_action(action_name="create-backup")
    backup_result = await action.wait()
    assert (
        "backup started" in backup_result.results["backup-status"]
    ), "backup didn't start after password rotation"

    # verify backup is present in the list of backups
    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore we should retry listing the backup several times
    for attempt in Retrying(stop=stop_after_delay(20), wait=wait_fixed(3), reraise=True):
        with attempt:
            backups = await count_logical_backups(leader_unit)
            assert backups == 2, "Backup not created after password rotation."


@pytest.mark.abort_on_fail
async def test_restore_backup(ops_test: OpsTest, substrate: Substrate, add_writes_to_shard) -> None:
    """Tests that sharded Charmed MongoDB cluster supports restores."""
    # count total writes
    cluster_writes = await get_cluster_writes_count(
        ops_test,
        substrate,
        shard_app_names=SHARD_APPS,
        db_names=[SHARD_ONE_DB_NAME, SHARD_TWO_DB_NAME],
        config_server_name=CONFIG_SERVER_APP_NAME,
    )

    assert cluster_writes["total_writes"], "no writes to backup"
    assert cluster_writes[SHARD_ONE_APP_NAME], "no writes to backup for shard one"
    assert cluster_writes[SHARD_TWO_APP_NAME], "no writes to backup for shard two"
    assert (
        cluster_writes[SHARD_ONE_APP_NAME] + cluster_writes[SHARD_TWO_APP_NAME]
        == cluster_writes["total_writes"]
    ), "writes not synced"

    leader_unit = await find_unit(ops_test, leader=True, app_name=CONFIG_SERVER_APP_NAME)
    prev_backups = await count_logical_backups(leader_unit)

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME], status="active", idle_period=20
    )

    action = await leader_unit.run_action(action_name="create-backup")
    first_backup = await action.wait()
    assert first_backup.status == "completed", "First backup not started."

    # verify that backup was made on the bucket
    for attempt in Retrying(stop=stop_after_delay(4), wait=wait_fixed(5), reraise=True):
        with attempt:
            backups = await count_logical_backups(leader_unit)
            assert backups == prev_backups + 1, "Backup not created."

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME], status="active", idle_period=20
    )

    # add writes to be cleared after restoring the backup.
    await add_and_verify_unwanted_writes(ops_test, substrate, leader_unit, cluster_writes)

    # find most recent backup id and restore
    list_result = await get_backup_list(ops_test, app_name=CONFIG_SERVER_APP_NAME)
    most_recent_backup = list_result.split("\n")[-1]
    backup_id = most_recent_backup.split()[0]
    action = await leader_unit.run_action(action_name="restore", **{"backup-id": backup_id})
    restore = await action.wait()
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME], status="active", idle_period=20
    )

    await verify_writes_restored(ops_test, substrate, cluster_writes)
