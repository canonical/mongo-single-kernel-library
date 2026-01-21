#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.backups import S3_APP_NAME, S3_ENDPOINT, S3_REVISION_FOR_ARCH
from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    find_unit,
    has_file,
    is_relation_joined,
)
from ...helpers.sharding import (
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
from ...helpers.tls import get_file_content
from ...helpers.types import Substrate

logger = getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_deploy_charms(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    architecture: str,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
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

    await integrate_sharding_components(
        ops_test, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME
    )
    # deploy the s3 integrator charm
    await ops_test.model.deploy(
        S3_APP_NAME, channel="1/edge", revision=S3_REVISION_FOR_ARCH.get(architecture, "amd64")
    )
    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], timeout=DEPLOYMENT_TIMEOUT)

    logger.info(f"Configure {S3_APP_NAME}")
    await ops_test.model.applications[S3_APP_NAME].set_config(storage_config)

    s3_unit = ops_test.model.applications[S3_APP_NAME].units[0]
    set_credentials_action = await s3_unit.run_action(
        "sync-s3-credentials",
        **storage_credentials,
    )
    await set_credentials_action.wait()

    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        timeout=DEPLOYMENT_TIMEOUT,
        status="active",
    )


@pytest.mark.abort_on_fail
async def test_s3_integration(
    ops_test: OpsTest, substrate: Substrate, s3_bucket, storage_config
) -> None:
    """Integrate charm and s3-integrator."""
    app_name = CONFIG_SERVER_APP_NAME
    await ops_test.model.integrate(S3_APP_NAME, app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, S3_ENDPOINT, S3_ENDPOINT) is True,
        timeout=TIMEOUT,
    )
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        timeout=TIMEOUT,
    )

    # bucket should be created when integrating both
    assert s3_bucket.meta.client.head_bucket(Bucket=s3_bucket.name)

    certificate: str = storage_config["tls-ca-chain"]

    for shard in SHARD_APPS:
        for unit in ops_test.model.applications[shard].units:
            cert_file_content = await get_file_content(
                ops_test,
                substrate,
                unit.name,
                "/usr/local/share/ca-certificates/pbm.crt",
                container="mongod",
            )
            assert (
                cert_file_content.strip() == base64.b64decode(certificate).decode("utf-8").strip()
            )


@pytest.mark.abort_on_fail
async def test_create_backup(ops_test: OpsTest) -> None:
    """With writes in the DB test creating a backup."""
    db_app_name = CONFIG_SERVER_APP_NAME

    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)

    # create first backup once ready
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    action = await leader_unit.run_action(action_name="create-backup")
    first_backup = await action.wait()
    assert first_backup.status == "completed", "First backup not started."


@pytest.mark.abort_on_fail
async def test_backup_restore(ops_test: OpsTest, add_writes_to_shard, substrate: Substrate) -> None:
    """Simple backup tests that verifies that writes are correctly restored."""
    db_app_name = CONFIG_SERVER_APP_NAME
    # create a backup in the AWS bucket
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
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=20)

    action = await leader_unit.run_action(action_name="create-backup")
    first_backup = await action.wait()
    assert first_backup.status == "completed", "First backup not started."

    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    # Wait for backup to be finished
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=20)

    # add writes to be cleared after restoring the backup.
    await add_and_verify_unwanted_writes(ops_test, substrate, leader_unit, cluster_writes)

    backup_id = most_recent_backup.split()[0]
    action = await leader_unit.run_action(action_name="restore", **{"backup-id": backup_id})
    restore = await action.wait()
    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # verify all writes are present
    await verify_writes_restored(ops_test, substrate, cluster_writes)


@pytest.mark.abort_on_fail
async def test_remove_integration(ops_test: OpsTest, substrate: Substrate) -> None:
    db_app_name = CONFIG_SERVER_APP_NAME

    await ops_test.model.applications[db_app_name].remove_relation(
        f"{db_app_name}:s3-credentials", f"{S3_APP_NAME}:s3-credentials"
    )
    await ops_test.model.wait_for_idle(
        apps=[db_app_name, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME], status="active", idle_period=20
    )

    for shard in SHARD_APPS:
        for unit in ops_test.model.applications[shard].units:
            still_present = await has_file(
                ops_test,
                substrate,
                unit=unit,
                dir_path="/usr/local/share/ca-certificates/",
                filename="pbm.crt",
                container="mongod",
            )
            assert not still_present, f"{unit.name} still has file"
