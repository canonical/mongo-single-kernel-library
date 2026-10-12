#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
from logging import getLogger

import jubilant
from mypy_boto3_s3.service_resource import Bucket

from tests.integration.helpers.constants import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    S3_APP_NAME,
    SHARD_APPS,
    SHARD_ONE_APP_NAME,
    SHARD_ONE_DB_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_TWO_DB_NAME,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_backups import (
    add_and_verify_unwanted_writes,
    configure_s3,
    create_and_verify_backup,
    get_cluster_writes_count,
    verify_writes_restored,
)
from tests.integration.helpers.jubilant_common import find_leader, read_remote_file, unit_has_file
from tests.integration.helpers.jubilant_sharding import (
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


def test_deploy_charms(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
    deploy_cluster_components(
        juju,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
        num_units_cluster_config={
            CONFIG_SERVER_APP_NAME: 2,
            SHARD_ONE_APP_NAME: 2,
            SHARD_TWO_APP_NAME: 1,
        },
    )

    # deploy the s3 integrator charm
    juju.deploy(S3_APP_NAME, channel="2/stable")

    integrate_sharding_components(juju)

    juju.wait(
        lambda status: are_agents_idle(
            status,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    logger.info(f"Configure {S3_APP_NAME}")
    configure_s3(
        juju,
        app_name=S3_APP_NAME,
        config=storage_config,
        credentials=storage_credentials,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )


def test_s3_integration(
    juju: jubilant.Juju, substrate: Substrate, s3_bucket: Bucket, storage_config: dict[str, str]
) -> None:
    """Integrate charm and s3-integrator."""
    app_name = CONFIG_SERVER_APP_NAME
    juju.integrate(S3_APP_NAME, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    # bucket should be created when integrating both
    assert s3_bucket.meta.client.head_bucket(Bucket=s3_bucket.name)

    certificate: str = storage_config["tls-ca-chain"]

    for shard in SHARD_APPS:
        for unit_name in juju.status().get_units(shard):
            cert_file_content = read_remote_file(
                juju,
                substrate,
                unit_name,
                file_path="/usr/local/share/ca-certificates/pbm.crt",
                container="mongod",
            )
            assert (
                cert_file_content.strip() == base64.b64decode(certificate).decode("utf-8").strip()
            )


def test_create_backup(juju: jubilant.Juju) -> None:
    """With writes in the DB test creating a backup."""
    app_name = CONFIG_SERVER_APP_NAME

    # create first backup once ready
    create_and_verify_backup(juju, app_name)


def test_backup_restore(
    juju: jubilant.Juju, substrate: Substrate, jubilant_add_writes_to_shard
) -> None:
    """Simple backup tests that verifies that writes are correctly restored."""
    app_name = CONFIG_SERVER_APP_NAME
    # create a backup in the AWS bucket
    # count total writes
    cluster_writes = get_cluster_writes_count(
        juju,
        substrate,
        shard_app_names=SHARD_APPS,
        db_names=[SHARD_ONE_DB_NAME, SHARD_TWO_DB_NAME],
        config_server_name=app_name,
    )

    assert cluster_writes["total_writes"], "no writes to backup"
    assert cluster_writes[SHARD_ONE_APP_NAME], "no writes to backup for shard one"
    assert cluster_writes[SHARD_TWO_APP_NAME], "no writes to backup for shard two"
    assert (
        cluster_writes[SHARD_ONE_APP_NAME] + cluster_writes[SHARD_TWO_APP_NAME]
        == cluster_writes["total_writes"]
    ), "writes not synced"

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    # verify backup is started
    create_and_verify_backup(juju, app_name)

    leader_unit, leader_unit_status = find_leader(juju, app_name=app_name)

    # add writes to be cleared after restoring the backup.
    add_and_verify_unwanted_writes(juju, substrate, leader_unit_status, cluster_writes)

    # find most recent backup id and restore
    task = juju.run(leader_unit, action="list-backups")
    list_result = task.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]
    backup_id = most_recent_backup.split()[0]

    restore_task = juju.run(leader_unit, action="restore", params={"backup-id": backup_id})
    logger.info(f"Restore backup result {restore_task.results=}")
    assert restore_task.results["restore-status"] == "restore started", "restore not successful"

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    verify_writes_restored(juju, substrate, cluster_writes)


def test_remove_integration(juju: jubilant.Juju, substrate: Substrate) -> None:
    app_name = CONFIG_SERVER_APP_NAME

    juju.remove_relation(f"{app_name}:s3-credentials", f"{S3_APP_NAME}:s3-credentials")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    for shard in SHARD_APPS:
        for unit_name in juju.status().get_units(shard):
            still_present = unit_has_file(
                juju,
                substrate,
                unit_name=unit_name,
                dir_path="/usr/local/share/ca-certificates/",
                filename="pbm.crt",
                container="mongod",
            )
            assert not still_present, f"{unit_name} still has file"
