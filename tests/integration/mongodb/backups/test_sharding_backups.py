#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CHARMED_BACKUP_USERNAME,
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    DEPLOYMENT_TIMEOUT,
    S3_APP_NAME,
    S3_ENDPOINT,
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
    get_backup_list,
    get_cluster_writes_count,
    verify_writes_restored,
)
from tests.integration.helpers.jubilant_common import (
    find_leader,
    get_password,
    set_password,
)
from tests.integration.helpers.jubilant_sharding import (
    deploy_cluster_components,
    integrate_sharding_components,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import CloudConfigs, Substrate

logger = getLogger(__name__)


def test_build_and_deploy(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
) -> None:
    """Build and deploy one unit of MongoDB."""
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

    juju.wait(
        lambda status: are_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_set_credentials_in_cluster(juju: jubilant.Juju, cloud_configs: CloudConfigs) -> None:
    """Tests that sharded cluster can be configured for s3 configurations."""
    configuration_parameters, credentials = cloud_configs["AWS"]
    configure_s3(
        juju,
        app_name=S3_APP_NAME,
        config=configuration_parameters,
        credentials=credentials,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    juju.integrate(
        f"{S3_APP_NAME}:{S3_ENDPOINT}",
        f"{CONFIG_SERVER_APP_NAME}:{S3_ENDPOINT}",
    )
    integrate_sharding_components(juju)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )


def test_create_and_list_backups_in_cluster(juju: jubilant.Juju) -> None:
    """Tests that sharded cluster can successfully create and list backups."""
    # verify backup list works
    backups = get_backup_list(juju, app_name=CONFIG_SERVER_APP_NAME)
    assert backups, "backups not outputted"

    # verify backup is started
    create_and_verify_backup(juju, CONFIG_SERVER_APP_NAME)


def test_shards_cannot_run_backup_actions(juju: jubilant.Juju) -> None:
    shard_unit, _ = find_leader(juju, app_name=SHARD_ONE_APP_NAME)

    with pytest.raises(jubilant.TaskError) as error:
        juju.run(shard_unit, "create-backup")
    assert error.value.task.status == "failed", "shard ran create-backup command, it shouldn't."

    with pytest.raises(jubilant.TaskError) as error:
        juju.run(shard_unit, "list-backups")
    assert error.value.task.status == "failed", "shard ran list-backup command, it shouldn't."

    with pytest.raises(jubilant.TaskError) as error:
        juju.run(shard_unit, "restore")
    assert error.value.task.status == "failed", "shard ran restore command, it shouldn't."


def test_rotate_backup_password(juju: jubilant.Juju) -> None:
    """Tests that sharded cluster can successfully create and list backups."""
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )
    new_password = "new-password"  # nosec: B105

    shard_backup_password = get_password(
        juju, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_ONE_APP_NAME
    )
    assert (
        shard_backup_password != new_password
    ), "shard-one is incorrectly already set to the new password."

    shard_backup_password = get_password(
        juju, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_TWO_APP_NAME
    )
    assert (
        shard_backup_password != new_password
    ), "shard-two is incorrectly already set to the new password."

    set_password(
        juju,
        username=CHARMED_BACKUP_USERNAME,
        password=new_password,
        app_name=CONFIG_SERVER_APP_NAME,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            *CLUSTER_COMPONENTS,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )
    config_svr_backup_password = get_password(
        juju, username=CHARMED_BACKUP_USERNAME, app_name=CONFIG_SERVER_APP_NAME
    )

    assert (
        config_svr_backup_password == new_password
    ), "Application config-server did not rotate password"

    shard_backup_password = get_password(
        juju, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_ONE_APP_NAME
    )
    assert shard_backup_password == new_password, "Application shard-one did not rotate password"

    shard_backup_password = get_password(
        juju, username=CHARMED_BACKUP_USERNAME, app_name=SHARD_TWO_APP_NAME
    )
    assert shard_backup_password == new_password, "Application shard-two did not rotate password"

    # verify backup actions work after password rotation
    create_and_verify_backup(juju, app_name=CONFIG_SERVER_APP_NAME)


def test_restore_backup(
    juju: jubilant.Juju, substrate: Substrate, jubilant_add_writes_to_shard
) -> None:
    """Tests that sharded Charmed MongoDB cluster supports restores."""
    # count total writes
    cluster_writes = get_cluster_writes_count(
        juju,
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

    create_and_verify_backup(juju, CONFIG_SERVER_APP_NAME)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONFIG_SERVER_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    leader_unit, leader_unit_status = find_leader(juju, app_name=CONFIG_SERVER_APP_NAME)
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
            CONFIG_SERVER_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    verify_writes_restored(juju, substrate, cluster_writes)
