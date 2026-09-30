#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant
import pytest
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from single_kernel_mongo.config.statuses import BackupStatuses
from tests.integration.helpers.constants import (
    CHARMED_BACKUP_USERNAME,
    CHARMED_OPERATOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    NEW_CLUSTER,
    S3_APP_NAME,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import count_writes
from tests.integration.helpers.jubilant_backups import (
    configure_s3,
    count_failed_backups,
    count_logical_backups,
    create_and_verify_backup,
    insert_unwanted_data,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    find_leader,
    get_password,
    set_password,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import CloudConfigs, Substrate

logger = getLogger(__name__)


@pytest.mark.abort_on_fail
def test_deploy_charms(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
):
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=len(UNIT_IDS))
    else:
        app_name = base_app_name
        deploy_charm(
            juju=juju,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=app_name,
            num_units=len(UNIT_IDS),
        )
    # deploy the s3 integrator charm
    juju.deploy(S3_APP_NAME, channel="2/stable")

    juju.wait(
        lambda status: are_agents_idle(status, app_name, S3_APP_NAME, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_blocked_missing_config(juju: jubilant.Juju) -> None:
    """Test that when charm is missing pbm information that it reports that."""
    app_name = existing_app(juju)
    assert app_name
    juju.integrate(S3_APP_NAME, app_name)
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [BackupStatuses.pbm_missing_conf("s3")],
                },
                expected_app_statuses={},
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_blocked_incorrect_creds(juju: jubilant.Juju, cloud_configs: CloudConfigs) -> None:
    """Verifies that the charm goes into blocked status when s3 creds are incorrect."""
    app_name = existing_app(juju)
    assert app_name

    configuration_parameters, _ = cloud_configs["AWS"]

    # set incorrect s3 credentials
    configure_s3(
        juju,
        S3_APP_NAME,
        configuration_parameters,
        {"access-key": "user", "secret-key": "doesnt-exist"},
    )

    # verify that Charmed MongoDB is blocked and reports incorrect credentials
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                S3_APP_NAME,
                idle_period=30,
            )
            and does_status_match(
                status,
                expected_unit_statuses={app_name: [BackupStatuses.pbm_incompatible_conf("s3")]},
                expected_app_statuses={},
            )
        ),
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
def test_ready_correct_conf(juju: jubilant.Juju, cloud_configs: CloudConfigs) -> None:
    """Verifies charm goes into active status when s3 config and creds options are correct."""
    app_name = existing_app(juju)
    assert app_name

    configuration_parameters, credentials = cloud_configs["AWS"]
    configure_s3(
        juju,
        app_name=S3_APP_NAME,
        config=configuration_parameters,
        credentials=credentials,
    )

    # after applying correct config options and creds the applications should both be active
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            S3_APP_NAME,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
def test_create_and_list_backups(juju: jubilant.Juju) -> None:
    """Tests that we can create a backup, and that it is listed in the backups."""
    app_name = existing_app(juju)
    assert app_name

    leader_unit, _ = find_leader(juju, app_name=app_name)
    # verify backup list works
    logger.info("!!!!! test_create_and_list_backups >>>  %s", leader_unit)
    task = juju.run(leader_unit, action="list-backups")

    assert task.status == "completed"

    logger.info("!!!!! test_create_and_list_backups >>>  %s", task.results)
    backups_output = task.results["backups"]

    assert backups_output, "No output"

    # verify backup is started
    backup_task = juju.run(leader_unit, action="create-backup")
    logger.info(f"Create backup result {backup_task.results=}")
    assert "backup started" in backup_task.results["backup-status"], "backup didn't start"

    # verify backup is present in the list of backups
    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore we should retry listing the backup several times
    backups = -1
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
            with attempt:
                backups = count_logical_backups(juju, leader_unit)
                assert backups == 1
    except RetryError:
        assert backups == 1, "Backup not created."


@pytest.mark.abort_on_fail
def test_restore(juju: jubilant.Juju, jubilant_add_writes_to_db, substrate: Substrate) -> None:
    """Simple backup tests that verifies that writes are correctly restored."""
    app_name = existing_app(juju)
    assert app_name

    leader_unit, leader_unit_status = find_leader(juju, app_name=app_name)

    # count total writes
    number_writes = count_writes(juju, substrate, app_name, leader_unit, leader_unit_status)
    assert number_writes > 0, "no writes to backup"

    create_and_verify_backup(juju, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    # add writes to be cleared after restoring the backup. Note these are written to the same
    # collection that was backed up.
    insert_unwanted_data(juju, substrate, app_name, leader_unit_status)

    new_number_of_writes = count_writes(juju, substrate, app_name, leader_unit, leader_unit_status)
    assert new_number_of_writes > number_writes, "No writes to be cleared after restoring."

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
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    # verify all writes are present
    number_writes_restored = -1
    try:
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(20)):
            with attempt:
                number_writes_restored = count_writes(
                    juju, substrate, app_name, leader_unit, leader_unit_status
                )
                assert number_writes == number_writes_restored, "writes not correctly restored"
    except RetryError:
        assert number_writes == number_writes_restored, "writes not correctly restored"


def test_restore_new_cluster(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    jubilant_add_writes_to_db,
):
    # configure test for the cloud provider
    app_name = existing_app(juju)
    assert app_name

    leader_unit, leader_unit_status = find_leader(juju, app_name=app_name)

    new_cluster_app_name = f"{NEW_CLUSTER}-aws"

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            S3_APP_NAME,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    # create a backup
    writes_in_old_cluster = count_writes(juju, substrate, app_name, leader_unit, leader_unit_status)

    assert writes_in_old_cluster > 0, "old cluster has no writes."

    create_and_verify_backup(juju, app_name)

    # save old password, since after restoring we will need this password to authenticate.
    old_password = get_password(juju, username=CHARMED_OPERATOR_USERNAME, app_name=app_name)

    # deploy a new cluster with a different name
    deploy_charm(
        juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=new_cluster_app_name,
        num_units=len(UNIT_IDS),
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            new_cluster_app_name,
            idle_period=15,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    set_password(
        juju,
        username=CHARMED_OPERATOR_USERNAME,
        password=old_password,
        app_name=new_cluster_app_name,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            new_cluster_app_name,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    # relate to s3 - s3 has the necessary configurations
    juju.integrate(S3_APP_NAME, new_cluster_app_name)

    # wait for new cluster to sync
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            new_cluster_app_name,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    # verify that the listed backups from the old cluster are not listed as failed.
    new_cluster_leader_unit, new_cluster_leader_unit_status = find_leader(
        juju, app_name=new_cluster_app_name
    )
    assert (
        count_failed_backups(juju, new_cluster_leader_unit) == 0
    ), "Backups from old cluster are listed as failed"

    # find most recent backup id and restore
    task = juju.run(new_cluster_leader_unit, action="list-backups")
    list_result = task.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]
    backup_id = most_recent_backup.split()[0]
    restore_task = juju.run(leader_unit, action="restore", params={"backup-id": backup_id})
    logger.info(f"Restore backup result {restore_task.results=}")
    assert restore_task.results["restore-status"] == "restore started", "restore not successful"

    writes_in_new_cluster = -1

    # verify all writes are present
    try:
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(20)):
            with attempt:
                writes_in_new_cluster = count_writes(
                    juju,
                    substrate,
                    new_cluster_app_name,
                    new_cluster_leader_unit,
                    new_cluster_leader_unit_status,
                )
                assert (
                    writes_in_new_cluster == writes_in_old_cluster
                ), "new cluster writes do not match old cluster writes after restore"
    except RetryError:
        assert (
            writes_in_new_cluster == writes_in_old_cluster
        ), "new cluster writes do not match old cluster writes after restore"


@pytest.mark.abort_on_fail
def test_update_backup_password(juju: jubilant.Juju) -> None:
    """Verifies that after changing the backup password the pbm tool is updated and functional."""
    app_name = existing_app(juju, test_deployments=[f"{NEW_CLUSTER}-aws"])
    assert app_name

    leader_unit, _ = find_leader(juju, app_name=app_name)

    # wait for charm to be idle before setting password
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    set_password(juju, username=CHARMED_BACKUP_USERNAME, password="new-password", app_name=app_name)

    # wait for charm to be idle after setting password
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    # verify we still have connection to pbm via creating a backup
    task = juju.run(leader_unit, "create-backup")
    logger.info(f"Create backup result {task.results=}")
    assert "backup started" in task.results["backup-status"], "backup didn't start"
