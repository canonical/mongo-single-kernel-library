#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from tests.integration.helpers.constants import (
    DEPLOYMENT_TIMEOUT,
    S3_APP_NAME,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import count_writes
from tests.integration.helpers.jubilant_backups import (
    configure_s3,
    count_logical_backups,
    create_and_verify_backup,
    insert_unwanted_data,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    find_leader,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import CloudConfigs, Substrate

logger = getLogger(__name__)


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


def test_ready_correct_conf(juju: jubilant.Juju, cloud_configs: CloudConfigs) -> None:
    """Verifies charm goes into active status when s3 config and creds options are correct."""
    app_name = existing_app(juju)
    assert app_name

    configuration_parameters, credentials = cloud_configs["GCP"]

    juju.integrate(S3_APP_NAME, app_name)

    juju.wait(
        lambda status: are_agents_idle(status, app_name, S3_APP_NAME, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    configure_s3(juju, S3_APP_NAME, configuration_parameters, credentials=credentials)

    # after applying correct config options and creds the applications should both be active
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            S3_APP_NAME,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )


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
    backups = task.results["backups"]

    assert backups, "backups not outputted"

    # verify backup is started
    backup_task = juju.run(leader_unit, action="create-backup")
    logger.info(f"Create backup result {backup_task.results=}")
    assert "backup started" in backup_task.results["backup-status"], "backup didn't start"

    # verify backup is present in the list of backups
    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore we should retry listing the backup several times
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
            with attempt:
                backups = count_logical_backups(juju, leader_unit)
                assert backups == 1
    except RetryError:
        assert backups == 1, "Backup not created."


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
