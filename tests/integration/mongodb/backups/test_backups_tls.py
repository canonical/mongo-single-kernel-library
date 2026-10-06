#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant
from mypy_boto3_s3.service_resource import Bucket
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

from tests.integration.helpers.constants import (
    DEPLOYMENT_TIMEOUT,
    S3_APP_NAME,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import count_writes
from tests.integration.helpers.jubilant_backups import (
    configure_s3,
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
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


def test_deploy_charms(
    juju: jubilant.Juju,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
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

    logger.info(f"Configure {S3_APP_NAME}")

    # apply new configuration options
    configure_s3(
        juju,
        app_name=S3_APP_NAME,
        config=storage_config,
        credentials=storage_credentials,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            S3_APP_NAME,
            idle_period=30,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )


def test_s3_integration(juju: jubilant.Juju, s3_bucket: Bucket) -> None:
    """Integrate charm and s3-integrator."""
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(app_name, S3_APP_NAME)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            S3_APP_NAME,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    # bucket should be created when integrating both
    assert s3_bucket.meta.client.head_bucket(Bucket=s3_bucket.name)


def test_backup_restore(
    juju: jubilant.Juju, substrate: Substrate, jubilant_add_writes_to_db
) -> None:
    """Simple backup tests that verifies that writes are correctly restored."""
    app_name = existing_app(juju)
    assert app_name
    # create a backup in the AWS bucket
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
