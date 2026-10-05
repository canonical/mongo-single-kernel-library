#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import time
from logging import getLogger

import jubilant
from mypy_boto3_s3.service_resource import Bucket
from tenacity import RetryError, Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    S3_APP_NAME,
    TIMEOUT,
)
from tests.integration.helpers.continuous_writes_helpers import (
    count_writes,
    start_continuous_writes,
    stop_continuous_writes,
)
from tests.integration.helpers.jubilant_backups import configure_s3, count_logical_backups
from tests.integration.helpers.jubilant_common import (
    deploy_application,
    deploy_charm,
    find_leader,
    relate_application,
    set_password,
)
from tests.integration.helpers.jubilant_major_upgrades import (
    USERNAME_MAPPING,
    add_rel8_internal_users,
    delete_rel6_internal_users,
    get_password_action,
    set_fcv,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

MONGODB_SIX = "mongodb-six"
MONGODB_SEVEN = "mongodb-seven"
MONGODB_EIGHT = "mongodb-eight"

logger = getLogger(__name__)


def test_deploy_mongodb_6(
    juju: jubilant.Juju,
    substrate: Substrate,
    application_path: str,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == Substrate.lxd else "mongodb-k8s"
    deploy_charm(
        juju,
        mongodb_charm_name,
        substrate,
        app_name=MONGODB_SIX,
        mongod_resource={},  # unused
        channel="6/edge",
        num_units=3,
        base="ubuntu@22.04",
    )
    # deploy the s3 integrator charm
    juju.deploy(S3_APP_NAME, channel="2/stable")

    juju.wait(
        lambda status: are_agents_idle(status, MONGODB_SIX, S3_APP_NAME, idle_period=20),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    configure_s3(juju, S3_APP_NAME, storage_config, storage_credentials)

    application_name = "application"
    deploy_application(juju, application_path=application_path, app_name=application_name)
    relate_application(juju, MONGODB_SIX, application_name)

    add_rel8_internal_users(juju, substrate, MONGODB_SIX)

    start_continuous_writes(juju, client_app_name=application_name)
    time.sleep(20)
    stop_continuous_writes(juju, client_app_name=application_name)


def test_backup_mongodb_6(juju: jubilant.Juju, s3_bucket: Bucket):
    """Relates, takes a backup."""
    juju.integrate(S3_APP_NAME, MONGODB_SIX)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGODB_SIX, S3_APP_NAME, idle_period=20
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )
    # bucket should be created when integrating both
    assert s3_bucket.meta.client.head_bucket(Bucket=s3_bucket.name)

    # create a backup in the AWS bucket
    leader_name, _ = find_leader(juju, MONGODB_SIX)

    task = juju.run(leader_name, "create-backup")
    assert task.status == "completed", "First backup not started."

    # verify that backup was made on the bucket
    backups = 0
    try:
        for attempt in Retrying(stop=stop_after_delay(TIMEOUT), wait=wait_fixed(5)):
            with attempt:
                backups = count_logical_backups(juju, leader_name)
                assert backups == 1, "Backup not created."
    except RetryError:
        assert backups == 1, "Backup not created."


def test_deploy_mongodb_7(
    juju: jubilant.Juju,
    substrate: Substrate,
):
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == Substrate.lxd else "mongodb-k8s"
    deploy_charm(
        juju,
        mongodb_charm_name,
        substrate,
        app_name=MONGODB_SEVEN,
        mongod_resource={},  # unused
        channel="8-transition/edge",
        num_units=3,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGODB_SEVEN, idle_period=20),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    juju.integrate(S3_APP_NAME, MONGODB_SEVEN)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, S3_APP_NAME, MONGODB_SEVEN, idle_period=20
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    for rel6_username in USERNAME_MAPPING.values():
        password = get_password_action(juju, username=rel6_username, app_name=MONGODB_SIX)
        set_password(juju, username=rel6_username, password=password, app_name=MONGODB_SEVEN)

        juju.wait(
            lambda status: are_apps_active_and_agents_idle(status, MONGODB_SEVEN, idle_period=20),
            timeout=TIMEOUT,
        )


def test_restore_backup_6_to_7(
    juju: jubilant.Juju,
    substrate: Substrate,
):
    leader_name, _ = find_leader(juju, MONGODB_SIX)

    task = juju.run(leader_name, "list-backups")
    list_result = task.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    backup_id = most_recent_backup.split()[0]

    logger.info("Set FCV to 6.0 on MongoDB 7")
    set_fcv(juju, substrate, MONGODB_SEVEN, "6.0", "operator")

    logger.info("Restore backup %s on MongoDB 7", backup_id)
    leader_name_seven, _ = find_leader(juju, MONGODB_SEVEN)
    task = juju.run(leader_name_seven, "restore", {"backup-id": backup_id})

    logger.info(f"Restore backup result {task.results=}")
    assert task.results["restore-status"] == "restore started", "restore not successful"

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGODB_SEVEN, idle_period=20),
        timeout=TIMEOUT,
    )

    logger.info("Set FCV to 7.0 on MongoDB 7")
    set_fcv(juju, substrate, MONGODB_SEVEN, "7.0", "operator")


def test_backup_mongodb_7(juju: jubilant.Juju):
    # create a backup in the AWS bucket
    leader_name_seven, _ = find_leader(juju, MONGODB_SEVEN)

    task = juju.run(leader_name_seven, "create-backup")
    assert task.status == "completed", "Second backup not started."

    # verify that backup was made on the bucket
    backups = 0
    try:
        for attempt in Retrying(stop=stop_after_delay(TIMEOUT), wait=wait_fixed(5)):
            with attempt:
                backups = count_logical_backups(juju, leader_name_seven)
                assert backups == 2, "Backup not created."
    except RetryError:
        assert backups == 2, "Backup not created."


def test_deploy_mongodb_8(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
):
    """Build and deploy one unit of MongoDB."""
    deploy_charm(
        juju,
        mongodb_charm,
        substrate,
        app_name=MONGODB_EIGHT,
        mongod_resource=mongod_resource,
        num_units=3,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGODB_EIGHT, idle_period=20),
        timeout=TIMEOUT,
    )

    juju.integrate(S3_APP_NAME, MONGODB_EIGHT)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, S3_APP_NAME, MONGODB_EIGHT, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    for rel8_username, rel6_username in USERNAME_MAPPING.items():
        password = get_password_action(juju, username=rel6_username, app_name=MONGODB_SIX)
        set_password(juju, username=rel8_username, password=password, app_name=MONGODB_EIGHT)

        juju.wait(
            lambda status: are_apps_active_and_agents_idle(status, MONGODB_EIGHT, idle_period=20),
            timeout=TIMEOUT,
        )


def test_restore_backup_7_to_8(
    juju: jubilant.Juju,
    substrate: Substrate,
):
    leader_name_seven, _ = find_leader(juju, MONGODB_SEVEN)

    task = juju.run(leader_name_seven, "list-backups")
    list_result = task.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    backup_id = most_recent_backup.split()[0]

    set_fcv(juju, substrate, MONGODB_EIGHT, "7.0", CHARMED_OPERATOR_USERNAME)

    leader_name_eight, _ = find_leader(juju, MONGODB_EIGHT)

    task = juju.run(leader_name_eight, "restore", {"backup-id": backup_id})

    logger.info(f"Restore backup result {task.results=}")
    assert task.results["restore-status"] == "restore started", "restore not successful"

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, MONGODB_EIGHT, idle_period=20),
        timeout=TIMEOUT,
    )

    set_fcv(juju, substrate, MONGODB_EIGHT, "8.0", CHARMED_OPERATOR_USERNAME)

    leader_unit_six, leader_unit_six_status = find_leader(juju, MONGODB_SIX)
    leader_unit_eight, leader_unit_eight_status = find_leader(juju, MONGODB_EIGHT)
    # count total writes
    n_writes_six = count_writes(
        juju, substrate, MONGODB_SIX, leader_unit_six, leader_unit_six_status, username="operator"
    )
    n_writes_eight = count_writes(
        juju,
        substrate,
        MONGODB_EIGHT,
        leader_unit_eight,
        leader_unit_eight_status,
        username=CHARMED_OPERATOR_USERNAME,
    )

    assert n_writes_six == n_writes_eight

    delete_rel6_internal_users(juju, substrate, MONGODB_EIGHT)
