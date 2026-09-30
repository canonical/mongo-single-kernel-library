#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant
import pytest
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from single_kernel_mongo.config.statuses import BackupStatuses
from tests.integration.helpers.constants import (
    DEPLOYMENT_TIMEOUT,
    GCS_APP_NAME,
    GCS_ENDPOINT,
    S3_APP_NAME,
    S3_ENDPOINT,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.jubilant_backups import (
    configure_gcs,
    count_logical_backups,
    set_credentials,
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
    juju.deploy(GCS_APP_NAME, channel="1/edge")

    juju.wait(
        lambda status: are_agents_idle(status, app_name, S3_APP_NAME, GCS_APP_NAME, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_ready_correct_conf(juju: jubilant.Juju, cloud_configs: CloudConfigs) -> None:
    """Verifies charm goes into active status when s3 config and creds options are correct."""
    app_name = existing_app(juju)
    assert app_name

    # For AWS
    # Set valid configuration
    configuration_parameters, _ = cloud_configs["AWS"]
    # apply new configuration options
    juju.config(S3_APP_NAME, configuration_parameters)

    set_credentials(juju, cloud_configs, cloud="AWS", app_name=S3_APP_NAME)

    # For GCS
    # Set valid configuration
    configuration_parameters, credentials = cloud_configs["GCS"]
    configure_gcs(
        juju, app_name=GCS_APP_NAME, config=configuration_parameters, credentials=credentials
    )

    # after applying correct config options and creds the applications should all be active
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            S3_APP_NAME,
            GCS_APP_NAME,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
def test_both_integrated_incompatible(juju: jubilant.Juju, substrate: Substrate) -> None:
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(S3_APP_NAME, app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            S3_APP_NAME,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )
    juju.integrate(GCS_APP_NAME, app_name)

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
                    app_name: [BackupStatuses.MUTUALLY_EXCLUSIVE.value],
                },
                expected_app_statuses={},
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    juju.remove_relation(f"{app_name}:{GCS_ENDPOINT}", f"{GCS_APP_NAME}:{GCS_ENDPOINT}")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
def test_multi_backup(
    juju: jubilant.Juju,
    continuous_writes_to_db,
):
    """With writes in the DB test creating a backup while another one is running.

    Note that before creating the second backup we change the bucket and change the s3 storage
    from AWS to GCP. This test verifies that the first backup in AWS is made, the second backup
    in GCP is made, and that before the second backup is made that pbm correctly resyncs.
    """
    app_name = existing_app(juju)
    assert app_name

    leader_unit, _ = find_leader(juju, app_name=app_name)

    # create first backup once ready
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    # verify backup is started
    first_backup = juju.run(leader_unit, action="create-backup")
    assert first_backup.status == "completed", "First backup not started."

    juju.remove_relation(f"{app_name}:{S3_ENDPOINT}", f"{S3_APP_NAME}:{S3_ENDPOINT}")
    juju.integrate(GCS_APP_NAME, app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    # create a backup as soon as possible. might not be immediately possible since only one backup
    # can happen at a time.
    try:
        for attempt in Retrying(stop=stop_after_delay(40), wait=wait_fixed(5)):
            with attempt:
                second_backup = juju.run(leader_unit, action="create-backup")
                assert second_backup.status == "completed"
    except RetryError:
        assert False, "Second backup not started."

    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore before checking, wait for Charmed MongoDB to finish creating the
    # backup
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    # verify that backups was made in GCP bucket
    backups = -1
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
            with attempt:
                backups = count_logical_backups(juju, leader_unit)
                assert backups == 1
    except RetryError:
        assert backups == 1, "Backup not created."

    juju.remove_relation(f"{app_name}:{GCS_ENDPOINT}", f"{GCS_APP_NAME}:{GCS_ENDPOINT}")
    juju.integrate(S3_APP_NAME, app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
        ),
        timeout=TIMEOUT,
    )

    # verify that backups was made on the AWS bucket
    backups = -1
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = count_logical_backups(juju, leader_unit)
                assert backups == 1, "Backup not created in bucket on AWS."
    except RetryError:
        assert backups == 1, "Backup not created in bucket on AWS."
