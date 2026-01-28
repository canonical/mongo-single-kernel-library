#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, stop_after_delay, wait_fixed

from tests.integration.helpers.backups import (
    GCS_APP_NAME,
    GCS_ENDPOINT,
    S3_APP_NAME,
    S3_ENDPOINT,
    CloudConfigs,
    configure_gcs,
    count_logical_backups,
    set_credentials,
)
from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    deploy_charm,
    find_unit,
    get_app_name,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_deploy_charms(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
):
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, substrate, app_name, len(UNIT_IDS))
        return

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
    )
    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="edge")
    await ops_test.model.deploy(GCS_APP_NAME, channel="1/edge")

    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


@pytest.mark.abort_on_fail
async def test_ready_correct_conf(ops_test: OpsTest, cloud_configs: CloudConfigs) -> None:
    """Verifies charm goes into active status when s3 config and creds options are correct."""
    db_app_name = await get_app_name(ops_test)

    # For AWS
    # Set valid configuration
    configuration_parameters, _ = cloud_configs["AWS"]
    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)

    # Set credentials
    await set_credentials(ops_test, cloud_configs, cloud="AWS", app_name=S3_APP_NAME)

    # For GCP
    # Set valid configuration
    configuration_parameters, credentials = cloud_configs["GCS"]
    await configure_gcs(ops_test, configuration_parameters, credentials)

    # after applying correct config options and creds the applications should both be active
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, GCS_APP_NAME], status="active", timeout=TIMEOUT
    )
    await ops_test.model.wait_for_idle(
        apps=[db_app_name], status="active", timeout=TIMEOUT, idle_period=60
    )


@pytest.mark.abort_on_fail
async def test_both_integrated_incompatible(ops_test: OpsTest, substrate: Substrate) -> None:
    db_app_name = await get_app_name(ops_test)
    await ops_test.model.integrate(S3_APP_NAME, db_app_name)
    await ops_test.model.wait_for_idle(
        apps=[db_app_name], status="active", timeout=TIMEOUT, idle_period=60
    )
    await ops_test.model.integrate(GCS_APP_NAME, db_app_name)

    await wait_for_mongodb_units_blocked(
        ops_test, substrate, db_app_name, status="Only one storage relation allowed."
    )

    await ops_test.model.applications[db_app_name].remove_relation(
        f"{db_app_name}:{GCS_ENDPOINT}", f"{GCS_APP_NAME}:{GCS_ENDPOINT}"
    )
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active")


@pytest.mark.abort_on_fail
async def test_multi_backup(
    ops_test: OpsTest,
    continuous_writes_to_db,
):
    """With writes in the DB test creating a backup while another one is running.

    Note that before creating the second backup we change the bucket and change the s3 storage
    from AWS to GCP. This test verifies that the first backup in AWS is made, the second backup
    in GCP is made, and that before the second backup is made that pbm correctly resyncs.
    """
    db_app_name = await get_app_name(ops_test)

    leader_unit = await find_unit(ops_test, leader=True, app_name=db_app_name)

    # create first backup once ready
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    action = await leader_unit.run_action(action_name="create-backup")
    first_backup = await action.wait()
    assert first_backup.status == "completed", "First backup not started."

    await ops_test.model.applications[db_app_name].remove_relation(
        f"{db_app_name}:{S3_ENDPOINT}", f"{S3_APP_NAME}:{S3_ENDPOINT}"
    )
    await ops_test.model.integrate(GCS_APP_NAME, db_app_name)
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # create a backup as soon as possible. might not be immediately possible since only one backup
    # can happen at a time.
    try:
        for attempt in Retrying(stop=stop_after_delay(40), wait=wait_fixed(5)):
            with attempt:
                action = await leader_unit.run_action(action_name="create-backup")
                second_backup = await action.wait()
                assert second_backup.status == "completed"
    except RetryError:
        assert second_backup.status == "completed", "Second backup not started."

    # the action `create-backup` only confirms that the command was sent to the `pbm`. Creating a
    # backup can take a lot of time so this function returns once the command was successfully
    # sent to pbm. Therefore before checking, wait for Charmed MongoDB to finish creating the
    # backup
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # verify that backups was made in GCP bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1, "Backup not created in bucket on GCP."
    except RetryError:
        assert backups == 1, "Backup not created in first bucket on GCP."

    await ops_test.model.applications[db_app_name].remove_relation(
        f"{db_app_name}:{GCS_ENDPOINT}", f"{GCS_APP_NAME}:{GCS_ENDPOINT}"
    )
    await ops_test.model.integrate(S3_APP_NAME, db_app_name)
    await ops_test.model.wait_for_idle(apps=[db_app_name], status="active", idle_period=15)

    # verify that backups was made on the AWS bucket
    try:
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1, "Backup not created in bucket on AWS."
    except RetryError:
        assert backups == 1, "Backup not created in bucket on AWS."
