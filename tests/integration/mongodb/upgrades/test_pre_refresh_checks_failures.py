#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.backups import S3_APP_NAME, S3_ENDPOINT, CloudConfigs

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    deploy_charm,
    find_unit,
    get_app_name,
    is_relation_joined,
    unit_hostname,
)
from ...helpers.ha import (
    cut_network_from_unit,
    restore_network_for_unit,
    wait_until_unit_in_status,
)
from ...helpers.types import Substrate

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, substrate: Substrate, base_app_name) -> None:
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == "lxd" else "mongodb-k8s"

    await deploy_charm(
        ops_test,
        mongodb_charm_name,
        substrate,
        app_name=base_app_name,
        mongod_resource={},  # unused
        channel="8/edge",
    )

    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="1/edge")

    await ops_test.model.wait_for_idle(
        apps=[base_app_name],
        status="active",
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )


@pytest.mark.abort_on_fail
async def test_preflight_check_fails_during_backup(
    ops_test: OpsTest, substrate: Substrate, cloud_configs: CloudConfigs
):
    """Verifies that the preflight check fails during a backup."""
    app_name = await get_app_name(ops_test)
    s3_integrator_unit = ops_test.model.applications[S3_APP_NAME].units[0]
    configuration_parameters, credentials = cloud_configs["AWS"]

    # apply new configuration options
    await ops_test.model.applications[S3_APP_NAME].set_config(configuration_parameters)
    action = await s3_integrator_unit.run_action(action_name="sync-s3-credentials", **credentials)
    await action.wait()

    # after applying correct config options and creds the applications should both be active
    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], status="active", timeout=TIMEOUT)

    await ops_test.model.integrate(S3_APP_NAME, app_name)
    await ops_test.model.block_until(
        lambda: is_relation_joined(ops_test, S3_ENDPOINT, S3_ENDPOINT) is True,
        timeout=TIMEOUT,
    )

    # verify backup is started
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    action = await leader_unit.run_action(action_name="create-backup")
    await action.wait()

    logger.info("Calling pre-refresh-check")
    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "failed", "pre-refresh-check succeeded, expected to fail."

    await ops_test.model.applications[app_name].remove_relation(
        f"{app_name}:{S3_ENDPOINT}", f"{S3_APP_NAME}:{S3_ENDPOINT}"
    )
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_preflight_check_failure(ops_test: OpsTest, substrate: Substrate, chaos_mesh) -> None:
    """Verifies that the preflight check can run successfully."""
    app_name = await get_app_name(ops_test)
    unit = await find_unit(ops_test, leader=False, app_name=app_name)
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    machine_name = await unit_hostname(ops_test, unit.name)
    cut_network_from_unit(ops_test, substrate, machine_name)

    await wait_until_unit_in_status(
        ops_test, substrate, unit, leader_unit, "(not reachable/healthy)", app_name
    )

    logger.info("Calling pre-refresh-check")
    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "failed", "pre-refresh-check succeeded, expected to fail."

    restore_network_for_unit(ops_test, substrate, machine_name)

    await ops_test.model.wait_for_idle(
        apps=[app_name],
        status="active",
        timeout=1000,
        idle_period=30,
        raise_on_error=False,
    )
