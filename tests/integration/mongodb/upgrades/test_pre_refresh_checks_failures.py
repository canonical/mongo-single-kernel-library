#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    S3_APP_NAME,
    S3_ENDPOINT,
    TIMEOUT,
)
from tests.integration.helpers.jubilant_backups import configure_s3
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    existing_app,
    find_leader,
    find_non_leader,
    get_mongodb_hostname_for_unit,
    get_password,
    unit_hostname,
)
from tests.integration.helpers.jubilant_ha import (
    cut_network_from_unit,
    mongodb_unit_in_status,
    restore_network_to_unit,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import CloudConfigs, Substrate

logger = logging.getLogger(__name__)


def test_build_and_deploy(juju: jubilant.Juju, substrate: Substrate, base_app_name: str) -> None:
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == Substrate.lxd else "mongodb-k8s"

    deploy_charm(
        juju,
        mongodb_charm_name,
        substrate,
        app_name=base_app_name,
        mongod_resource={},  # unused
        channel="8/edge",
    )

    # deploy the s3 integrator charm
    juju.deploy(S3_APP_NAME, channel="2/stable")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, base_app_name, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_preflight_check_fails_during_backup(juju: jubilant.Juju, cloud_configs: CloudConfigs):
    """Verifies that the preflight check fails during a backup."""
    app_name = existing_app(juju)
    assert app_name
    configuration_parameters, credentials = cloud_configs["AWS"]

    configure_s3(juju, S3_APP_NAME, configuration_parameters, credentials)

    # apply new configuration options

    # after applying correct config options and creds the applications should both be active

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, S3_APP_NAME, idle_period=20),
        timeout=TIMEOUT,
    )

    juju.integrate(S3_APP_NAME, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, S3_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    # verify backup is started
    leader_unit, _ = find_leader(juju, app_name)
    juju.run(leader_unit, "create-backup")

    logger.info("Calling pre-refresh-check")
    with pytest.raises(jubilant.TaskError) as error:
        juju.run(leader_unit, "pre-refresh-check")
    assert error.value.task.status == "failed", "pre-refresh-check succeeded, expected to fail."

    juju.remove_relation(f"{app_name}:{S3_ENDPOINT}", f"{S3_APP_NAME}:{S3_ENDPOINT}")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, app_name, idle_period=20),
        timeout=TIMEOUT,
    )


def test_preflight_check_failure(
    juju: jubilant.Juju, substrate: Substrate, jubilant_chaos_mesh
) -> None:
    """Verifies that the preflight check can run successfully."""
    app_name = existing_app(juju)
    assert app_name
    assert juju.model

    leader_name, _ = find_leader(juju, app_name)
    non_leader_name, non_leader_status = find_non_leader(juju, app_name)

    machine_name = unit_hostname(juju, non_leader_name)
    mongodb_primary_hostname = get_mongodb_hostname_for_unit(
        juju, substrate, non_leader_name, non_leader_status
    )
    password = get_password(juju, app_name, username=CHARMED_OPERATOR_USERNAME)
    cut_network_from_unit(substrate, juju.model, machine_name)

    juju.wait(
        lambda status: mongodb_unit_in_status(
            status,
            substrate,
            unit_to_check=non_leader_name,
            unit_to_check_hostname=mongodb_primary_hostname,
            expected_status="(not reachable/healthy)",
            username=CHARMED_OPERATOR_USERNAME,
            password=password,
        ),
        timeout=TIMEOUT,
    )

    logger.info("Calling pre-refresh-check")
    with pytest.raises(jubilant.TaskError) as error:
        juju.run(leader_name, "pre-refresh-check")
    assert error.value.task.status == "failed", "pre-refresh-check succeeded, expected to fail."

    restore_network_to_unit(substrate, substrate, machine_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, app_name, idle_period=20),
        timeout=TIMEOUT,
    )
