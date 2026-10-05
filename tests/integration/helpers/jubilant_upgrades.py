#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import shlex

import jubilant
import tomllib
from data_platform_helpers.advanced_statuses.models import StatusObject
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

from tests.integration.helpers.constants import DEPLOYMENT_TIMEOUT, TIMEOUT
from tests.integration.helpers.jubilant_common import fast_forward, find_leader, get_unit_id
from tests.integration.helpers.status_helpers import are_agents_idle, unit_in_status
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)

UPGRADE_INCOMPATIBLE_STATUS = StatusObject(
    status="blocked",
    message="Refresh incompatible. Rollback with instructions in Charmhub docs or see `juju debug-log`",
)


@retry(
    retry=retry_if_exception_type((AssertionError, jubilant.CLIError)),
    stop=stop_after_attempt(5),
    wait=wait_fixed(10),
    reraise=True,
)
def get_workload_version(juju: jubilant.Juju, unit_name: str) -> str:
    """Get the workload version of the deployed router charm.

    Retries 5 times since `juju ssh` can fail transiently (e.g. the exec proxy path isn't
    ready yet on k8s).
    """
    output = juju.ssh(
        unit_name,
        f"sudo cat /var/lib/juju/agents/unit-{unit_name.replace('/', '-')}/charm/refresh_versions.toml",
    )
    try:
        data = tomllib.loads(output)
    except tomllib.TOMLDecodeError:
        assert False, f"failed to parse {output=} to TOML"
    return data["workload"]


def refresh_charm(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    mongo_charm: str,
    mongod_resource: dict[str, str],
):
    if substrate == Substrate.lxd:
        juju.refresh(app=app_name, path=mongo_charm)
    else:
        juju.refresh(app=app_name, path=mongo_charm, resources=mongod_resource)


def refresh_with_juju(juju: jubilant.Juju, app_name: str, channel: str, charm_name: str) -> None:
    refresh_cmd = f"refresh {app_name} --channel {channel} --switch {charm_name}"
    logger.info(f"[refresh_with_juju] juju {refresh_cmd}")
    juju.cli(*shlex.split(refresh_cmd))


def assert_successful_run_upgrade_sequence(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    new_charm: str,
    mongod_resource: dict[str, str],
) -> None:
    """Runs the upgrade sequence on a given app."""
    leader_name, _ = find_leader(juju, app_name)
    leader_id = get_unit_id(leader_name)

    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        juju.status().get_units(app_name),
        key=lambda unit: get_unit_id(unit),
        reverse=True,
    )

    logger.info("Calling pre-refresh-check")
    task = juju.run(leader_name, "pre-refresh-check")

    assert task.status == "completed", "pre-refresh-check-failed, expected to succeed"

    logger.info(f"Upgrading {app_name}")
    refresh_charm(juju, substrate, app_name, new_charm, mongod_resource)

    juju.wait(
        lambda status: are_agents_idle(
            status,
            app_name,
            idle_period=60,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    if unit_in_status(
        juju.status(),
        app_name,
        refresh_order[0],
        UPGRADE_INCOMPATIBLE_STATUS,
    ):
        logger.info("Upgrade is blocked due to incompatibility")

        logger.info(f"Continue refresh on unit {refresh_order[0]}")
        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_task = juju.run(
            refresh_order[0],
            "force-refresh-start",
            params={"check-compatibility": False, "run-pre-refresh-checks": False},
        )
        assert force_refresh_task.return_code == 0, "action failed"

    juju.wait(
        lambda status: are_agents_idle(
            status,
            app_name,
            idle_period=20,
        ),
        timeout=TIMEOUT,
    )

    if "resume-refresh" in juju.status().apps.get(app_name).app_status.message:
        logger.info(f"Calling resume-refresh for {app_name}")
        if substrate == Substrate.lxd:
            unit = refresh_order[1]
        else:
            unit = leader_name

        task = juju.run(unit, "resume-refresh")

        if (substrate == Substrate.lxd) or (
            substrate == Substrate.k8s and leader_id != get_unit_id(refresh_order[1])
        ):
            assert task.status == "completed", "resume-refresh failed, expected to succeed."

    with fast_forward(juju, update_interval="60s"):
        juju.wait(
            lambda status: are_agents_idle(status, app_name, idle_period=20),
            timeout=DEPLOYMENT_TIMEOUT,
        )
