#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from tests.integration.helpers.constants import (
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.jubilant_common import (
    count_primaries,
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    fast_forward,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


def scale_and_verify(juju: jubilant.Juju, substrate: Substrate, app_name: str, count: int):
    if count == 0:
        logger.warning("Skipping scale up/down by 0")
        return
    if count > 0:
        logger.info(f"Scaling up by {count} units")
    else:
        logger.info(f"Scaling down by {abs(count)} units")

    current_units = len(juju.status().get_units(app_name))

    with fast_forward(juju, update_interval="2m"):
        ensure_app_number_units(juju, substrate, app_name, current_units + count, wait=True)

    assert count_primaries(juju, substrate, app_name) == 1, "Replica set has no primary."


@pytest.mark.abort_on_fail
@pytest.mark.juju_setup
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
) -> None:
    """Build the charm-under-test and deploy it with three units."""
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=len(UNIT_IDS))
        return

    app_name = base_app_name
    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=app_name,
        num_units=len(UNIT_IDS),
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_long_scale_up_scale_down_units(juju: jubilant.Juju, substrate: Substrate):
    """Scale up and down the application and verify the replica set is healthy."""
    scales = [2, -1, -1, 2, -2, 3, -3]

    app_name = existing_app(juju)
    assert app_name

    for count in scales:
        scale_and_verify(juju, substrate, app_name=app_name, count=count)
