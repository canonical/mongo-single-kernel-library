#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import logging

import jubilant
import pytest
from pymongo import MongoClient

from single_kernel_mongo.config.statuses import MongoDBStatuses
from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    TIMEOUT,
    UNIT_IDS,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    find_leader,
    get_ip_from_unit,
    get_password,
    unit_uri,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
) -> None:
    """Deploys the charm with an invalid config.

    Then waits for the status to display, change it to a correct value and
    checks that the service starts afterwards.
    """
    app_name = base_app_name

    deploy_charm(
        juju=juju,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=app_name,
        num_units=len(UNIT_IDS),
        config={"role": "invalidrole"},
    )
    juju.wait(
        lambda status: are_agents_idle(status, app_name, idle_period=30, unit_count=len(UNIT_IDS)),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    does_status_match(
        juju.status(),
        expected_unit_statuses=None,
        expected_app_statuses={app_name: [MongoDBStatuses.INVALID_ROLE.value]},
        num_units={app_name: len(UNIT_IDS)},
    )

    juju.config(app_name, {"role": "replication"})
    # Check that we can resolve it
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=len(UNIT_IDS)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    _, leader_unit_info = find_leader(juju=juju, app_name=app_name)

    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)

    ip_address = get_ip_from_unit(substrate=substrate, unit_info=leader_unit_info)

    client = MongoClient(
        unit_uri(
            username=CHARMED_OPERATOR_USERNAME,
            ip_address=ip_address,
            password=password,
            replica_set=app_name,
        ),
        directConnection=True,
    )

    assert client.server_info()["version"].split("-")[0] is not None
