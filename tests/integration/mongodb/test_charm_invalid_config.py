#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import logging

import pytest
from pymongo import MongoClient
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
    check_app_status,
    deploy_charm,
    find_unit,
    get_address_of_unit,
    get_app_name,
    get_password,
    unit_uri,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, mongodb_charm: str, substrate: Substrate, mongod_resource, base_app_name
):
    """Deploys the charm with an invalid config.

    Then waits for the status to display, change it to a correct value and
    checks that the service starts afterwards.
    """
    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
        config={"role": "invalidrole"},
    )
    await ops_test.model.wait_for_idle(
        apps=[base_app_name], raise_on_blocked=False, timeout=DEPLOYMENT_TIMEOUT
    )

    # Check that status is blocked.
    await check_app_status(ops_test, base_app_name, "blocked", "The role config option is invalid")

    # Check that we can resolve it
    await ops_test.model.applications[base_app_name].set_config({"role": "replication"})
    await ops_test.model.wait_for_idle(
        apps=[base_app_name], raise_on_blocked=False, status="active"
    )
    app_name = await get_app_name(ops_test)
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    password = await get_password(ops_test, app_name=app_name)
    ip_address = await get_address_of_unit(
        ops_test, substrate, int(leader_unit.name.split("/")[1]), app_name
    )

    client = MongoClient(unit_uri(ip_address, password, app_name), directConnection=True)

    # Good, we have a valid version, the server is running.
    assert client.server_info()["version"].split("-")[0] is not None
