#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    deploy_charm,
    get_app_name,
)
from ...helpers.tls import (
    TLS_CERTIFICATES_APP_NAME,
    check_tls,
)
from ...helpers.types import Substrate


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, mongodb_charm: Path, substrate: Substrate, mongod_resource, base_app_name
) -> None:
    """Build and deploy one unit of MongoDB and one unit of TLS."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, substrate, app_name, len(UNIT_IDS))
    else:
        app_name = base_app_name
        await deploy_charm(
            ops_test=ops_test,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=len(UNIT_IDS),
        )
        await ops_test.model.wait_for_idle(
            apps=[app_name], status="active", timeout=DEPLOYMENT_TIMEOUT
        )

    config = {"ca-common-name": "Test CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel="latest/stable",
        config=config,
        base="ubuntu@22.04",
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME], status="active", timeout=DEPLOYMENT_TIMEOUT
    )


async def test_enable_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify each unit has TLS enabled after relating to the TLS application."""
    # Relate it to the MongoDB to enable TLS.
    app_name = await get_app_name(ops_test)

    await ops_test.model.integrate(
        f"{app_name}:certificates", f"{TLS_CERTIFICATES_APP_NAME}:certificates"
    )

    await ops_test.model.wait_for_idle(status="active", timeout=1000, idle_period=60)

    # Wait for all units enabling TLS.
    for unit in ops_test.model.applications[app_name].units:
        assert await check_tls(
            ops_test, substrate, unit, enabled=True, app_name=app_name
        ), f"TLS not enabled for unit {unit.name}."


async def test_disable_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify each unit has TLS disabled after removing relation to the TLS application."""
    # Remove the relation.
    app_name = await get_app_name(ops_test)
    await ops_test.model.applications[app_name].remove_relation(
        f"{app_name}:certificates", f"{TLS_CERTIFICATES_APP_NAME}:certificates"
    )

    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, idle_period=60
    )

    # Wait for all units disabling TLS.
    for unit in ops_test.model.applications[app_name].units:
        assert await check_tls(
            ops_test, substrate, unit, enabled=False, app_name=app_name
        ), f"TLS not disabled for unit {unit.name}."
