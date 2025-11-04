#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    deploy_charm,
    get_app_name,
    wait_for_mongodb_units_blocked,
)
from tests.integration.helpers.tls import (
    SNAP_MONGOD_SERVICE,
    TLS_CERTIFICATES_APP_NAME,
    check_certs_correctly_distributed,
    check_tls,
    external_cert_path,
    internal_cert_path,
    set_invalid_private_key,
    set_private_key,
    set_private_keys,
    time_file_created,
    time_process_started,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)


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


@pytest.mark.abort_on_fail
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


@pytest.mark.abort_on_fail
async def test_rotate_tls_key(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify rotating tls private keys restarts mongod with new certificates.

    This test rotates tls private keys to randomly generated keys.
    """
    # dict of values for cert file creation and mongod service start times. After resetting the
    # private keys these certificates should be updated and the mongod service should be
    # restarted
    original_tls_times = {}

    app_name = await get_app_name(ops_test)

    for unit in ops_test.model.applications[app_name].units:
        original_tls_times[unit.name] = {}
        original_tls_times[unit.name]["external_cert"] = await time_file_created(
            ops_test, substrate, unit.name, external_cert_path(substrate)
        )
        original_tls_times[unit.name]["internal_cert"] = await time_file_created(
            ops_test, substrate, unit.name, internal_cert_path(substrate)
        )
        original_tls_times[unit.name]["mongod_service"] = await time_process_started(
            ops_test, substrate, unit.name, SNAP_MONGOD_SERVICE
        )

        await check_certs_correctly_distributed(ops_test, substrate, app_name, unit)

    await set_private_keys(ops_test, app_name)

    # wait for certificate to be available and processed. Can get receive two certificate
    # available events and restart twice so we want to ensure we are idle for at least 1 minute
    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, idle_period=60
    )

    # After updating both the external key and the internal key a new certificate request will be
    # made; then the certificates should be available and updated.
    for unit in ops_test.model.applications[app_name].units:
        new_external_cert_time = await time_file_created(
            ops_test, substrate, unit.name, external_cert_path(substrate)
        )

        new_internal_cert_time = await time_file_created(
            ops_test, substrate, unit.name, internal_cert_path(substrate)
        )
        new_mongod_service_time = await time_process_started(
            ops_test, substrate, unit.name, "snap.charmed-mongodb.mongod.service"
        )
        await check_certs_correctly_distributed(ops_test, substrate, app_name, unit)

        assert (
            new_external_cert_time > original_tls_times[unit.name]["external_cert"]
        ), f"external cert for {unit.name} was not updated."
        assert (
            new_internal_cert_time > original_tls_times[unit.name]["internal_cert"]
        ), f"internal cert for {unit.name} was not updated."

        # Once the certificate requests are processed and updated the mongod.service should be
        # restarted
        assert (
            new_mongod_service_time > original_tls_times[unit.name]["mongod_service"]
        ), f"mongod service for {unit.name} was not restarted."

    # Verify that TLS is functioning on all units.
    for unit in ops_test.model.applications[app_name].units:
        assert await check_tls(
            ops_test, substrate, unit, enabled=True, app_name=app_name
        ), f"tls is not enabled for {unit.name}."


@pytest.mark.abort_on_fail
async def test_invalid_key(ops_test: OpsTest, substrate: Substrate) -> None:
    """Tests that setting an invalid key outputs the correct status."""
    app_name = await get_app_name(ops_test)

    for scope in ("peer", "client"):
        logger.info(f"Setting invalid {scope} private key for {app_name}")
        await set_invalid_private_key(ops_test, app_name, scope=scope)

        await wait_for_mongodb_units_blocked(
            ops_test, substrate, app_name, status=f"Invalid {scope} private key"
        )
        logger.info(f"Setting valid {scope} private key for {app_name}")
        await set_private_key(ops_test, app_name, scope=scope)

        await ops_test.model.wait_for_idle(apps=[app_name], status="active")

    logger.info("Verify that TLS is functioning on all units")
    for unit in ops_test.model.applications[app_name].units:
        assert await check_tls(
            ops_test, substrate, unit, enabled=True, app_name=app_name
        ), f"TLS is not enabled for {unit.name}."
        # assert await cannot_connect_without_tls(
        #    ops_test, substrate, unit, app_name=app_name
        # ), f"TLS is enabled and client can still connect without TLS on unit {unit.name}"


@pytest.mark.abort_on_fail
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
