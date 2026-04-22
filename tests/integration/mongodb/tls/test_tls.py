#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import re
import time

import pytest
from cryptography import x509
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    clear_continous_writes,
    deploy_application,
    deploy_charm,
    get_app_name,
    get_secret_by_label,
    start_continous_writes,
    stop_continous_writes,
)
from tests.integration.helpers.tls import (
    SNAP_MONGOD_SERVICE,
    TLS_CERTIFICATES_APP_NAME,
    check_certs_correctly_distributed,
    check_tls,
    external_cert_path,
    internal_cert_path,
    time_file_created,
    time_process_started,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)

REGEX_TLS = re.compile("(-+(BEGIN|END) [A-Z ]+-+)")

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict[str, str],
    base_app_name: str,
    application_path: str,
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

    await deploy_application(
        ops_test, application_path=application_path, app_name=CONTINUOUS_WRITE_APPLICATION
    )


async def test_enable_tls(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify each unit has TLS enabled after relating to the TLS application."""
    # Relate it to the MongoDB to enable TLS.
    app_name = await get_app_name(ops_test)

    await ops_test.model.integrate(
        f"{app_name}:certificates", f"{TLS_CERTIFICATES_APP_NAME}:certificates"
    )

    await ops_test.model.wait_for_idle(
        apps=[app_name, TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000, idle_period=60
    )

    # Wait for all units enabling TLS.
    for unit in ops_test.model.applications[app_name].units:
        assert await check_tls(
            ops_test, substrate, unit, enabled=True, app_name=app_name
        ), f"TLS not enabled for unit {unit.name}."


async def test_integrate_client_access_tls(ops_test: OpsTest, substrate: Substrate):
    """Tests that an integration with a client application sends the certificate as expected."""
    app_name = await get_app_name(ops_test)

    relation = await ops_test.model.integrate(CONTINUOUS_WRITE_APPLICATION, app_name)
    await ops_test.model.wait_for_idle(
        apps=[app_name, CONTINUOUS_WRITE_APPLICATION],
        status="active",
    )
    assert relation

    secret = await get_secret_by_label(ops_test, f"database.{relation.id}.tls.secret")

    assert secret.get("tls") == "True"
    tls_certificate = secret.get("tls-ca")
    assert tls_certificate, "No TLS CA in secret."

    parsed_cert = x509.load_pem_x509_certificate(data=tls_certificate.encode())
    _common_name = parsed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    common_name = str(_common_name[0].value) if _common_name else ""

    assert common_name == "Test CA"

    await start_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)
    time.sleep(20)
    n_writes = await stop_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)
    await clear_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)

    assert n_writes != -1, "Did not manage to write on database"


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

    # set external and internal key using auto-generated key for each unit
    for unit in ops_test.model.applications[app_name].units:
        action = await unit.run_action(action_name="set-tls-private-key")
        action = await action.wait()
        assert action.status == "completed", "setting external and internal key failed."

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

    await start_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)
    time.sleep(20)
    n_writes = await stop_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)
    await clear_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)

    assert n_writes != -1, "Did not manage to write on database"


async def test_set_tls_key(ops_test: OpsTest, substrate: Substrate) -> None:
    """Verify rotating tls private keys restarts mongod with new certificates.

    This test rotates tls private keys to user specified keys.
    """
    # dict of values for cert file certion and mongod service start times. After resetting the
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
            ops_test, substrate, unit.name, "snap.charmed-mongodb.mongod.service"
        )

    with open("tests/integration/data/internal-key.pem") as f:
        internal_key_contents = f.readlines()
        internal_key_contents = "".join(internal_key_contents)

    # set external and internal key for each unit
    for unit_id in range(len(ops_test.model.applications[app_name].units)):
        unit = ops_test.model.applications[app_name].units[unit_id]

        with open(f"tests/integration/data/external-key-{unit_id}.pem") as f:
            external_key_contents = f.readlines()
            external_key_contents = "".join(external_key_contents)

        key_settings = {
            "internal-key": internal_key_contents,
            "external-key": external_key_contents,
        }

        action = await unit.run_action(
            action_name="set-tls-private-key",
            **key_settings,
        )
        action = await action.wait()
        assert action.status == "completed", "setting external and internal key failed."

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
