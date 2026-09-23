#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import re
import time

import jubilant
import pytest
from cryptography import x509

from single_kernel_mongo.config.statuses import TLSStatuses
from tests.integration.helpers.constants import (
    CONTINUOUS_WRITE_APPLICATION,
    DEPLOYMENT_TIMEOUT,
    SNAP_MONGOD_SERVICE,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import (
    clear_continuous_writes,
    start_continuous_writes,
    stop_continuous_writes,
)
from tests.integration.helpers.jubilant_common import (
    deploy_application,
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    external_cert_path,
    get_secret_by_uri,
    internal_cert_path,
)
from tests.integration.helpers.jubilant_tls import (
    cannot_connect_without_tls,
    check_certs_correctly_distributed,
    check_tls,
    integrate_apps_with_tls,
    remove_tls_integrations,
    set_invalid_private_key,
    set_private_key,
    set_private_keys,
    time_file_created,
    time_process_started,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate

REGEX_TLS = re.compile("(-+(BEGIN|END) [A-Z ]+-+)")


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
    application_path: str,
) -> None:
    """Build and deploy one unit of MongoDB and one unit of TLS."""
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=len(UNIT_IDS))
    else:
        app_name = base_app_name
        deploy_charm(
            juju=juju,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=len(UNIT_IDS),
        )

    config = {"ca-common-name": "Test CA"}
    juju.deploy(
        charm=TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
        config=config,
    )
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=30,
            unit_count={app_name: len(UNIT_IDS), TLS_CERTIFICATES_APP_NAME: 1},
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    deploy_application(
        juju, application_path=application_path, app_name=CONTINUOUS_WRITE_APPLICATION
    )


@pytest.mark.abort_on_fail
def test_enable_tls(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify each unit has TLS enabled after relating to the TLS application."""
    # Relate it to the MongoDB to enable TLS.
    app_name = existing_app(juju)
    assert app_name

    integrate_apps_with_tls(juju, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=30,
            unit_count={app_name: len(UNIT_IDS), TLS_CERTIFICATES_APP_NAME: 1},
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    # Wait for all units enabling TLS.
    for unit_name, unit_info in juju.status().get_units(app_name).items():
        assert check_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            enabled=True,
            app_name=app_name,
        ), f"TLS not enabled for unit {unit_name}."
        assert cannot_connect_without_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            app_name=app_name,
        ), f"Client can still connect without TLS on unit {unit_name}"


def test_integrate_client_access_tls(juju: jubilant.Juju):
    """Tests that an integration with a client application sends the certificate as expected."""
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(CONTINUOUS_WRITE_APPLICATION, app_name)
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            CONTINUOUS_WRITE_APPLICATION,
            idle_period=30,
            unit_count=1,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )
    secret_tls = None
    for relation_data in juju.show_unit(f"{CONTINUOUS_WRITE_APPLICATION}/leader").relation_info:
        if relation_data.endpoint == "mongodb" and relation_data.related_endpoint == "database":
            secret_tls = relation_data.app_data.get("secret-tls")

    assert secret_tls, "Missing secret-tls in relation databag."

    secret = get_secret_by_uri(juju, secret_tls)

    assert secret.get("tls") == "True"
    tls_certificate = secret.get("tls-ca")
    assert tls_certificate, "No TLS CA in secret."

    parsed_cert = x509.load_pem_x509_certificate(data=tls_certificate.encode())
    _common_name = parsed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    common_name = str(_common_name[0].value) if _common_name else ""

    assert common_name == "Test CA"

    start_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)
    time.sleep(20)
    n_writes = stop_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)
    clear_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)

    assert n_writes != -1, "Did not manage to write on database"


def test_rotate_tls_key(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify rotating tls private keys restarts mongod with new certificates.

    This test rotates tls private keys to randomly generated keys.
    """
    # dict of values for cert file creation and mongod service start times. After resetting the
    # private keys these certificates should be updated and the mongod service should be
    # restarted
    original_tls_times = {}

    app_name = existing_app(juju)
    assert app_name

    for unit_name in juju.status().get_units(app_name).keys():
        original_tls_times[unit_name] = {}
        original_tls_times[unit_name]["external_cert"] = time_file_created(
            juju, substrate, unit_name, external_cert_path(substrate)
        )
        original_tls_times[unit_name]["internal_cert"] = time_file_created(
            juju, substrate, unit_name, internal_cert_path(substrate)
        )
        original_tls_times[unit_name]["mongod_service"] = time_process_started(
            juju, substrate, unit_name, SNAP_MONGOD_SERVICE
        )

        check_certs_correctly_distributed(juju, substrate, app_name, unit_name)

    set_private_keys(juju, app_name)

    # wait for certificate to be available and processed. Can get receive two certificate
    # available events and restart twice so we want to ensure we are idle for at least 1 minute
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=60,
            unit_count={app_name: len(UNIT_IDS), TLS_CERTIFICATES_APP_NAME: 1},
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    # After updating both the external key and the internal key a new certificate request will be
    # made; then the certificates should be available and updated.
    for unit_name in juju.status().get_units(app_name).keys():
        new_external_cert_time = time_file_created(
            juju, substrate, unit_name, external_cert_path(substrate)
        )

        new_internal_cert_time = time_file_created(
            juju, substrate, unit_name, internal_cert_path(substrate)
        )
        new_mongod_service_time = time_process_started(
            juju, substrate, unit_name, SNAP_MONGOD_SERVICE
        )
        check_certs_correctly_distributed(juju, substrate, app_name, unit_name)

        assert (
            new_external_cert_time > original_tls_times[unit_name]["external_cert"]
        ), f"external cert for {unit_name} was not updated."
        assert (
            new_internal_cert_time > original_tls_times[unit_name]["internal_cert"]
        ), f"internal cert for {unit_name} was not updated."

        # Once the certificate requests are processed and updated the mongod.service should be
        # restarted
        assert (
            new_mongod_service_time > original_tls_times[unit_name]["mongod_service"]
        ), f"mongod service for {unit_name} was not restarted."

    # Verify that TLS is functioning on all units.
    for unit_name, unit_info in juju.status().get_units(app_name).items():
        assert check_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            enabled=True,
            app_name=app_name,
        ), f"TLS not enabled for unit {unit_name}."
        assert cannot_connect_without_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            app_name=app_name,
        ), f"Client can still connect without TLS on unit {unit_name}"

    start_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)
    time.sleep(20)
    n_writes = stop_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)
    clear_continuous_writes(juju, CONTINUOUS_WRITE_APPLICATION)

    assert n_writes != -1, "Did not manage to write on database"


def test_invalid_key(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that setting an invalid key outputs the correct status."""
    app_name = existing_app(juju)
    assert app_name

    for scope in ("peer", "client"):
        set_invalid_private_key(juju, app_name, scope=scope)

        expected_status = (
            TLSStatuses.INVALID_CLIENT_PRIVATE_KEY.value
            if scope == "client"
            else TLSStatuses.INVALID_PEER_PRIVATE_KEY.value
        )

        juju.wait(
            lambda status: (
                are_agents_idle(
                    status,
                    app_name,
                    idle_period=30,
                    unit_count=3,
                )
                and does_status_match(
                    model_status=status,
                    expected_unit_statuses={app_name: [expected_status]},
                    expected_app_statuses={},
                )
            ),
            timeout=TIMEOUT,
            delay=5,
            successes=3,
        )

        set_private_key(juju, app_name, scope=scope)

        juju.wait(
            lambda status: are_apps_active_and_agents_idle(
                status,
                app_name,
                TLS_CERTIFICATES_APP_NAME,
                idle_period=60,
                unit_count={app_name: len(UNIT_IDS), TLS_CERTIFICATES_APP_NAME: 1},
            ),
            timeout=TIMEOUT,
            delay=5,
            successes=3,
        )

    # Verify that TLS is functioning on all units.
    for unit_name, unit_info in juju.status().get_units(app_name).items():
        assert check_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            enabled=True,
            app_name=app_name,
        ), f"TLS not enabled for unit {unit_name}."
        assert cannot_connect_without_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            app_name=app_name,
        ), f"Client can still connect without TLS on unit {unit_name}"


def test_disable_tls(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify each unit has TLS disabled after removing relation to the TLS application."""
    # Remove the relation.
    app_name = existing_app(juju)
    assert app_name

    remove_tls_integrations(juju, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=60,
            unit_count={app_name: len(UNIT_IDS), TLS_CERTIFICATES_APP_NAME: 1},
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Wait for all units disabling TLS.
    for unit_name, unit_info in juju.status().get_units(app_name).items():
        assert check_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            enabled=False,
            app_name=app_name,
        ), f"TLS still enabled for unit {unit_name}."
