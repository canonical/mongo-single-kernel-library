#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

from tests.integration.helpers.constants import (
    CLIENT_TLS_RELATION_NAME,
    DEPLOYMENT_TIMEOUT,
    PEER_TLS_RELATION_NAME,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
    UNIT_IDS,
)
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
)
from tests.integration.helpers.jubilant_tls import (
    cannot_connect_without_tls,
    check_tls,
)
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
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


def test_enable_tls_peer_only(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify each unit has TLS enabled after relating to the TLS application."""
    # Relate it to the MongoDB to enable TLS.
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(TLS_CERTIFICATES_APP_NAME, f"{app_name}:{PEER_TLS_RELATION_NAME}")

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

    juju.remove_relation(f"{app_name}:{PEER_TLS_RELATION_NAME}", TLS_CERTIFICATES_APP_NAME)
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


def test_enable_tls_client_only(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Verify each unit has TLS enabled after relating to the TLS application."""
    # Relate it to the MongoDB to enable TLS.
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(TLS_CERTIFICATES_APP_NAME, f"{app_name}:{CLIENT_TLS_RELATION_NAME}")

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
            enabled=False,
            app_name=app_name,
        ), f"TLS not enabled for unit {unit_name}."
        assert cannot_connect_without_tls(
            juju=juju,
            substrate=substrate,
            unit_name=unit_name,
            unit_info=unit_info,
            app_name=app_name,
        ), f"Client can still connect without TLS on unit {unit_name}"
