#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for OIDC authentication on a MongoDB replica set."""

import jubilant

from tests.integration.helpers.constants import DEPLOYMENT_TIMEOUT
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
)
from tests.integration.helpers.jubilant_oidc import deploy_authentik, integrate_authentik
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
) -> None:
    """Deploy a three-unit MongoDB replica set and wait until it is ready."""
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=3)
    else:
        app_name = base_app_name
        deploy_charm(
            juju=juju,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=app_name,
            num_units=3,
            config={"role": "replication"},
        )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=3
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_deploy_authentik(juju_k8s_model: jubilant.Juju) -> None:
    """Deploy Authentik and wait until its supporting applications are ready."""
    deploy_authentik(juju_k8s_model)


def test_integrate_oauth_and_certificates(
    juju: jubilant.Juju, juju_k8s_model: jubilant.Juju
) -> None:
    """Integrate the replica set with Authentik and its certificate provider."""
    app_name = existing_app(juju)
    assert app_name

    integrate_authentik(juju, juju_k8s_model, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=3
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )
