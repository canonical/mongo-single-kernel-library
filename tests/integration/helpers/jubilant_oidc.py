#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for deploying OIDC providers in integration tests."""

from urllib.parse import quote

import jubilant

from tests.integration.helpers.constants import (
    DEPLOYMENT_TIMEOUT,
    MONGOD_PORT,
    MONGOS_PORT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.jubilant_common import get_ips_for_app
from tests.integration.helpers.status_helpers import are_apps_active_and_agents_idle
from tests.integration.helpers.types import Substrate

AUTHENTIK_SERVER_APP_NAME = "authentik-server"
AUTHENTIK_WORKER_APP_NAME = "authentik-worker"
AUTHENTIK_CHANNEL = "latest/edge"
POSTGRESQL_APP_NAME = "postgresql-k8s"
TRAEFIK_APP_NAME = "traefik-k8s"
OAUTH_OFFER = "authentik-oauth"
OAUTH_CERT_OFFER = "authentik-ca"


def deploy_authentik(juju_k8s_model: jubilant.Juju) -> None:
    """Deploy Authentik and its database, ingress and certificate provider."""
    juju_k8s_model.deploy(
        POSTGRESQL_APP_NAME,
        channel="14/stable",
        base="ubuntu@22.04",
        trust=True,
        config={"profile": "testing"},
    )
    juju_k8s_model.deploy(AUTHENTIK_SERVER_APP_NAME, channel=AUTHENTIK_CHANNEL, trust=True)
    juju_k8s_model.deploy(AUTHENTIK_WORKER_APP_NAME, channel=AUTHENTIK_CHANNEL, trust=True)
    juju_k8s_model.deploy(TRAEFIK_APP_NAME, channel="latest/stable", trust=True)
    juju_k8s_model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
    )

    juju_k8s_model.integrate(
        f"{AUTHENTIK_SERVER_APP_NAME}:pg-database", f"{POSTGRESQL_APP_NAME}:database"
    )
    juju_k8s_model.integrate(
        f"{AUTHENTIK_SERVER_APP_NAME}:authentik-cluster",
        AUTHENTIK_WORKER_APP_NAME,
    )
    juju_k8s_model.integrate(f"{AUTHENTIK_SERVER_APP_NAME}:traefik-route", TRAEFIK_APP_NAME)
    juju_k8s_model.integrate(
        f"{TRAEFIK_APP_NAME}:certificates", f"{TLS_CERTIFICATES_APP_NAME}:certificates"
    )

    juju_k8s_model.wait(
        lambda status: jubilant.all_active(status, POSTGRESQL_APP_NAME)
        and are_apps_active_and_agents_idle(
            status,
            AUTHENTIK_SERVER_APP_NAME,
            AUTHENTIK_WORKER_APP_NAME,
            TRAEFIK_APP_NAME,
            TLS_CERTIFICATES_APP_NAME,
            idle_period=30,
            unit_count=1,
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def integrate_authentik(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju, app_name: str) -> None:
    """Connect MongoDB to Authentik and its CA provider through cross-model offers."""
    juju_k8s_model.offer(app=AUTHENTIK_SERVER_APP_NAME, endpoint="oauth", name=OAUTH_OFFER)
    juju_k8s_model.offer(
        app=TLS_CERTIFICATES_APP_NAME, endpoint="send-ca-cert", name=OAUTH_CERT_OFFER
    )

    assert juju_k8s_model.model
    provider_model = juju_k8s_model.model.split(":")[-1]
    juju.consume(f"{provider_model}.{OAUTH_OFFER}")
    juju.consume(f"{provider_model}.{OAUTH_CERT_OFFER}")

    juju.integrate(f"{app_name}:oauth-certificate-transfer", f"{OAUTH_CERT_OFFER}:send-ca-cert")
    juju.integrate(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")


def generate_mongodb_oidc_client(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    database: str,
    mongos: bool = False,
) -> str:
    """Build an OIDC connection URI; supply access tokens separately through the client."""
    if mongos and substrate == Substrate.lxd:
        app_unit_status = next(iter(juju.status().get_units(app_name).values()))
        addresses = [app_unit_status.public_address]
    else:
        addresses = get_ips_for_app(juju, substrate, app_name)
    port = MONGOS_PORT if mongos else MONGOD_PORT
    hosts = ",".join(f"{address}:{port}" for address in addresses)
    return (
        f"mongodb://{hosts}/{quote(database, safe='')}"
        "?authSource=%24external&authMechanism=MONGODB-OIDC"
    )
