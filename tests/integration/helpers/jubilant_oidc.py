#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for deploying OIDC providers in integration tests."""

import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import quote

import httpx
import jubilant
from pymongo import MongoClient
from pymongo.auth_oidc import OIDCCallback, OIDCCallbackContext, OIDCCallbackResult

from tests.integration.helpers.constants import (
    CHARMED_OPERATOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    MONGOD_PORT,
    MONGOS_PORT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.continuous_writes_helpers import replica_set_primary
from tests.integration.helpers.jubilant_common import (
    execute_on_mongod,
    find_leader,
    get_application_relation_data,
    get_ip_from_unit,
    get_password,
    read_remote_file,
    unit_uri,
)
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


def consume_authentik_offers(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """Offer Authentik and its CA provider, then consume both in the MongoDB model."""
    juju_k8s_model.offer(app=AUTHENTIK_SERVER_APP_NAME, endpoint="oauth", name=OAUTH_OFFER)
    juju_k8s_model.offer(
        app=TLS_CERTIFICATES_APP_NAME, endpoint="send-ca-cert", name=OAUTH_CERT_OFFER
    )

    assert juju_k8s_model.model
    provider_model = juju_k8s_model.model.split(":")[-1]
    juju.consume(f"{provider_model}.{OAUTH_OFFER}")
    juju.consume(f"{provider_model}.{OAUTH_CERT_OFFER}")


class OIDCTokenCallback(OIDCCallback):
    """Supply the test user's existing access token to PyMongo."""

    def __init__(self, access_token: str):
        self._access_token = access_token

    def fetch(self, context: OIDCCallbackContext) -> OIDCCallbackResult:
        """Return the token for this short-lived integration-test connection."""
        return OIDCCallbackResult(access_token=self._access_token)


def generate_mongodb_oidc_client(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    access_token: str,
    database: str = "app",
    mongos: bool = False,
) -> MongoClient:
    """Connect directly to the replica-set primary or a router using an OIDC token."""
    if mongos:
        unit_info = next(iter(juju.status().get_units(app_name).values()))
    else:
        _, unit_info = replica_set_primary(juju, substrate, app_name)
    address = get_ip_from_unit(substrate, unit_info)
    port = MONGOS_PORT if mongos else MONGOD_PORT
    return MongoClient(
        f"mongodb://{address}:{port}/{quote(database, safe='')}",
        authSource="$external",
        authMechanism="MONGODB-OIDC",
        authMechanismProperties={"OIDC_CALLBACK": OIDCTokenCallback(access_token)},
        directConnection=True,
        serverSelectionTimeoutMS=30000,
    )


def create_mongodb_oidc_role(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    mongos: bool = False,
    tls: bool = False,
) -> None:
    """Create the oauth/analytics role in admin for the analytics OIDC group."""
    _, leader_unit_info = find_leader(juju=juju, app_name=app_name)
    password = get_password(juju, app_name=app_name, username=CHARMED_OPERATOR_USERNAME)
    ip_address = get_ip_from_unit(substrate=substrate, unit_info=leader_unit_info)
    uri = unit_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=password,
        ip_address=ip_address,
        replica_set=app_name,
        mongos=mongos,
    )

    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri=uri,
        command=(
            "db.getSiblingDB('admin').createRole({"
            "  role: 'oauth/analytics',"
            "  privileges: [{"
            "    resource: {db: 'app', collection: 'reports'},"
            "    actions: ['find']"
            "  }],"
            "  roles: [{role: 'readWrite', db: 'app'}]"
            "})"
        ),
        tls=tls,
    )
    assert result.succeeded, "Failed to create the oauth/analytics role"


def configure_authentik_signing_key(
    juju: jubilant.Juju, juju_k8s_model: jubilant.Juju, app_name: str
) -> None:
    """Assign an RSA signing key so MongoDB can verify tokens using the provider's JWKS."""
    client_id = get_application_relation_data(juju, app_name, "oauth", "client_id")
    assert client_id, "OAuth relation is missing the client ID"
    with _authentik_admin_client(juju_k8s_model) as client:
        providers = client.get("providers/oauth2/", params={"client_id": client_id})
        providers.raise_for_status()
        matches = providers.json()["results"]
        assert len(matches) == 1, "Expected one Authentik provider for the MongoDB client ID"
        provider = matches[0]

        keys = client.get("crypto/certificatekeypairs/", params={"name": "mongodb-oidc-signing"})
        keys.raise_for_status()
        signing_keys = keys.json()["results"]
        if signing_keys:
            signing_key = signing_keys[0]
        else:
            generated = client.post(
                "crypto/certificatekeypairs/generate/",
                json={
                    "common_name": "mongodb-oidc-signing",
                    "validity_days": 365,
                    "alg": "rsa",
                },
            )
            generated.raise_for_status()
            signing_key = generated.json()

        updated = client.patch(
            f"providers/oauth2/{provider['pk']}/",
            json={"signing_key": signing_key["pk"]},
        )
        updated.raise_for_status()
        assert updated.json()["signing_key"] == signing_key["pk"]


def create_authentik_user_and_group(
    juju_k8s_model: jubilant.Juju,
    username: str = "oidc-test-user",
    group_name: str = "analytics",
) -> tuple[int, str]:
    """Create the user, authorization group and app password.

    Returns:
        tuple[int, str]: The Authentik user ID and the app password.
    """
    with _authentik_admin_client(juju_k8s_model) as client:
        group_id = create_authentik_group(client, group_name)
        user_id = create_authentik_user(client, username, group_id)
        password = create_authentik_app_password(client, user_id, username)
        return user_id, password


def create_authentik_group(client: httpx.Client, group_name: str) -> str:
    """Create a non-administrator group and return its ID."""
    group = client.post("core/groups/", json={"name": group_name, "is_superuser": False})
    group.raise_for_status()
    return group.json()["pk"]


def create_authentik_user(client: httpx.Client, username: str, group_id: str) -> int:
    """Create a service account in the given group and return its user ID."""
    user = client.post(
        "core/users/",
        json={
            "username": username,
            "name": username,
            "is_active": True,
            "type": "service_account",
            "path": "users",
            "groups": [group_id],
        },
    )
    user.raise_for_status()
    user_data = user.json()
    assert group_id in user_data["groups"], "Authentik user is missing its OIDC group"
    return user_data["pk"]


def create_authentik_app_password(client: httpx.Client, user_id: int, username: str) -> str:
    """Create an expiring app password for the service account and return its value."""
    identifier = f"mongodb-{username}"
    password_token = client.post(
        "core/tokens/",
        json={
            "identifier": identifier,
            "user": user_id,
            "intent": "app_password",
            "expiring": True,
        },
    )
    password_token.raise_for_status()
    key = client.get(f"core/tokens/{identifier}/view_key/")
    key.raise_for_status()
    return key.json()["key"]


def get_authentik_app_password(juju_k8s_model: jubilant.Juju, username: str) -> str:
    """Retrieve the app password created during the identity setup test."""
    with _authentik_admin_client(juju_k8s_model) as client:
        key = client.get(f"core/tokens/mongodb-{username}/view_key/")
        key.raise_for_status()
        return key.json()["key"]


@contextmanager
def _authentik_admin_client(juju_k8s_model: jubilant.Juju) -> Iterator[httpx.Client]:
    """Open an Authentik API client using the bootstrap administrator token."""
    leader, unit_info = find_leader(juju_k8s_model, AUTHENTIK_SERVER_APP_NAME)
    credentials = juju_k8s_model.run(leader, "get-bootstrap-admin-credentials")
    assert credentials.status == "completed", "Failed to retrieve Authentik admin credentials"
    token = credentials.results["bootstrap-token"]
    with httpx.Client(
        base_url=f"http://{unit_info.address}:9000/api/v3/",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
        trust_env=False,
    ) as client:
        yield client


def oauth_ca_path(substrate: Substrate) -> str:
    """Return the OAuth CA bundle path in the MongoDB workload."""
    return (
        "/var/snap/charmed-mongodb/current/etc/oauth/certs/oauth-ca.crt"
        if substrate == Substrate.lxd
        else "/etc/oauth/certs/oauth-ca.crt"
    )


def get_oauth_ca(
    juju: jubilant.Juju, substrate: Substrate, app_name: str, container: str = "mongod"
) -> str:
    """Read the OAuth CA bundle from the MongoDB leader's workload filesystem."""
    return read_remote_file(
        juju, substrate, f"{app_name}/leader", oauth_ca_path(substrate), container=container
    )


def get_oidc_access_token(
    juju: jubilant.Juju,
    juju_k8s_model: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    username: str = "oidc-test-user",
    ca_app_name: str | None = None,
) -> str:
    """Exchange the service account's existing app password for an OIDC access token."""
    password = get_authentik_app_password(juju_k8s_model, username)
    client_id = get_application_relation_data(juju, app_name, "oauth", "client_id")
    token_endpoint = get_application_relation_data(juju, app_name, "oauth", "token_endpoint")
    assert client_id, "OAuth relation is missing the client ID"
    assert token_endpoint, "OAuth relation is missing the token endpoint"

    ca = get_oauth_ca(
        juju, substrate, ca_app_name or app_name, container="mongos" if ca_app_name else "mongod"
    )
    context = ssl.create_default_context(cadata=ca)

    with httpx.Client(verify=context, timeout=30, trust_env=False) as client:
        response = client.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "username": username,
                "password": password,
                "scope": "openid profile",
            },
        )
        response.raise_for_status()
        access_token = response.json()["access_token"]
        assert access_token, "Authentik returned an empty access token"
        return access_token


def teardown_authentik_offers(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """Remove consumed applications and the Authentik and CA offers."""
    assert juju_k8s_model.model
    provider_model = juju_k8s_model.model.split(":")[-1]
    juju.cli("remove-saas", OAUTH_OFFER)
    juju.cli("remove-saas", OAUTH_CERT_OFFER)
    juju_k8s_model.cli(
        "remove-offer",
        f"admin/{provider_model}.{OAUTH_OFFER}",
        "--force",
        "--yes",
        include_model=False,
    )
    juju_k8s_model.cli(
        "remove-offer",
        f"admin/{provider_model}.{OAUTH_CERT_OFFER}",
        "--force",
        "--yes",
        include_model=False,
    )
