#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for OIDC authentication on a MongoDB replica set."""

import json
from uuid import uuid4

import jubilant
import pytest
from pymongo.errors import OperationFailure
from yaml import safe_load

from single_kernel_mongo.config.statuses import OAuthStatuses
from tests.integration.helpers.constants import DEPLOYMENT_TIMEOUT
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    existing_app,
    mongodb_config_path,
    read_remote_file,
    run_command_on_server,
)
from tests.integration.helpers.jubilant_oidc import (
    OAUTH_CERT_OFFER,
    OAUTH_OFFER,
    configure_authentik_signing_key,
    consume_authentik_offers,
    create_authentik_user_and_group,
    create_mongodb_oidc_role,
    deploy_authentik,
    generate_mongodb_oidc_client,
    get_oidc_access_token,
    oauth_ca_path,
    teardown_authentik_offers,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
    none_is_restarting,
)
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

    create_mongodb_oidc_role(juju, substrate, app_name)


def test_deploy_authentik(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """Deploy Authentik and wait until its supporting applications are ready."""
    deploy_authentik(juju_k8s_model)
    consume_authentik_offers(juju, juju_k8s_model)
    user_id, password = create_authentik_user_and_group(juju_k8s_model)

    assert user_id > 0
    assert password


def test_integrate_oauth_only(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """OIDC with a self-signed issuer is blocked until its CA is received."""
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")

    juju.wait(
        lambda status: are_agents_idle(status, app_name, idle_period=30, unit_count=3)
        and does_status_match(
            model_status=status,
            expected_unit_statuses={app_name: [OAuthStatuses.ISSUER_TLS_ERROR.value]},
            expected_app_statuses={},
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    configure_authentik_signing_key(juju, juju_k8s_model, app_name)


def test_integrate_oauth_certificates(juju: jubilant.Juju) -> None:
    """Receiving the issuer CA enables OIDC on all three replicas."""
    app_name = existing_app(juju)
    assert app_name
    juju.integrate(f"{app_name}:oauth-certificate-transfer", f"{OAUTH_CERT_OFFER}:send-ca-cert")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=3
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )


def test_oidc_user_can_write_and_read(
    juju: jubilant.Juju,
    substrate: Substrate,
    juju_k8s_model: jubilant.Juju,
) -> None:
    """Authenticate with the analytics user's token and access app.reports."""
    app_name = existing_app(juju)
    assert app_name
    token = get_oidc_access_token(juju, juju_k8s_model, substrate, app_name)
    document = {"_id": uuid4().hex, "number": 1}

    with generate_mongodb_oidc_client(juju, substrate, app_name, token) as client:
        authenticated = client.admin.command("connectionStatus")
        assert authenticated["authInfo"]["authenticatedUsers"]

        inserted = client.app.reports.insert_one(document)
        assert inserted.acknowledged

        report = client.app.reports.find_one({"_id": document["_id"]})
        assert report == document


def test_remove_oauth_blocks_and_prevents_writes(
    juju: jubilant.Juju, substrate: Substrate, juju_k8s_model: jubilant.Juju
) -> None:
    """Removing OAuth leaves a CA-only setup blocked and disables token authentication."""
    app_name = existing_app(juju)
    assert app_name
    token = get_oidc_access_token(juju, juju_k8s_model, substrate, app_name)
    juju.remove_relation(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")

    juju.wait(
        lambda status: are_agents_idle(status, app_name, idle_period=30, unit_count=3)
        and does_status_match(
            model_status=status,
            expected_unit_statuses={app_name: [OAuthStatuses.OAUTH_REQUIRED.value]},
            expected_app_statuses={},
        )
        and none_is_restarting(status, juju, app_name),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    with generate_mongodb_oidc_client(juju, substrate, app_name, token) as client:
        with pytest.raises(OperationFailure):
            client.app.reports.insert_one({"_id": uuid4().hex, "number": 2})


def test_restore_oauth_then_remove_certificates_prevents_writes(
    juju: jubilant.Juju, substrate: Substrate, juju_k8s_model: jubilant.Juju
) -> None:
    """Restoring OAuth enables access; removing its self-signed CA blocks it again."""
    app_name = existing_app(juju)
    assert app_name
    juju.integrate(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=3
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    configure_authentik_signing_key(juju, juju_k8s_model, app_name)
    token = get_oidc_access_token(juju, juju_k8s_model, substrate, app_name)
    with generate_mongodb_oidc_client(juju, substrate, app_name, token) as client:
        assert client.app.reports.insert_one({"_id": uuid4().hex, "number": 3}).acknowledged

    juju.remove_relation(
        f"{app_name}:oauth-certificate-transfer", f"{OAUTH_CERT_OFFER}:send-ca-cert"
    )
    juju.wait(
        lambda status: are_agents_idle(status, app_name, idle_period=30, unit_count=3)
        and does_status_match(
            model_status=status,
            expected_unit_statuses={app_name: [OAuthStatuses.ISSUER_TLS_ERROR.value]},
            expected_app_statuses={},
        )
        and none_is_restarting(status, juju, app_name),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    for unit in juju.status().get_units(app_name):
        run_command_on_server(juju, substrate, unit, f"test ! -e {oauth_ca_path(substrate)}")
        configuration = safe_load(
            read_remote_file(juju, substrate, unit, mongodb_config_path(substrate))
        )
        providers = json.loads(configuration["setParameter"]["oidcIdentityProviders"])
        assert "serverCAFile" not in providers[0], f"{unit} still references the removed CA"

    with generate_mongodb_oidc_client(juju, substrate, app_name, token) as client:
        with pytest.raises(OperationFailure):
            client.app.reports.insert_one({"_id": uuid4().hex, "number": 4})


def test_teardown(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """Remove the remaining OAuth relation and clean up cross-model offers."""
    app_name = existing_app(juju)
    assert app_name
    juju.remove_relation(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, idle_period=30, unit_count=3
        ),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )
    teardown_authentik_offers(juju, juju_k8s_model)
