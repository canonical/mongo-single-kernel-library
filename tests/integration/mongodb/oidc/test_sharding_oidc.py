#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for OIDC authentication on a sharded MongoDB cluster."""

from uuid import uuid4

import jubilant
import pytest
from pymongo.errors import OperationFailure

from single_kernel_mongo.config.statuses import OAuthStatuses
from tests.integration.helpers.constants import (
    CLUSTER_COMPONENTS,
    CONFIG_SERVER_APP_NAME,
    DEPLOYMENT_TIMEOUT,
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
    teardown_authentik_offers,
)
from tests.integration.helpers.jubilant_sharding import (
    deploy_cluster_components,
    integrate_sharding_components,
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
) -> None:
    """Deploy the config server and two shards, then create the OIDC role through Mongos."""
    deploy_cluster_components(
        juju,
        substrate=substrate,
        mongodb_charm=mongodb_charm,
        mongod_resource=mongod_resource,
    )
    integrate_sharding_components(juju)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    create_mongodb_oidc_role(juju, substrate, CONFIG_SERVER_APP_NAME, mongos=True)


def test_deploy_authentik(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """Deploy Authentik and wait until its supporting applications are ready."""
    deploy_authentik(juju_k8s_model)
    consume_authentik_offers(juju, juju_k8s_model)
    user_id, password = create_authentik_user_and_group(juju_k8s_model)

    assert user_id > 0
    assert password


def test_integrate_oauth_only(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """OIDC with a self-signed issuer is blocked until its CA is received."""
    app_name = CONFIG_SERVER_APP_NAME

    juju.integrate(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")

    juju.wait(
        lambda status: are_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30)
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
    """The config server distributes the issuer CA and enables OIDC on Mongos."""
    app_name = CONFIG_SERVER_APP_NAME
    juju.integrate(f"{app_name}:oauth-certificate-transfer", f"{OAUTH_CERT_OFFER}:send-ca-cert")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30),
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
    app_name = CONFIG_SERVER_APP_NAME
    token = get_oidc_access_token(juju, juju_k8s_model, substrate, app_name)
    document = {"_id": uuid4().hex, "number": 1}

    with generate_mongodb_oidc_client(juju, substrate, app_name, token, mongos=True) as client:
        authenticated = client.admin.command("connectionStatus")
        assert authenticated["authInfo"]["authenticatedUsers"]

        inserted = client.app.reports.insert_one(document)
        assert inserted.acknowledged

        report = client.app.reports.find_one({"_id": document["_id"]})
        assert report == document


def test_remove_oauth_disables_oidc_and_prevents_writes(
    juju: jubilant.Juju, substrate: Substrate, juju_k8s_model: jubilant.Juju
) -> None:
    """Removing OAuth disables token authentication while the cluster remains active."""
    app_name = CONFIG_SERVER_APP_NAME
    token = get_oidc_access_token(juju, juju_k8s_model, substrate, app_name)
    juju.remove_relation(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30)
        and none_is_restarting(status, juju, app_name),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    with generate_mongodb_oidc_client(juju, substrate, app_name, token, mongos=True) as client:
        with pytest.raises(OperationFailure):
            client.app.reports.insert_one({"_id": uuid4().hex, "number": 2})


def test_restore_oauth_then_remove_certificates_prevents_writes(
    juju: jubilant.Juju, substrate: Substrate, juju_k8s_model: jubilant.Juju
) -> None:
    """Restoring OAuth enables access; removing its self-signed CA blocks it again."""
    app_name = CONFIG_SERVER_APP_NAME
    juju.integrate(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    configure_authentik_signing_key(juju, juju_k8s_model, app_name)
    token = get_oidc_access_token(juju, juju_k8s_model, substrate, app_name)
    with generate_mongodb_oidc_client(juju, substrate, app_name, token, mongos=True) as client:
        assert client.app.reports.insert_one({"_id": uuid4().hex, "number": 3}).acknowledged

    juju.remove_relation(
        f"{app_name}:oauth-certificate-transfer", f"{OAUTH_CERT_OFFER}:send-ca-cert"
    )
    juju.wait(
        lambda status: are_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30)
        and does_status_match(
            model_status=status,
            expected_unit_statuses={app_name: [OAuthStatuses.ISSUER_TLS_ERROR.value]},
            expected_app_statuses={},
        )
        and none_is_restarting(status, juju, CONFIG_SERVER_APP_NAME),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )

    with generate_mongodb_oidc_client(juju, substrate, app_name, token, mongos=True) as client:
        with pytest.raises(OperationFailure):
            client.app.reports.insert_one({"_id": uuid4().hex, "number": 4})


def test_teardown(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju) -> None:
    """Remove the remaining OAuth relation and clean up cross-model offers."""
    app_name = CONFIG_SERVER_APP_NAME
    juju.remove_relation(f"{app_name}:oauth", f"{OAUTH_OFFER}:oauth")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, *CLUSTER_COMPONENTS, idle_period=30),
        timeout=DEPLOYMENT_TIMEOUT,
        delay=5,
        successes=3,
    )
    teardown_authentik_offers(juju, juju_k8s_model)
