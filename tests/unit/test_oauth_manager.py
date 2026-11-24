# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from dataclasses import replace
from unittest.mock import PropertyMock, patch

import pytest
import requests
from data_platform_helpers.advanced_statuses.models import StatusObject
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Relation, Secret
from yaml import safe_dump, safe_load

from single_kernel_mongo.config.literals import RollingOpsCallbackId
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    OauthIssuerTLSError,
    OauthIssuerUnreachableError,
    OauthProviderDataMissingError,
)
from single_kernel_mongo.managers.oauth import OAuthManager
from tests.unit.auth_scenario_helpers import (
    get_relation,
    mongo_state,
    mongos_state,
    oauth_relation,
)

pytest_plugins = ("tests.unit.auth_scenario_helpers",)
pytestmark = pytest.mark.usefixtures("isolate_oauth_events")


@pytest.mark.parametrize("initialised", [True, False])
def test_oauth_hook_checks_reject_shard(mongodb_ctx, mongodb_container, initialised):
    state_in = mongo_state(mongodb_container, role=MongoDBRoles.SHARD, initialised=initialised)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        with pytest.raises(
            NonDeferrableFailedHookChecksError, match="Cannot integrate OAuth with shard"
        ):
            scenario.charm.operator.oauth_manager._assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_require_initialised_database(mongodb_ctx, mongodb_container, role):
    state_in = mongo_state(mongodb_container, role=role, initialised=False)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        with pytest.raises(DeferrableFailedHookChecksError, match="DB is not initialised"):
            scenario.charm.operator.oauth_manager._assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_reject_degraded_vault(mongodb_ctx, mongodb_container, mocker, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.vault_manager, "get_degraded_state", return_value=True)

        with pytest.raises(DeferrableFailedHookChecksError, match="Encryption at rest"):
            operator.oauth_manager._assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_reject_refresh_in_progress(mongodb_ctx, mongodb_container, mocker, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(
            type(operator), "refresh_in_progress", new_callable=PropertyMock, return_value=True
        )

        with pytest.raises(DeferrableFailedHookChecksError, match="during a refresh"):
            operator.oauth_manager._assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_pass(mongodb_ctx, mongodb_container, role):
    with mongodb_ctx(
        mongodb_ctx.on.collect_unit_status(), mongo_state(mongodb_container, role=role)
    ) as scenario:
        scenario.charm.operator.oauth_manager._assert_pass_hook_checks()


def test_oauth_info_changed_rejects_shards(mongodb_ctx, mongodb_container, caplog):
    secret = Secret(tracked_content={"secret": "client-secret"})
    oauth = oauth_relation(client_id="client-id", client_secret_id=secret.id)
    state_in = replace(
        mongo_state(
            mongodb_container,
            role=MongoDBRoles.SHARD,
            initialised=True,
            relations={oauth},
        ),
        secrets={secret},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(get_relation(state_in, "oauth")), state_in
    ) as scenario:
        state_out = scenario.run()

    assert "Cannot integrate OAuth with shard" in caplog.text
    assert (
        "oauth-issuer" not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    assert not state_out.deferred


def test_oauth_info_changed_shares_issuer_and_requests_restart_replica_set(
    mongodb_ctx, mongodb_container, mocker
):
    secret = Secret(tracked_content={"secret": "client-secret"})
    state_in = replace(
        mongo_state(
            mongodb_container,
            relations={
                oauth_relation(
                    "https://10.0.0.3", client_id="client-id", client_secret_id=secret.id
                )
            },
        ),
        secrets={secret},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(get_relation(state_in, "oauth")),
        state_in,
    ) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

        assert operator.state.app_peer_data.oauth_issuer == "https://10.0.0.3"
        parameters = operator.config_manager.build_config()["setParameter"]
        assert parameters["authenticationMechanisms"] == "SCRAM-SHA-256,MONGODB-OIDC"
        assert json.loads(parameters["oidcIdentityProviders"]) == [
            {
                "issuer": "https://10.0.0.3",
                "audience": "client-id",
                "authNamePrefix": "oauth",
                "principalName": "sub",
                "useAuthorizationClaim": True,
                "authorizationClaim": "groups",
                "supportsHumanFlows": False,
            }
        ]
        restart.assert_called_once_with(force=False)
    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == "https://10.0.0.3"
    )


def test_oauth_info_changed_does_not_restart_unchanged_configuration_replica_set(
    mongodb_ctx, mongodb_container, mocker
):
    secret = Secret(tracked_content={"secret": "client-secret"})
    state_in = replace(
        mongo_state(
            mongodb_container,
            peer_data={"oauth-issuer": "https://issuer.example", "oauth-client-id": "client-id"},
            relations={oauth_relation(client_id="client-id", client_secret_id=secret.id)},
        ),
        secrets={secret},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(get_relation(state_in, "oauth")),
        state_in,
    ) as scenario:
        operator = scenario.charm.operator
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.config_manager.workload, "read", return_value=[current])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

        restart.assert_not_called()


def test_oauth_info_removed_clears_issuer_and_requests_restart_replica_set(
    mongodb_ctx, mongodb_container, mocker
):
    oauth = oauth_relation()
    state_in = mongo_state(
        mongodb_container,
        peer_data={"oauth-issuer": "https://issuer.example", "oauth-client-id": "client-id"},
        relations={oauth},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_broken(get_relation(state_in, "oauth")), state_in
    ) as scenario:
        operator = scenario.charm.operator
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.config_manager.workload, "read", return_value=[current])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert (
        "oauth-issuer" not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    assert (
        "oauth-client-id"
        not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    restart.assert_called_once_with(force=False)


def test_oauth_provider_update_changes_issuer_replica_set(
    mongodb_ctx, mongodb_container, mocker, registered_oauth
):
    oauth, secret = registered_oauth
    state_in = replace(
        mongo_state(
            mongodb_container,
            peer_data={"oauth-issuer": "https://old-issuer", "oauth-client-id": "old-client-id"},
            relations={oauth},
        ),
        secrets={secret},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(get_relation(state_in, "oauth")),
        state_in,
    ) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == "https://new-issuer"
    )
    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-client-id"]
        == "client-id"
    )
    restart.assert_called_once_with(force=False)


def test_oauth_hook_defers_until_database_initialised_replica_set(
    mongodb_ctx, mongodb_container, mocker, registered_oauth
):
    oauth, secret = registered_oauth
    state_in = replace(
        mongo_state(mongodb_container, initialised=False, relations={oauth}), secrets={secret}
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(get_relation(state_in, "oauth")),
        state_in,
    ) as scenario:
        restart = mocker.patch.object(scenario.charm.operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert len(state_out.deferred) == 1
    restart.assert_not_called()


def test_oauth_follower_restarts_from_shared_issuer_replica_set(
    mongodb_ctx, mongodb_container, mocker
):
    state_in = mongo_state(
        mongodb_container,
        leader=False,
        peer_data={"oauth-issuer": "https://10.0.0.3", "oauth-client-id": "client-id"},
        peers_data={1: {}},
    )
    peer = get_relation(state_in, PeerRelationNames.PEERS.value)
    with mongodb_ctx(mongodb_ctx.on.relation_changed(peer, remote_unit=1), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator, "peer_changed")
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

    restart.assert_called_once_with(force=False)


def test_oauth_info_removed_config_server_publishes_removal(
    mongodb_ctx, mongodb_container, mocker, config_server_relations
):
    first, second, pending = config_server_relations
    first = replace(
        first,
        local_app_data={"oauth-issuer": "https://first-issuer", "oauth-client-id": "first-client"},
    )
    second = replace(
        second,
        local_app_data={"oauth-issuer": "https://first-issuer", "oauth-client-id": "first-client"},
    )
    oauth = oauth_relation("https://first-issuer")
    state_in = mongo_state(
        mongodb_container,
        role=MongoDBRoles.CONFIG_SERVER,
        peer_data={"oauth-issuer": "https://first-issuer", "oauth-client-id": "first-client"},
        relations={first, second, pending, oauth},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_broken(get_relation(state_in, "oauth")), state_in
    ) as scenario:
        restart = mocker.patch.object(scenario.charm.operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert "oauth-issuer" not in state_out.get_relation(first.id).local_app_data
    assert "oauth-issuer" not in state_out.get_relation(second.id).local_app_data
    assert (
        "oauth-issuer" not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    assert "oauth-client-id" not in state_out.get_relation(first.id).local_app_data
    assert "oauth-client-id" not in state_out.get_relation(second.id).local_app_data
    assert (
        "oauth-client-id"
        not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    restart.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_setups_issuer_from_cluster_relation(mongos_ctx, mongodb_container, leader):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={"oauth-issuer": "https://issuer.example", "oauth-client-id": "client-id"},
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        parameters = scenario.charm.operator.config_manager.oauth_parameters
        assert (
            parameters["setParameter"]["authenticationMechanisms"] == "SCRAM-SHA-256,MONGODB-OIDC"
        )
        assert (
            json.loads(parameters["setParameter"]["oidcIdentityProviders"])[0]["issuer"]
            == "https://issuer.example"
        )


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_omits_oidc_without_cluster_issuer(mongos_ctx, mongodb_container, leader):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        assert scenario.charm.operator.config_manager.oauth_parameters == {}


@pytest.mark.parametrize("leader", [True, False])
@pytest.mark.parametrize("issuer", ["https://first-issuer", "https://updated-issuer", ""])
def test_mongos_issuer_change_requests_async_restart(
    mongos_ctx, mongodb_container, mongos_oauth_restart, mongos_cluster, leader, issuer
):
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": issuer,
            "oauth-client-id": "client-id",
        },
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_oauth_restart(state_in, mongos_ctx.on.relation_changed(cluster)) as context:
        context.scenario.run()

        context.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        context.write.assert_not_called()
        context.restart.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
@pytest.mark.parametrize(
    ("initial_issuer", "issuer"),
    [
        pytest.param("", "https://first-issuer", id="initial-issuer"),
        pytest.param("https://first-issuer", "https://updated-issuer", id="updated-issuer"),
    ],
)
def test_mongos_rolling_restart_writes_issuer(
    mongos_ctx,
    mongodb_container,
    mongos_oauth_restart,
    mongos_cluster,
    leader,
    initial_issuer,
    issuer,
):
    initial_cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": initial_issuer,
            "oauth-client-id": "client-id",
        },
    )
    initial_state = mongos_state(mongodb_container, leader=leader, relations={initial_cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), initial_state) as scenario:
        current = safe_dump(scenario.charm.operator.config_manager.build_config())
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": issuer,
            "oauth-client-id": "client-id",
        },
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_oauth_restart(state_in, mongos_ctx.on.collect_unit_status(), current) as context:
        context.cluster.update_mongos_and_restart(force=False)

        context.write.assert_called_once()
        path, content = context.write.call_args.args
        assert path == context.config.file
        parameters = safe_load(content)["setParameter"]
        assert json.loads(parameters["oidcIdentityProviders"])[0]["issuer"] == issuer
        assert parameters["authenticationMechanisms"] == "SCRAM-SHA-256,MONGODB-OIDC"
        context.restart.assert_called_once()


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_rolling_restart_removes_oidc(
    mongos_ctx, mongodb_container, mongos_oauth_restart, mongos_cluster, leader
):
    initial_cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://first-issuer",
            "oauth-client-id": "client-id",
        },
    )
    initial_state = mongos_state(mongodb_container, leader=leader, relations={initial_cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), initial_state) as scenario:
        current = safe_dump(scenario.charm.operator.config_manager.build_config())
    state_in = mongos_state(mongodb_container, leader=leader, relations={mongos_cluster})
    with mongos_oauth_restart(state_in, mongos_ctx.on.collect_unit_status(), current) as context:
        context.cluster.update_mongos_and_restart(force=False)

        context.write.assert_called_once()
        path, content = context.write.call_args.args
        assert path == context.config.file
        parameters = safe_load(content)["setParameter"]
        assert "oidcIdentityProviders" not in parameters
        assert "MONGODB-OIDC" not in parameters.get("authenticationMechanisms", "")
        context.restart.assert_called_once()


@pytest.mark.parametrize("initialised", [True, False])
@pytest.mark.parametrize("leader", [True])
def test_oauth_relation_blocks_shard(mongodb_ctx, shard_state, mocker, initialised):
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.get_statuses",
        return_value=[StatusObject(status="active", message="")],
    )
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(shard_state, relations={*shard_state.relations, oauth})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        with pytest.raises(NonDeferrableFailedHookChecksError):
            scenario.charm.operator.oauth_manager._assert_pass_hook_checks()
        statuses = scenario.charm.operator.oauth_manager.get_statuses("app", recompute=True)
        assert statuses == [OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value]
        state_out = scenario.run()
    assert state_out.unit_status == ActiveStatus()
    assert state_out.app_status == BlockedStatus("Cannot integrate OIDC with shard.")


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_relation_does_not_block_supported_roles(
    mongodb_ctx, mongodb_container, registered_oauth, role
):
    oauth, secret = registered_oauth
    state_in = replace(
        mongo_state(
            mongodb_container,
            role=role,
            peer_data={"oauth-issuer": "https://new-issuer", "oauth-client-id": "client-id"},
            relations={oauth},
        ),
        secrets={secret},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert scenario.charm.operator.oauth_manager.get_statuses("unit", recompute=True) == [
            OAuthStatuses.ACTIVE_IDLE.value
        ]
        assert scenario.charm.operator.oauth_manager.get_statuses("unit") == []


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_update_status_waits_for_missing_oauth_provider_data(
    mongodb_ctx, mongodb_container, mocker, role
):
    state_in = mongo_state(
        mongodb_container,
        role=role,
        relations={Relation(endpoint="oauth", remote_app_name="hydra")},
    )
    with mongodb_ctx(mongodb_ctx.on.update_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(
            operator.config_manager, "file_has_oauth_configuration", return_value=False
        )
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

        manager = operator.oauth_manager
        assert manager.get_statuses("unit") == [OAuthStatuses.WAITING_FOR_OAUTH_DATA.value]
        restart.assert_not_called()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
@pytest.mark.parametrize(
    "failure, expected_status",
    [
        (requests.exceptions.SSLError("untrusted CA"), OAuthStatuses.ISSUER_TLS_ERROR.value),
        (requests.Timeout("issuer timed out"), OAuthStatuses.ISSUER_UNREACHABLE.value),
        (None, OAuthStatuses.INVALID_DISCOVERY.value),
    ],
    ids=["tls-error", "unreachable", "invalid-discovery"],
)
def test_update_status_reports_provider_failure_without_restarting(
    mongodb_ctx, mongodb_container, mocker, registered_oauth, role, failure, expected_status
):
    oauth, secret = registered_oauth
    state_in = replace(
        mongo_state(
            mongodb_container,
            role=role,
            peer_data={"oauth-issuer": "https://new-issuer", "oauth-client-id": "client-id"},
            relations={oauth},
        ),
        secrets={secret},
    )
    with mongodb_ctx(mongodb_ctx.on.update_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch(
            "single_kernel_mongo.managers.oauth.OAuthManager._fetch_issuer_discovery",
            side_effect=failure,
            return_value=b"not json",
        )
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

        manager = operator.oauth_manager
        assert manager.get_statuses("unit") == [expected_status]
        assert manager.get_statuses("unit", recompute=True) == [expected_status]
        assert manager.get_statuses("app", recompute=True) == []
        restart.assert_not_called()
        assert (
            get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
            == "https://new-issuer"
        )
        assert not state_out.deferred


def test_check_provider_returns_none_on_success(provider):
    document = {
        "issuer": provider.issuer_url,
        "token_endpoint": provider.token_endpoint,
        "jwks_uri": provider.jwks_endpoint,
    }
    with patch.object(OAuthManager, "_fetch_issuer_discovery", return_value=json.dumps(document)):
        assert OAuthManager._check_provider_connection(provider, None) is None
        manager = object.__new__(OAuthManager)
        assert manager._get_provider_connection_status(provider, None) is None


@pytest.mark.parametrize(
    "error, expected_error, expected_status",
    [
        (requests.Timeout(), OauthIssuerUnreachableError, OAuthStatuses.ISSUER_UNREACHABLE.value),
        (
            requests.exceptions.SSLError(),
            OauthIssuerTLSError,
            OAuthStatuses.ISSUER_TLS_ERROR.value,
        ),
    ],
)
def test_transport_failure_classification(provider, error, expected_error, expected_status):
    with patch.object(OAuthManager, "_fetch_issuer_discovery", side_effect=error):
        with pytest.raises(expected_error):
            OAuthManager._check_provider_connection(provider, None)
        manager = object.__new__(OAuthManager)
        assert manager._get_provider_connection_status(provider, None) == expected_status


def test_missing_provider():
    with pytest.raises(OauthProviderDataMissingError):
        OAuthManager._check_provider_connection(None, None)
    manager = object.__new__(OAuthManager)
    assert (
        manager._get_provider_connection_status(None, None)
        == OAuthStatuses.WAITING_FOR_OAUTH_DATA.value
    )


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_client_id_change_with_same_issuer_updates_configuration(
    mongodb_ctx, mongodb_container, mocker, registered_oauth, config_server_relations, role
):
    oauth, secret = registered_oauth
    first, second, pending = config_server_relations
    routers = {first, second, pending} if role == MongoDBRoles.CONFIG_SERVER else set()
    state_in = replace(
        mongo_state(
            mongodb_container,
            role=role,
            peer_data={"oauth-issuer": "https://new-issuer", "oauth-client-id": "old-client-id"},
            relations={oauth, *routers},
        ),
        secrets={secret},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(oauth), state_in) as scenario:
        operator = scenario.charm.operator
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.workload, "read", return_value=current.splitlines())
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

        peer = get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
        assert peer["oauth-issuer"] == "https://new-issuer"
        assert peer["oauth-client-id"] == "client-id"
        if role == MongoDBRoles.REPLICATION:
            providers = json.loads(
                operator.config_manager.build_config()["setParameter"]["oidcIdentityProviders"]
            )
            assert providers[0]["audience"] == "client-id"
            restart.assert_called_once_with(force=False)
        else:
            for router in (first, second):
                data = state_out.get_relation(router.id).local_app_data
                assert data["oauth-issuer"] == "https://new-issuer"
                assert data["oauth-client-id"] == "client-id"
            assert "oauth-client-id" not in state_out.get_relation(pending.id).local_app_data
            restart.assert_not_called()
