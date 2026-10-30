# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import ssl
from dataclasses import replace
from unittest.mock import PropertyMock
from urllib.error import HTTPError, URLError

import pytest
from data_platform_helpers.advanced_statuses.models import StatusObject
from ops.model import BlockedStatus
from ops.testing import Relation, Secret
from yaml import safe_dump, safe_load

from single_kernel_mongo.config.literals import RollingOpsCallbackId
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
)
from tests.unit.auth_scenario_helpers import get_relation, mongo_state, mongos_state, oauth_relation

pytest_plugins = ("tests.unit.auth_scenario_helpers",)


@pytest.mark.parametrize("initialised", [True, False])
def test_oauth_hook_checks_reject_shard(
    mock_issuer_tls, mongodb_ctx, mongodb_container, initialised
):
    state_in = mongo_state(mongodb_container, role=MongoDBRoles.SHARD, initialised=initialised)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        with pytest.raises(
            NonDeferrableFailedHookChecksError, match="Cannot integrate OAuth with shard"
        ):
            scenario.charm.operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_require_initialised_database(
    mock_issuer_tls, mongodb_ctx, mongodb_container, role
):
    state_in = mongo_state(mongodb_container, role=role, initialised=False)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        with pytest.raises(DeferrableFailedHookChecksError, match="DB is not initialised"):
            scenario.charm.operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_reject_degraded_vault(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, role
):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.vault_manager, "get_degraded_state", return_value=True)

        with pytest.raises(DeferrableFailedHookChecksError, match="Encryption at rest"):
            operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_reject_refresh_in_progress(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, role
):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(
            type(operator), "refresh_in_progress", new_callable=PropertyMock, return_value=True
        )

        with pytest.raises(DeferrableFailedHookChecksError, match="during a refresh"):
            operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_pass(mock_issuer_tls, mongodb_ctx, mongodb_container, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        scenario.charm.operator.oauth_manager.assert_pass_hook_checks()


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
                "audience": "mongodb",
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
            peer_data={"oauth-issuer": "https://issuer.example"},
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


def test_remove_clears_issuer_and_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    oauth = oauth_relation()
    state_in = mongo_state(
        mongodb_container, peer_data={"oauth-issuer": "https://issuer.example"}, relations={oauth}
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
    restart.assert_called_once_with(force=False)


def test_oauth_provider_update_changes_issuer_replica_set(
    mongodb_ctx, mongodb_container, mocker, registered_oauth
):
    oauth, secret = registered_oauth
    state_in = replace(
        mongo_state(
            mongodb_container, peer_data={"oauth-issuer": "https://old-issuer"}, relations={oauth}
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
    restart.assert_called_once_with(force=False)


def test_oauth_hook_defers_until_database_initialised(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, registered_oauth
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
        peer_data={"oauth-issuer": "https://10.0.0.3"},
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
    first = replace(first, local_app_data={"oauth-issuer": "https://first-issuer"})
    second = replace(second, local_app_data={"oauth-issuer": "https://first-issuer"})
    oauth = oauth_relation("https://first-issuer")
    state_in = mongo_state(
        mongodb_container,
        role=MongoDBRoles.CONFIG_SERVER,
        peer_data={"oauth-issuer": "https://first-issuer"},
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
    restart.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_setups_issuer_from_cluster_relation(mongos_ctx, mongodb_container, leader):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={"oauth-issuer": "https://issuer.example"},
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
def test_mongos_omits_oidc_without_cluster_issuer(
    mock_issuer_tls, mongos_ctx, mongodb_container, leader
):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        assert scenario.charm.operator.config_manager.oauth_parameters == {}


@pytest.mark.parametrize("leader", [True, False])
@pytest.mark.parametrize("issuer", ["https://first-issuer", "https://updated-issuer", ""])
def test_mongos_issuer_change_requests_async_restart(
    mock_issuer_tls,
    mongos_ctx,
    mongodb_container,
    mongos_oauth_restart,
    mongos_cluster,
    leader,
    issuer,
):
    cluster = replace(
        mongos_cluster, remote_app_data={**mongos_cluster.remote_app_data, "oauth-issuer": issuer}
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
    mock_issuer_tls,
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
        remote_app_data={**mongos_cluster.remote_app_data, "oauth-issuer": initial_issuer},
    )
    initial_state = mongos_state(mongodb_container, leader=leader, relations={initial_cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), initial_state) as scenario:
        current = safe_dump(scenario.charm.operator.config_manager.build_config())
    cluster = replace(
        mongos_cluster, remote_app_data={**mongos_cluster.remote_app_data, "oauth-issuer": issuer}
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
    mock_issuer_tls, mongos_ctx, mongodb_container, mongos_oauth_restart, mongos_cluster, leader
):
    initial_cluster = replace(
        mongos_cluster,
        remote_app_data={**mongos_cluster.remote_app_data, "oauth-issuer": "https://first-issuer"},
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
@pytest.mark.parametrize("leader", [True, False])
def test_oauth_relation_blocks_shard(mongodb_ctx, shard_state, mocker):
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.get_statuses",
        return_value=[StatusObject(status="active", message="")],
    )
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(shard_state, relations={*shard_state.relations, oauth})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        scenario.charm.status_handler._recompute_statuses_for_scope(
            "unit", scenario.charm.operator.oauth_manager
        )
        state_out = scenario.run()
    assert state_out.unit_status == BlockedStatus("Cannot integrate OIDC with shard.")


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_relation_does_not_block_supported_roles(
    mock_issuer_tls, mongodb_ctx, mongodb_container, role
):
    state_in = mongo_state(
        mongodb_container,
        role=role,
        relations={Relation(endpoint="oauth", remote_app_name="hydra")},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert scenario.charm.operator.oauth_manager.get_statuses("unit", recompute=True) == []
        assert scenario.charm.operator.oauth_manager.get_statuses("unit") == []


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_issuer_check_uses_system_trust_without_ca(
    mongodb_ctx, mongodb_container, mock_issuer_tls, role
):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator

        assert operator.oauth_manager.check_issuer_connection("https://issuer.example") is None

        mock_issuer_tls.context.assert_called_once_with()
        mock_issuer_tls.request.assert_called_once_with(
            "https://issuer.example/.well-known/openid-configuration",
            context=mock_issuer_tls.context.return_value,
            timeout=5,
        )


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_issuer_check_uses_peer_ca(mongodb_ctx, mongodb_container, mocker, mock_issuer_tls, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        operator.state.app_peer_data.oauth_ca = "root-ca"
        read = mocker.patch.object(operator.workload, "read")

        assert operator.oauth_manager.check_issuer_connection("https://issuer.example:8443") is None

        read.assert_not_called()
        mock_issuer_tls.context.assert_called_once_with(cadata="root-ca")
        mock_issuer_tls.request.assert_called_once_with(
            "https://issuer.example:8443/.well-known/openid-configuration",
            context=mock_issuer_tls.context.return_value,
            timeout=5,
        )


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_issuer_tls_failure_without_ca_blocks(
    mongodb_ctx, mongodb_container, mocker, mock_issuer_tls, role
):
    state_in = mongo_state(
        mongodb_container, role=role, relations={oauth_relation("https://issuer.example")}
    )
    mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()
        state_out = scenario.run()

        assert operator.oauth_manager.get_statuses("unit", recompute=True) == [
            OAuthStatuses.ISSUER_TLS_ERROR.value
        ]
        assert isinstance(state_out.unit_status, BlockedStatus)
        restart.assert_not_called()


def test_issuer_network_failure_reports_waiting(mongodb_ctx, mongodb_container, mock_issuer_tls):
    mock_issuer_tls.request.side_effect = TimeoutError("connection timed out")
    state_in = mongo_state(
        mongodb_container,
    )
    with mongodb_ctx(
        mongodb_ctx.on.collect_unit_status(),
        state_in,
    ) as scenario:
        assert (
            scenario.charm.operator.oauth_manager.check_issuer_connection("https://issuer.example")
            == OAuthStatuses.ISSUER_UNREACHABLE.value
        )


def test_successful_issuer_check_clears_tls_block(
    mongodb_ctx, mongodb_container, mocker, mock_issuer_tls
):
    state_in = mongo_state(mongodb_container, relations={oauth_relation("https://issuer.example")})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "read", return_value=["{}"])
        mocker.patch.object(operator, "async_restart_charm_services")
        operator.state.statuses.add(
            OAuthStatuses.ISSUER_TLS_ERROR.value,
            scope="unit",
            component=operator.oauth_manager.name,
        )

        operator.oauth_manager.configure()

        assert OAuthStatuses.ISSUER_TLS_ERROR.value not in operator.oauth_manager.get_statuses(
            "unit"
        )


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
@pytest.mark.parametrize("field", ["issuer", "token_endpoint", "jwks_uri"])
def test_discovery_mismatch_blocks_configuration(
    mongodb_ctx, mongodb_container, mocker, mock_issuer_tls, role, field
):
    issuer = "https://issuer.example"
    document = {
        "issuer": issuer,
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        field: "https://unexpected.example",
    }
    response = mocker.MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(document)
    mock_issuer_tls.request.side_effect = None
    mock_issuer_tls.request.return_value = response
    state_in = mongo_state(mongodb_container, role=role, relations={oauth_relation(issuer)})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()

        assert operator.oauth_manager.get_statuses("unit") == [
            OAuthStatuses.INVALID_DISCOVERY.value
        ]
        restart.assert_not_called()


@pytest.mark.parametrize("body", ["not json", "[]", "{}", '{"issuer": "https://issuer.example"}'])
def test_invalid_discovery_metadata_is_blocked(
    mongodb_ctx, mongodb_container, mocker, mock_issuer_tls, body
):
    response = mocker.MagicMock()
    response.__enter__.return_value.read.return_value = body
    mock_issuer_tls.request.side_effect = None
    mock_issuer_tls.request.return_value = response
    state_in = mongo_state(
        mongodb_container,
    )
    with mongodb_ctx(
        mongodb_ctx.on.collect_unit_status(),
        state_in,
    ) as scenario:
        assert (
            scenario.charm.operator.oauth_manager.check_issuer_connection("https://issuer.example")
            == OAuthStatuses.INVALID_DISCOVERY.value
        )


def test_discovery_http_error_is_blocked(mongodb_ctx, mongodb_container, mock_issuer_tls):
    mock_issuer_tls.request.side_effect = HTTPError(
        "https://issuer.example/.well-known/openid-configuration", 404, "Not Found", None, None
    )
    state_in = mongo_state(
        mongodb_container,
    )
    with mongodb_ctx(
        mongodb_ctx.on.collect_unit_status(),
        state_in,
    ) as scenario:
        assert (
            scenario.charm.operator.oauth_manager.check_issuer_connection("https://issuer.example")
            == OAuthStatuses.INVALID_DISCOVERY.value
        )


def test_discovery_uses_issuer_path(mongodb_ctx, mongodb_container, mock_issuer_tls):
    issuer = "https://issuer.example/tenant"
    state_in = mongo_state(mongodb_container, relations={oauth_relation(issuer)})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert scenario.charm.operator.oauth_manager.check_issuer_connection(issuer) is None

        mock_issuer_tls.request.assert_called_once_with(
            f"{issuer}/.well-known/openid-configuration",
            context=mock_issuer_tls.context.return_value,
            timeout=5,
        )


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
@pytest.mark.parametrize("previous_issuer", ["", "https://previous.example"])
def test_failed_validation_preserves_stored_and_shared_issuer(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, role, previous_issuer
):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="mongos",
        remote_app_data={"database": "mongos"},
        local_app_data={"oauth-issuer": previous_issuer},
    )
    state_in = mongo_state(
        mongodb_container,
        role=role,
        peer_data={"oauth-issuer": previous_issuer},
        relations={cluster, oauth_relation("https://new.example")},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(
            operator.oauth_manager,
            "check_issuer_connection",
            return_value=OAuthStatuses.INVALID_DISCOVERY.value,
        )
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()
        state_out = scenario.run()

    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data.get(
            "oauth-issuer", ""
        )
        == previous_issuer
    )
    assert (
        state_out.get_relation(cluster.id).local_app_data.get("oauth-issuer", "") == previous_issuer
    )
    assert isinstance(state_out.unit_status, BlockedStatus)
    restart.assert_not_called()
