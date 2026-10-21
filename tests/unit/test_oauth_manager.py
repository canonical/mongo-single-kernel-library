# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import ssl
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import PropertyMock
from urllib.error import HTTPError, URLError

import pytest
from data_platform_helpers.advanced_statuses.models import StatusObject
from ops.model import BlockedStatus
from ops.testing import Relation, Secret
from yaml import safe_dump, safe_load

from single_kernel_mongo.config.literals import RollingOpsCallbackId
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
)
from tests.unit.auth_scenario_helpers import get_relation, mongo_state, mongos_state, oauth_relation


@pytest.fixture(autouse=True)
def mock_issuer_tls(mocker):
    """Keep issuer checks offline and expose the TLS context to connection tests."""
    context = mocker.patch("single_kernel_mongo.managers.oauth.ssl.create_default_context")

    def discovery_response(url, **kwargs):
        issuer = url.removesuffix("/.well-known/openid-configuration")
        response = mocker.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"issuer": issuer, "token_endpoint": f"{issuer}/token", "jwks_uri": f"{issuer}/jwks"}
        )
        return response

    request = mocker.patch(
        "single_kernel_mongo.managers.oauth.urlopen", side_effect=discovery_response
    )
    return SimpleNamespace(context=context, request=request)


@pytest.mark.parametrize("initialised", [True, False])
def test_oauth_hook_checks_reject_shard(mongodb_ctx, mongodb_container, initialised):
    state_in = mongo_state(mongodb_container, role=MongoDBRoles.SHARD, initialised=initialised)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        with pytest.raises(
            NonDeferrableFailedHookChecksError, match="Cannot integrate OAuth with shard"
        ):
            scenario.charm.operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_require_initialised_database(mongodb_ctx, mongodb_container, role):
    state_in = mongo_state(mongodb_container, role=role, initialised=False)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        with pytest.raises(DeferrableFailedHookChecksError, match="DB is not initialised"):
            scenario.charm.operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_reject_degraded_vault(mongodb_ctx, mongodb_container, mocker, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.vault_manager, "get_degraded_state", return_value=True)

        with pytest.raises(DeferrableFailedHookChecksError, match="Encryption at rest"):
            operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_reject_refresh_in_progress(mongodb_ctx, mongodb_container, mocker, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(
            type(operator), "refresh_in_progress", new_callable=PropertyMock, return_value=True
        )

        with pytest.raises(DeferrableFailedHookChecksError, match="during a refresh"):
            operator.oauth_manager.assert_pass_hook_checks()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_hook_checks_pass(mongodb_ctx, mongodb_container, role):
    with mongodb_ctx(
        mongodb_ctx.on.collect_unit_status(), mongo_state(mongodb_container, role=role)
    ) as scenario:
        scenario.charm.operator.oauth_manager.assert_pass_hook_checks()


def test_configure_shares_issuer_and_requests_restart(mongodb_ctx, mongodb_container, mocker):
    state_in = mongo_state(mongodb_container, relations={oauth_relation("https://10.0.0.3")})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()

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
        state_out = scenario.run()
    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == "https://10.0.0.3"
    )


def test_configure_does_not_restart_unchanged_configuration(mongodb_ctx, mongodb_container, mocker):
    state_in = mongo_state(
        mongodb_container,
        peer_data={"oauth-issuer": "https://issuer.example"},
        relations={oauth_relation()},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.config_manager.workload, "read", return_value=[current])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()

        restart.assert_not_called()


def test_remove_clears_issuer_and_requests_restart(mongodb_ctx, mongodb_container, mocker):
    oauth = oauth_relation()
    state_in = mongo_state(
        mongodb_container, peer_data={"oauth-issuer": "https://issuer.example"}, relations={oauth}
    )
    with mongodb_ctx(mongodb_ctx.on.relation_broken(oauth), state_in) as scenario:
        operator = scenario.charm.operator
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.config_manager.workload, "read", return_value=[current])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert (
        "oauth-issuer" not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    restart.assert_called_once_with(force=False)


@pytest.fixture
def registered_oauth():
    secret = Secret(tracked_content={"secret": "client-secret"})
    oauth = oauth_relation("https://new-issuer", client_id="client-id", client_secret_id=secret.id)
    return oauth, secret


def test_oauth_provider_update_changes_issuer(
    mongodb_ctx, mongodb_container, mocker, registered_oauth
):
    oauth, secret = registered_oauth
    state_in = replace(
        mongo_state(
            mongodb_container, peer_data={"oauth-issuer": "https://old-issuer"}, relations={oauth}
        ),
        secrets={secret},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(oauth), state_in) as scenario:
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
    mongodb_ctx, mongodb_container, mocker, registered_oauth
):
    oauth, secret = registered_oauth
    state_in = replace(
        mongo_state(mongodb_container, initialised=False, relations={oauth}), secrets={secret}
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(oauth), state_in) as scenario:
        restart = mocker.patch.object(scenario.charm.operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert len(state_out.deferred) == 1
    restart.assert_not_called()


def test_oauth_follower_restarts_from_shared_issuer(mongodb_ctx, mongodb_container, mocker):
    state_in = mongo_state(
        mongodb_container, leader=False, peer_data={"oauth-issuer": "https://10.0.0.3"}
    )
    original_peer = get_relation(state_in, PeerRelationNames.PEERS.value)
    peer = replace(original_peer, peers_data={1: {}})
    state_in = replace(state_in, relations=(state_in.relations - {original_peer}) | {peer})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(peer, remote_unit=1), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator, "peer_changed")
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

    restart.assert_called_once_with(force=False)


@pytest.fixture
def config_server_relations():
    return (
        Relation(
            endpoint="cluster", remote_app_name="mongos-one", remote_app_data={"database": "mongos"}
        ),
        Relation(
            endpoint="cluster", remote_app_name="mongos-two", remote_app_data={"database": "mongos"}
        ),
        Relation(endpoint="cluster", remote_app_name="pending"),
    )


@pytest.mark.parametrize(
    ("previous_issuer", "issuer"),
    [("", "https://first-issuer"), ("https://first-issuer", "https://second-issuer")],
)
def test_config_server_publishes_updates(
    mongodb_ctx, mongodb_container, mocker, config_server_relations, previous_issuer, issuer
):
    first, second, pending = config_server_relations
    first = replace(first, local_app_data={"oauth-issuer": previous_issuer})
    second = replace(second, local_app_data={"oauth-issuer": previous_issuer})
    state_in = mongo_state(
        mongodb_container,
        role=MongoDBRoles.CONFIG_SERVER,
        peer_data={"oauth-issuer": previous_issuer},
        relations={first, second, pending, oauth_relation(issuer)},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()

        assert "oidcIdentityProviders" not in operator.config_manager.build_config()["setParameter"]
        state_out = scenario.run()
    assert state_out.get_relation(first.id).local_app_data["oauth-issuer"] == issuer
    assert state_out.get_relation(second.id).local_app_data["oauth-issuer"] == issuer
    assert "oauth-issuer" not in state_out.get_relation(pending.id).local_app_data
    restart.assert_not_called()


def test_config_server_publishes_removal(
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
    with mongodb_ctx(mongodb_ctx.on.relation_broken(oauth), state_in) as scenario:
        restart = mocker.patch.object(scenario.charm.operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert "oauth-issuer" not in state_out.get_relation(first.id).local_app_data
    assert "oauth-issuer" not in state_out.get_relation(second.id).local_app_data
    assert (
        "oauth-issuer" not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    restart.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_renders_issuer_from_cluster_relation(mongos_ctx, mongodb_container, leader):
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
def test_mongos_omits_oidc_without_cluster_issuer(mongos_ctx, mongodb_container, leader):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        assert scenario.charm.operator.config_manager.oauth_parameters == {}


@pytest.fixture
def mongos_oauth_restart(mongos_ctx, mocker):
    @contextmanager
    def run(state_in, event, current="{}"):
        with mongos_ctx(event, state_in) as scenario:
            operator = scenario.charm.operator
            cluster = operator.cluster_manager
            config = operator.config_manager
            mocker.patch.object(cluster, "assert_pass_hook_checks")
            mocker.patch.object(cluster, "share_credentials_to_clients")
            mocker.patch.object(cluster, "_set_ldap_user_to_dn")
            mocker.patch.object(cluster, "_set_cluster_id")
            mocker.patch.object(operator, "update_keyfile", return_value=False)
            mocker.patch.object(operator, "update_config_server_db", return_value=False)
            mocker.patch("pathlib.Path.unlink")
            request = mocker.patch.object(operator.rollingops_manager, "request_async_lock")
            mocker.patch.object(config.workload, "read", return_value=[current])
            mocker.patch.object(config.workload, "active", return_value=True)
            write = mocker.patch.object(config.workload, "write")
            restart = mocker.patch.object(config.workload, "restart")
            yield SimpleNamespace(
                scenario=scenario,
                cluster=cluster,
                config=config,
                request=request,
                write=write,
                restart=restart,
            )

    return run


@pytest.fixture
def mongos_cluster():
    return Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.1:27017",
        },
    )


@pytest.mark.parametrize("leader", [True, False])
@pytest.mark.parametrize("issuer", ["https://first-issuer", "https://updated-issuer", ""])
def test_mongos_issuer_change_requests_async_restart(
    mongos_ctx, mongodb_container, mongos_oauth_restart, mongos_cluster, leader, issuer
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
    state_in = mongos_state(mongodb_container, leader=leader, relations={initial_cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        current = safe_dump(scenario.charm.operator.config_manager.build_config())
    cluster = replace(
        mongos_cluster, remote_app_data={**mongos_cluster.remote_app_data, "oauth-issuer": issuer}
    )
    state_in = replace(state_in, relations=(state_in.relations - {initial_cluster}) | {cluster})
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
        remote_app_data={**mongos_cluster.remote_app_data, "oauth-issuer": "https://first-issuer"},
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={initial_cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        current = safe_dump(scenario.charm.operator.config_manager.build_config())
    state_in = replace(
        state_in, relations=(state_in.relations - {initial_cluster}) | {mongos_cluster}
    )
    with mongos_oauth_restart(state_in, mongos_ctx.on.collect_unit_status(), current) as context:
        context.cluster.update_mongos_and_restart(force=False)

        context.write.assert_called_once()
        path, content = context.write.call_args.args
        assert path == context.config.file
        parameters = safe_load(content)["setParameter"]
        assert "oidcIdentityProviders" not in parameters
        assert "MONGODB-OIDC" not in parameters.get("authenticationMechanisms", "")
        context.restart.assert_called_once()


@pytest.fixture
def shard_state(mongodb_container, initialised, leader):
    return mongo_state(
        mongodb_container, role=MongoDBRoles.SHARD, initialised=initialised, leader=leader
    )


@pytest.fixture
def isolate_shard_status(mocker):
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.get_statuses",
        return_value=[StatusObject(status="active", message="")],
    )


@pytest.mark.parametrize("initialised", [True, False])
@pytest.mark.parametrize("leader", [True, False])
def test_oauth_relation_blocks_shard(mongodb_ctx, shard_state, isolate_shard_status):
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(shard_state, relations={*shard_state.relations, oauth})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        manager = scenario.charm.operator.oauth_manager
        assert manager in scenario.charm.operator.components
        assert manager.get_statuses("unit", recompute=True) == [
            OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value
        ]
        assert manager.get_statuses("app", recompute=True) == []
        scenario.charm.status_handler._recompute_statuses_for_scope("unit", manager)
        assert manager.get_statuses("unit") == [OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value]
        state_out = scenario.run()
    assert state_out.unit_status == BlockedStatus("Cannot integrate OIDC with shard.")


@pytest.mark.parametrize("initialised", [True, False])
@pytest.mark.parametrize("leader", [True, False])
def test_removing_oauth_relation_clears_shard_status(
    mongodb_ctx, shard_state, isolate_shard_status
):
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(shard_state, relations={*shard_state.relations, oauth})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        manager = scenario.charm.operator.oauth_manager
        scenario.charm.status_handler._recompute_statuses_for_scope("unit", manager)
        state_out = scenario.run()
    assert state_out.unit_status == BlockedStatus("Cannot integrate OIDC with shard.")
    state_in = replace(
        state_out, relations=state_out.relations - {state_out.get_relation(oauth.id)}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        manager = scenario.charm.operator.oauth_manager
        scenario.charm.status_handler._recompute_statuses_for_scope("unit", manager)
        assert manager.get_statuses("unit", recompute=True) == []
        assert manager.get_statuses("unit") == []
        state_out = scenario.run()
    assert not isinstance(state_out.unit_status, BlockedStatus)


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_relation_does_not_block_supported_roles(mongodb_ctx, mongodb_container, role):
    state_in = mongo_state(
        mongodb_container,
        role=role,
        relations={Relation(endpoint="oauth", remote_app_name="hydra")},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert scenario.charm.operator.oauth_manager.get_statuses("unit", recompute=True) == []
        assert scenario.charm.operator.oauth_manager.get_statuses("unit") == []


@pytest.mark.parametrize("leader", [True, False])
def test_certificate_available_writes_replica_set_ca(mongodb_ctx, mongo_auth_state, mocker, leader):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={
            "version": "1",
            "certificates": json.dumps(["root-ca", "intermediate-ca"]),
        },
    )
    state = mongo_auth_state(leader=leader, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation), state) as scenario:
        operator = scenario.charm.operator
        write = mocker.patch.object(operator.workload, "write")

        scenario.run()

        write.assert_called_once_with(
            operator.workload.paths.oauth_ca_file, "intermediate-ca\nroot-ca"
        )


def test_certificate_available_does_not_write_config_server_ca(
    mongodb_ctx, mongo_auth_state, mocker
):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state = mongo_auth_state(role=MongoDBRoles.CONFIG_SERVER, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation), state) as scenario:
        write = mocker.patch.object(scenario.charm.operator.workload, "write")

        scenario.run()

        write.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_certificate_removed_deletes_replica_set_ca(mongodb_ctx, mongo_auth_state, mocker, leader):
    relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state = mongo_auth_state(leader=leader, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_broken(relation), state) as scenario:
        workload = scenario.charm.operator.workload
        mocker.patch.object(workload, "exists", return_value=True)
        delete = mocker.patch.object(workload, "delete")

        scenario.run()

        delete.assert_called_once_with(workload.paths.oauth_ca_file)


def test_certificate_removed_skips_missing_replica_set_ca(mongodb_ctx, mongo_auth_state, mocker):
    relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state = mongo_auth_state(relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_broken(relation), state) as scenario:
        workload = scenario.charm.operator.workload
        mocker.patch.object(workload, "exists", return_value=False)
        delete = mocker.patch.object(workload, "delete")

        scenario.run()

        delete.assert_not_called()


@pytest.mark.parametrize("role", [MongoDBRoles.CONFIG_SERVER, MongoDBRoles.SHARD])
def test_certificate_removed_does_not_delete_ca_for_other_roles(
    mongodb_ctx, mongo_auth_state, mocker, role
):
    relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state = mongo_auth_state(role=role, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_broken(relation), state) as scenario:
        delete = mocker.patch.object(scenario.charm.operator.workload, "delete")

        scenario.run()

        delete.assert_not_called()


@pytest.mark.parametrize("bundle", ["first-ca", "updated-ca"])
def test_certificate_available_publishes_config_server_ca_to_mongos(
    mongodb_ctx, mongo_auth_state, mocker, config_server_relations, bundle
):
    first, second, pending = config_server_relations
    certificate_relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps([bundle])},
    )
    state = mongo_auth_state(
        role=MongoDBRoles.CONFIG_SERVER,
        relations={first, second, pending, certificate_relation},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificate_relation), state) as scenario:
        write = mocker.patch.object(scenario.charm.operator.workload, "write")

        result = scenario.run()

    assert result.get_relation(first.id).local_app_data["oauth-ca"] == bundle
    assert result.get_relation(second.id).local_app_data["oauth-ca"] == bundle
    assert "oauth-ca" not in result.get_relation(pending.id).local_app_data
    write.assert_not_called()


def test_certificate_available_config_server_follower_does_not_publish_ca(
    mongodb_ctx, mongo_auth_state, mocker
):
    certificate_relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state = mongo_auth_state(
        role=MongoDBRoles.CONFIG_SERVER, leader=False, relations={certificate_relation}
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificate_relation), state) as scenario:
        publish = mocker.patch.object(
            scenario.charm.operator.cluster_manager, "update_oauth_ca_to_mongos"
        )

        scenario.run()

        publish.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
@pytest.mark.parametrize("bundle", ["first-ca", "updated-ca"])
def test_mongos_stores_oauth_ca_from_cluster_relation(
    mongos_ctx, mongos_auth_state, mongos_oauth_restart, mongos_cluster, leader, bundle
):
    cluster = replace(
        mongos_cluster, remote_app_data={**mongos_cluster.remote_app_data, "oauth-ca": bundle}
    )
    state = mongos_auth_state(leader=leader, relations={cluster})
    with mongos_oauth_restart(state, mongos_ctx.on.relation_changed(cluster)) as run:
        run.scenario.run()

        run.write.assert_called_once_with(run.config.workload.paths.oauth_ca_file, bundle)


def test_replica_set_oidc_provider_uses_local_ca(mongodb_ctx, mongo_auth_state, mocker):
    state = mongo_auth_state(peer_data={"oauth-issuer": "https://issuer.example"})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert providers[0]["serverCAFile"] == str(operator.workload.paths.oauth_ca_file)


def test_replica_set_oidc_provider_omits_missing_ca(mongodb_ctx, mongo_auth_state, mocker):
    state = mongo_auth_state(peer_data={"oauth-issuer": "https://issuer.example"})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=False)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert "serverCAFile" not in providers[0]


def test_replica_set_ca_alone_does_not_enable_oidc(mongodb_ctx, mongo_auth_state, mocker):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), mongo_auth_state()) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        assert operator.config_manager.oauth_parameters == {}


def test_mongos_oidc_provider_uses_local_ca(mongos_ctx, mongos_auth_state, mocker):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={"oauth-issuer": "https://issuer.example"},
    )
    state = mongos_auth_state(relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert providers[0]["serverCAFile"] == str(operator.workload.paths.oauth_ca_file)


def test_mongos_oidc_provider_omits_missing_ca(mongos_ctx, mongos_auth_state, mocker):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={"oauth-issuer": "https://issuer.example"},
    )
    state = mongos_auth_state(relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=False)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert "serverCAFile" not in providers[0]


def test_mongos_ca_alone_does_not_enable_oidc(mongos_ctx, mongos_auth_state, mocker):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    state = mongos_auth_state(relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        assert operator.config_manager.oauth_parameters == {}


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_issuer_check_uses_system_trust_without_ca(
    mongodb_ctx, mongo_auth_state, mocker, mock_issuer_tls, role
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), mongo_auth_state(role=role)) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=False)

        assert operator.oauth_manager.check_issuer_connection("https://issuer.example") is None

        mock_issuer_tls.context.assert_called_once_with()
        mock_issuer_tls.request.assert_called_once_with(
            "https://issuer.example/.well-known/openid-configuration",
            context=mock_issuer_tls.context.return_value,
            timeout=5,
        )


def test_replica_set_issuer_check_uses_workload_ca(
    mongodb_ctx, mongo_auth_state, mocker, mock_issuer_tls
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), mongo_auth_state()) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)
        read = mocker.patch.object(operator.workload, "read", return_value=["root-ca"])

        assert operator.oauth_manager.check_issuer_connection("https://issuer.example:8443") is None

        read.assert_called_once_with(operator.workload.paths.oauth_ca_file)
        mock_issuer_tls.context.assert_called_once_with(cadata="root-ca")
        mock_issuer_tls.request.assert_called_once_with(
            "https://issuer.example:8443/.well-known/openid-configuration",
            context=mock_issuer_tls.context.return_value,
            timeout=5,
        )


def test_config_server_issuer_check_uses_relation_ca(
    mongodb_ctx, mongo_auth_state, mock_issuer_tls
):
    certificate_relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state = mongo_auth_state(role=MongoDBRoles.CONFIG_SERVER, relations={certificate_relation})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        assert (
            scenario.charm.operator.oauth_manager.check_issuer_connection("https://issuer.example")
            is None
        )

        mock_issuer_tls.context.assert_called_once_with(cadata="root-ca")


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_issuer_tls_failure_without_ca_blocks(
    mongodb_ctx, mongo_auth_state, mocker, mock_issuer_tls, role
):
    state = mongo_auth_state(role=role, relations={oauth_relation("https://issuer.example")})
    mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=False)
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()
        result = scenario.run()

        assert operator.oauth_manager.get_statuses("unit", recompute=True) == [
            OAuthStatuses.ISSUER_TLS_ERROR.value
        ]
        assert isinstance(result.unit_status, BlockedStatus)
        restart.assert_not_called()


def test_issuer_network_failure_reports_waiting(mongodb_ctx, mongo_auth_state, mock_issuer_tls):
    mock_issuer_tls.request.side_effect = TimeoutError("connection timed out")
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), mongo_auth_state()) as scenario:
        assert (
            scenario.charm.operator.oauth_manager.check_issuer_connection("https://issuer.example")
            == OAuthStatuses.ISSUER_UNREACHABLE.value
        )


def test_successful_issuer_check_clears_tls_block(
    mongodb_ctx, mongo_auth_state, mocker, mock_issuer_tls
):
    state = mongo_auth_state(relations={oauth_relation("https://issuer.example")})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
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
    mongodb_ctx, mongo_auth_state, mocker, mock_issuer_tls, role, field
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
    state = mongo_auth_state(role=role, relations={oauth_relation(issuer)})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()

        assert operator.oauth_manager.get_statuses("unit") == [
            OAuthStatuses.DISCOVERY_MISMATCH.value
        ]
        restart.assert_not_called()


@pytest.mark.parametrize("body", ["not json", "[]", "{}", '{"issuer": "https://issuer.example"}'])
def test_invalid_discovery_metadata_is_blocked(
    mongodb_ctx, mongo_auth_state, mocker, mock_issuer_tls, body
):
    response = mocker.MagicMock()
    response.__enter__.return_value.read.return_value = body
    mock_issuer_tls.request.side_effect = None
    mock_issuer_tls.request.return_value = response
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), mongo_auth_state()) as scenario:
        assert (
            scenario.charm.operator.oauth_manager.check_issuer_connection("https://issuer.example")
            == OAuthStatuses.INVALID_DISCOVERY.value
        )


def test_discovery_http_error_is_blocked(mongodb_ctx, mongo_auth_state, mock_issuer_tls):
    mock_issuer_tls.request.side_effect = HTTPError(
        "https://issuer.example/.well-known/openid-configuration", 404, "Not Found", None, None
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), mongo_auth_state()) as scenario:
        assert (
            scenario.charm.operator.oauth_manager.check_issuer_connection("https://issuer.example")
            == OAuthStatuses.INVALID_DISCOVERY.value
        )


def test_discovery_uses_issuer_path(mongodb_ctx, mongo_auth_state, mock_issuer_tls):
    issuer = "https://issuer.example/tenant"
    state = mongo_auth_state(relations={oauth_relation(issuer)})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        assert scenario.charm.operator.oauth_manager.check_issuer_connection(issuer) is None

        mock_issuer_tls.request.assert_called_once_with(
            f"{issuer}/.well-known/openid-configuration",
            context=mock_issuer_tls.context.return_value,
            timeout=5,
        )


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
@pytest.mark.parametrize("previous_issuer", ["", "https://previous.example"])
def test_failed_validation_preserves_stored_and_shared_issuer(
    mongodb_ctx, mongo_auth_state, mocker, role, previous_issuer
):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="mongos",
        remote_app_data={"database": "mongos"},
        local_app_data={"oauth-issuer": previous_issuer},
    )
    state = mongo_auth_state(
        role=role,
        peer_data={"oauth-issuer": previous_issuer},
        relations={cluster, oauth_relation("https://new.example")},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(
            operator.oauth_manager,
            "check_issuer_connection",
            return_value=OAuthStatuses.DISCOVERY_MISMATCH.value,
        )
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()
        result = scenario.run()

    assert (
        get_relation(result, PeerRelationNames.PEERS.value).local_app_data.get("oauth-issuer", "")
        == previous_issuer
    )
    assert result.get_relation(cluster.id).local_app_data.get("oauth-issuer", "") == previous_issuer
    assert isinstance(result.unit_status, BlockedStatus)
    restart.assert_not_called()


@pytest.fixture
def oauth_workload_files(mocker):
    """Model local files so configuration reflects CA writes and removals."""

    def attach(workload):
        files = {}
        mocker.patch.object(workload, "exists", side_effect=lambda path: path in files)
        mocker.patch.object(
            workload, "read", side_effect=lambda path: files.get(path, "").splitlines()
        )
        mocker.patch.object(
            workload, "write", side_effect=lambda path, content: files.update({path: content})
        )
        mocker.patch.object(workload, "delete", side_effect=lambda path: files.pop(path, None))
        return files

    return attach


@pytest.mark.parametrize("leader", [True, False])
def test_replica_set_ca_addition_requests_restart(
    mongodb_ctx, mongo_auth_state, mocker, oauth_workload_files, leader
):
    state = mongo_auth_state(leader=leader, peer_data={"oauth-issuer": "https://issuer.example"})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        files = oauth_workload_files(operator.workload)
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.store_certificates({"root-ca"})

        request.assert_called_once_with(force=False)
        assert files[operator.workload.paths.oauth_ca_file] == "root-ca"


@pytest.mark.parametrize("leader", [True, False])
def test_replica_set_ca_rotation_does_not_request_restart(
    mongodb_ctx, mongo_auth_state, mocker, oauth_workload_files, leader
):
    state = mongo_auth_state(leader=leader, peer_data={"oauth-issuer": "https://issuer.example"})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        files = oauth_workload_files(operator.workload)
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.store_certificates({"updated-ca"})

        request.assert_not_called()
        assert files[operator.workload.paths.oauth_ca_file] == "updated-ca"


@pytest.mark.parametrize("leader", [True, False])
def test_replica_set_ca_removal_requests_restart(
    mongodb_ctx, mongo_auth_state, mocker, oauth_workload_files, leader
):
    state = mongo_auth_state(leader=leader, peer_data={"oauth-issuer": "https://issuer.example"})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        files = oauth_workload_files(operator.workload)
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.remove_certificates()

        request.assert_called_once_with(force=False)
        assert operator.workload.paths.oauth_ca_file not in files


@pytest.fixture
def mongos_ca_restart(mongos_ctx, mongos_auth_state, mocker, oauth_workload_files, tmp_path):
    @contextmanager
    def run(bundle, leader=True, external_ca=""):
        cluster = Relation(
            endpoint="cluster",
            remote_app_name="config-server",
            remote_app_data={
                "oauth-issuer": "https://issuer.example",
                "oauth-ca": bundle,
                "ext-ca-secret": external_ca,
                "key-file": "keyfile",
                "config-server-db": "rs/10.0.0.1:27017",
            },
        )
        state = mongos_auth_state(leader=leader, relations={cluster})
        with mongos_ctx(mongos_ctx.on.relation_changed(cluster), state) as scenario:
            operator = scenario.charm.operator
            files = oauth_workload_files(operator.workload)
            files[operator.workload.paths.keyfile] = "keyfile"
            mocker.patch.object(
                type(operator.workload.paths),
                "config_server_ext_ca_file",
                new_callable=PropertyMock,
                return_value=tmp_path / "cluster-ca.crt",
            )
            mocker.patch.object(operator.workload, "active", return_value=True)
            mocker.patch.object(operator.cluster_manager, "assert_pass_hook_checks")
            request = mocker.patch.object(operator.rollingops_manager, "request_async_lock")
            yield SimpleNamespace(
                operator=operator, files=files, request=request, scenario=scenario
            )

    return run


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_ca_addition_requests_restart(mongos_ca_restart, leader):
    with mongos_ca_restart("root-ca", leader=leader) as run:
        config = run.operator.config_manager
        run.files[config.file] = safe_dump(config.build_config())

        run.scenario.run()

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        assert run.files[run.operator.workload.paths.oauth_ca_file] == "root-ca"


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_ca_rotation_does_not_restart_service(mongos_ca_restart, mocker, leader):
    with mongos_ca_restart("updated-ca", leader=leader) as run:
        operator = run.operator
        config = operator.config_manager
        run.files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        run.files[config.file] = safe_dump(config.build_config())
        mocker.patch.object(operator.cluster_manager, "_set_ldap_user_to_dn")
        mocker.patch.object(operator.cluster_manager, "_set_cluster_id")
        mocker.patch.object(operator, "update_keyfile", return_value=False)
        mocker.patch.object(operator, "update_config_server_db", return_value=False)
        restart = mocker.patch.object(operator.workload, "restart")

        run.scenario.run()
        operator.cluster_manager.update_mongos_and_restart(force=False)

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        restart.assert_not_called()
        assert run.files[operator.workload.paths.oauth_ca_file] == "updated-ca"


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_ca_removal_requests_restart(mongos_ca_restart, leader):
    with mongos_ca_restart("", leader=leader) as run:
        config = run.operator.config_manager
        path = run.operator.workload.paths.oauth_ca_file
        run.files[path] = "previous-ca"
        run.files[config.file] = safe_dump(config.build_config())

        run.scenario.run()

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        assert path not in run.files


def test_mongos_keyfile_change_still_requests_restart(mongos_ca_restart):
    with mongos_ca_restart("updated-ca") as run:
        config = run.operator.config_manager
        run.files[run.operator.workload.paths.oauth_ca_file] = "previous-ca"
        run.files[run.operator.workload.paths.keyfile] = "old-keyfile"
        run.files[config.file] = safe_dump(config.build_config())

        run.scenario.run()

        run.request.assert_called_once()


def test_mongos_forced_restart_is_preserved(mongos_ca_restart):
    with mongos_ca_restart("updated-ca") as run:
        config = run.operator.config_manager
        run.files[run.operator.workload.paths.oauth_ca_file] = "previous-ca"
        run.files[config.file] = safe_dump(config.build_config())

        run.operator.cluster_manager.async_update_mongos_and_restart(force=True)

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": True}
        )


def test_mongos_cluster_tls_ca_change_still_requests_restart(mongos_ca_restart):
    with mongos_ca_restart("updated-ca", external_ca="updated-cluster-ca") as run:
        config = run.operator.config_manager
        run.files[run.operator.workload.paths.oauth_ca_file] = "previous-ca"
        run.files[config.file] = safe_dump(config.build_config())

        run.scenario.run()

        run.request.assert_called_once()
        assert (
            run.operator.workload.paths.config_server_ext_ca_file.read_text()
            == "updated-cluster-ca"
        )


def test_config_server_ca_removal_is_shared_with_mongos(
    mongodb_ctx, mongo_auth_state, mocker, config_server_relations
):
    first, second, pending = config_server_relations
    first = replace(first, local_app_data={"oauth-ca": "previous-ca"})
    second = replace(second, local_app_data={"oauth-ca": "previous-ca"})
    certificate_relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state = mongo_auth_state(
        role=MongoDBRoles.CONFIG_SERVER, relations={first, second, pending, certificate_relation}
    )
    with mongodb_ctx(mongodb_ctx.on.relation_broken(certificate_relation), state) as scenario:
        restart = mocker.patch.object(scenario.charm.operator, "async_restart_charm_services")

        result = scenario.run()

    assert "oauth-ca" not in result.get_relation(first.id).local_app_data
    assert "oauth-ca" not in result.get_relation(second.id).local_app_data
    assert "oauth-ca" not in result.get_relation(pending.id).local_app_data
    restart.assert_not_called()


def test_replica_set_certificate_arrival_retries_pending_issuer(
    mongodb_ctx, mongo_auth_state, mocker, oauth_workload_files, mock_issuer_tls
):
    issuer = "https://issuer.example"
    certificates = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state = mongo_auth_state(relations={oauth_relation(issuer), certificates})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificates), state) as scenario:
        operator = scenario.charm.operator
        files = oauth_workload_files(operator.workload)
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        successful_response = mock_issuer_tls.request.side_effect
        mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
        operator.oauth_manager.configure()
        assert operator.state.app_peer_data.oauth_issuer is None
        mock_issuer_tls.request.side_effect = successful_response

        result = scenario.run()

    assert (
        get_relation(result, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"] == issuer
    )
    assert files[operator.workload.paths.oauth_ca_file] == "root-ca"
    assert OAuthStatuses.ISSUER_TLS_ERROR.value not in operator.oauth_manager.get_statuses("unit")
    request.assert_called_once_with(force=False)


def test_config_server_certificate_arrival_retries_and_shares_pending_issuer(
    mongodb_ctx, mongo_auth_state, mocker, mock_issuer_tls, config_server_relations
):
    issuer = "https://issuer.example"
    first, second, pending = config_server_relations
    certificates = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state = mongo_auth_state(
        role=MongoDBRoles.CONFIG_SERVER,
        relations={oauth_relation(issuer), certificates, first, second, pending},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificates), state) as scenario:
        operator = scenario.charm.operator
        request = mocker.patch.object(operator, "async_restart_charm_services")
        successful_response = mock_issuer_tls.request.side_effect
        mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
        operator.oauth_manager.configure()
        assert operator.state.app_peer_data.oauth_issuer is None
        mock_issuer_tls.request.side_effect = successful_response

        result = scenario.run()

    assert (
        get_relation(result, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"] == issuer
    )
    assert result.get_relation(first.id).local_app_data["oauth-issuer"] == issuer
    assert result.get_relation(second.id).local_app_data["oauth-issuer"] == issuer
    assert "oauth-issuer" not in result.get_relation(pending.id).local_app_data
    assert OAuthStatuses.ISSUER_TLS_ERROR.value not in operator.oauth_manager.get_statuses("unit")
    request.assert_not_called()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_certificate_arrival_keeps_invalid_issuer_unstored(
    mongodb_ctx, mongo_auth_state, mocker, oauth_workload_files, mock_issuer_tls, role
):
    certificates = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state = mongo_auth_state(
        role=role, relations={oauth_relation("https://issuer.example"), certificates}
    )
    mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificates), state) as scenario:
        operator = scenario.charm.operator
        oauth_workload_files(operator.workload)
        request = mocker.patch.object(operator, "async_restart_charm_services")

        result = scenario.run()

    assert "oauth-issuer" not in get_relation(result, PeerRelationNames.PEERS.value).local_app_data
    assert operator.oauth_manager.get_statuses("unit") == [OAuthStatuses.ISSUER_TLS_ERROR.value]
    request.assert_not_called()


def test_mongos_requests_oauth_ca_as_secret(mongos_ctx, mongos_auth_state):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    state = mongos_auth_state(relations={cluster})

    result = mongos_ctx.run(mongos_ctx.on.relation_created(cluster), state)

    requested = json.loads(result.get_relation(cluster.id).local_app_data["requested-secrets"])
    assert "oauth-ca" in requested


@pytest.mark.parametrize("bundle", ["first-ca", "updated-ca"])
def test_config_server_shares_oauth_ca_as_secret(mongodb_ctx, mongo_auth_state, bundle):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="mongos",
        remote_app_data={"database": "mongos", "requested-secrets": json.dumps(["oauth-ca"])},
    )
    state = mongo_auth_state(role=MongoDBRoles.CONFIG_SERVER, relations={cluster})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        scenario.charm.operator.cluster_manager.update_oauth_ca_to_mongos(bundle)

        result = scenario.run()

    data = result.get_relation(cluster.id).local_app_data
    assert "oauth-ca" not in data
    secret = next(
        secret for secret in result.secrets if secret.label == f"cluster.{cluster.id}.extra.secret"
    )
    assert data["secret-extra"] == secret.id
    assert secret.latest_content["oauth-ca"] == bundle
    assert "mongos" in secret.remote_grants[cluster.id]


@pytest.fixture
def config_server_oauth_secret(mongo_auth_state):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="mongos",
        remote_app_data={
            "database": "mongos",
            "requested-secrets": json.dumps(["key-file", "oauth-ca"]),
        },
    )
    secret = Secret(
        tracked_content={"key-file": "keyfile", "oauth-ca": "previous-ca"},
        owner="app",
        label=f"cluster.{cluster.id}.extra.secret",
        remote_grants={cluster.id: {"mongos"}},
    )
    cluster = replace(cluster, local_app_data={"secret-extra": secret.id})
    state = replace(
        mongo_auth_state(role=MongoDBRoles.CONFIG_SERVER, relations={cluster}), secrets={secret}
    )
    return SimpleNamespace(cluster=cluster, secret=secret, state=state)


def test_config_server_updates_oauth_ca_secret(mongodb_ctx, config_server_oauth_secret):
    state = config_server_oauth_secret.state
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        scenario.charm.operator.cluster_manager.update_oauth_ca_to_mongos("updated-ca")

        result = scenario.run()

    secret = next(
        secret for secret in result.secrets if secret.id == config_server_oauth_secret.secret.id
    )
    assert secret.latest_content == {"key-file": "keyfile", "oauth-ca": "updated-ca"}
    assert (
        "oauth-ca" not in result.get_relation(config_server_oauth_secret.cluster.id).local_app_data
    )


def test_config_server_removes_oauth_ca_from_secret(mongodb_ctx, config_server_oauth_secret):
    state = config_server_oauth_secret.state
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        scenario.charm.operator.cluster_manager.update_oauth_ca_to_mongos("")

        result = scenario.run()

    secret = next(
        secret for secret in result.secrets if secret.id == config_server_oauth_secret.secret.id
    )
    assert secret.latest_content == {"key-file": "keyfile"}


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_stores_oauth_ca_from_cluster_secret(
    mongos_ctx, mongos_auth_state, mongos_oauth_restart, leader
):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    secret = Secret(
        tracked_content={
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.1:27017",
            "oauth-ca": "root-ca",
        },
        label=f"cluster.{cluster.id}.extra.secret",
    )
    cluster = replace(cluster, remote_app_data={"secret-extra": secret.id})
    state = replace(mongos_auth_state(leader=leader, relations={cluster}), secrets={secret})
    with mongos_oauth_restart(state, mongos_ctx.on.relation_changed(cluster)) as run:
        run.scenario.run()

        run.write.assert_called_once_with(run.config.workload.paths.oauth_ca_file, "root-ca")


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_reconciles_updated_oauth_ca_secret(
    mongos_ctx, mongos_auth_state, mongos_oauth_restart, leader
):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    secret = Secret(
        tracked_content={
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.1:27017",
            "oauth-ca": "previous-ca",
        },
        latest_content={
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.1:27017",
            "oauth-ca": "updated-ca",
        },
        label=f"cluster.{cluster.id}.extra.secret",
    )
    cluster = replace(cluster, remote_app_data={"secret-extra": secret.id})
    state = replace(mongos_auth_state(leader=leader, relations={cluster}), secrets={secret})
    with mongos_oauth_restart(state, mongos_ctx.on.secret_changed(secret)) as run:
        run.scenario.run()

        run.write.assert_called_once_with(run.config.workload.paths.oauth_ca_file, "updated-ca")


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_removes_oauth_ca_when_cluster_secret_field_is_removed(
    mongos_ctx, mongos_auth_state, mongos_oauth_restart, mocker, leader
):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    secret = Secret(
        tracked_content={
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.1:27017",
            "oauth-ca": "previous-ca",
        },
        latest_content={"key-file": "keyfile", "config-server-db": "rs/10.0.0.1:27017"},
        label=f"cluster.{cluster.id}.extra.secret",
    )
    cluster = replace(cluster, remote_app_data={"secret-extra": secret.id})
    state = replace(mongos_auth_state(leader=leader, relations={cluster}), secrets={secret})
    with mongos_oauth_restart(state, mongos_ctx.on.secret_changed(secret)) as run:
        mocker.patch.object(run.config.workload, "exists", return_value=True)
        delete = mocker.patch.object(run.config.workload, "delete")

        run.scenario.run()

        delete.assert_called_once_with(run.config.workload.paths.oauth_ca_file)
        run.write.assert_not_called()
