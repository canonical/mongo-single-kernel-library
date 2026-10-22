# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import PropertyMock

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
