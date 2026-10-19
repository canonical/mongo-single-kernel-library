# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from types import SimpleNamespace
from unittest.mock import PropertyMock

import pytest
from yaml import safe_dump

from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
)


@pytest.mark.parametrize(
    ("role", "initialised", "degraded", "refreshing", "error", "message"),
    [
        (
            MongoDBRoles.SHARD,
            True,
            False,
            False,
            NonDeferrableFailedHookChecksError,
            "Cannot integrate OAuth with shard",
        ),
        (
            MongoDBRoles.SHARD,
            False,
            False,
            False,
            NonDeferrableFailedHookChecksError,
            "Cannot integrate OAuth with shard",
        ),
        (
            MongoDBRoles.REPLICATION,
            False,
            False,
            False,
            DeferrableFailedHookChecksError,
            "DB is not initialised",
        ),
        (
            MongoDBRoles.REPLICATION,
            True,
            True,
            False,
            DeferrableFailedHookChecksError,
            "Encryption at rest",
        ),
        (
            MongoDBRoles.REPLICATION,
            True,
            False,
            True,
            DeferrableFailedHookChecksError,
            "during a refresh",
        ),
        (MongoDBRoles.REPLICATION, True, False, False, None, None),
        (MongoDBRoles.CONFIG_SERVER, True, False, False, None, None),
    ],
)
def test_oauth_hook_checks(
    harness, mocker, role, initialised, degraded, refreshing, error, message
):
    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = role
    operator.state.app_peer_data.db_initialised = initialised
    mocker.patch.object(operator.vault_manager, "get_degraded_state", return_value=degraded)
    mocker.patch.object(
        type(operator), "refresh_in_progress", new_callable=PropertyMock, return_value=refreshing
    )

    if error:
        with pytest.raises(error, match=message):
            operator.oauth_manager.assert_pass_hook_checks()
    else:
        operator.oauth_manager.assert_pass_hook_checks()


def test_configure_shares_issuer_and_requests_restart(harness, mocker):
    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    operator.state.app_peer_data.db_initialised = True
    manager = operator.oauth_manager
    mocker.patch.object(manager, "assert_pass_hook_checks")
    mocker.patch.object(
        manager.oauth_requirer,
        "get_provider_info",
        return_value=SimpleNamespace(issuer_url="https://10.0.0.3"),
    )
    mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
    restart = mocker.patch.object(operator, "async_restart_charm_services")

    manager.configure()

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

    restart.reset_mock()
    mocker.patch.object(
        operator.config_manager.workload,
        "read",
        return_value=[safe_dump(operator.config_manager.build_config())],
    )
    manager.configure()
    restart.assert_not_called()


def test_remove_clears_issuer_and_requests_restart(harness, mocker):
    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    operator.state.app_peer_data.oauth_issuer = "https://10.0.0.3"
    mocker.patch.object(operator.oauth_manager, "assert_pass_hook_checks")
    current = safe_dump(operator.config_manager.build_config())
    mocker.patch.object(operator.config_manager.workload, "read", return_value=[current])
    restart = mocker.patch.object(operator, "async_restart_charm_services")

    operator.oauth_manager.remove()

    assert operator.state.app_peer_data.oauth_issuer is None
    assert "oidcIdentityProviders" not in operator.config_manager.build_config()["setParameter"]
    restart.assert_called_once_with(force=False)


def test_oauth_provider_update_changes_issuer(harness, mocker):
    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    operator.state.app_peer_data.oauth_issuer = "https://old-issuer"
    manager = operator.oauth_manager
    mocker.patch.object(manager, "assert_pass_hook_checks")
    mocker.patch.object(
        manager.oauth_requirer,
        "get_provider_info",
        return_value=SimpleNamespace(issuer_url="https://new-issuer"),
    )
    mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
    restart = mocker.patch.object(operator, "async_restart_charm_services")

    manager.oauth_requirer.on.oauth_info_changed.emit("client-id", "secret-id")

    assert operator.state.app_peer_data.oauth_issuer == "https://new-issuer"
    restart.assert_called_once_with(force=False)


def test_oauth_hook_defers_until_database_initialised(harness, mocker):
    operator = harness.charm.operator
    event = mocker.Mock()
    restart = mocker.patch.object(operator, "async_restart_charm_services")

    operator.oauth_events._on_oauth_info_changed(event)

    event.defer.assert_called_once()
    restart.assert_not_called()


def test_oauth_follower_restarts_from_shared_issuer(harness, mocker):
    operator = harness.charm.operator
    harness.set_leader(True)
    operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    operator.state.app_peer_data.oauth_issuer = "https://10.0.0.3"
    harness.set_leader(False)
    mocker.patch.object(operator.oauth_manager, "assert_pass_hook_checks")
    mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
    restart = mocker.patch.object(operator, "async_restart_charm_services")

    operator.oauth_events._on_peer_relation_changed(mocker.Mock())

    restart.assert_called_once_with(force=False)


def test_config_server_publishes_updates_and_removal(harness, mocker):
    from single_kernel_mongo.config.relations import RelationNames

    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    operator.state.app_peer_data.db_initialised = True
    mocker.patch.object(operator.oauth_manager, "assert_pass_hook_checks")
    provider = mocker.patch.object(
        operator.oauth_manager.oauth_requirer,
        "get_provider_info",
        return_value=SimpleNamespace(issuer_url="https://first-issuer"),
    )
    restart = mocker.patch.object(operator, "async_restart_charm_services")
    with harness.hooks_disabled():
        relations = [
            harness.add_relation(RelationNames.CLUSTER.value, name)
            for name in ("mongos-one", "mongos-two")
        ]
        for relation_id, name in zip(relations, ("mongos-one", "mongos-two")):
            harness.update_relation_data(relation_id, name, {"database": "mongos"})
        pending = harness.add_relation(RelationNames.CLUSTER.value, "pending")

    for issuer in ("https://first-issuer", "https://second-issuer"):
        provider.return_value.issuer_url = issuer
        operator.oauth_manager.configure()
        for relation_id in relations:
            assert (
                harness.get_relation_data(relation_id, harness.charm.app.name)["oauth-issuer"]
                == issuer
            )
        assert "oauth-issuer" not in harness.get_relation_data(pending, harness.charm.app.name)
        assert "oidcIdentityProviders" not in operator.config_manager.build_config()["setParameter"]

    operator.oauth_manager.remove()
    for relation_id in relations:
        assert "oauth-issuer" not in harness.get_relation_data(relation_id, harness.charm.app.name)
    restart.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_renders_issuer_from_cluster_relation(mongos_harness, leader):
    from single_kernel_mongo.config.relations import RelationNames

    mongos_harness.set_leader(leader)
    operator = mongos_harness.charm.operator
    with mongos_harness.hooks_disabled():
        relation_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")
        mongos_harness.update_relation_data(
            relation_id, "config-server", {"oauth-issuer": "https://issuer.example"}
        )
    parameters = operator.config_manager.oauth_parameters
    assert parameters["setParameter"]["authenticationMechanisms"] == "SCRAM-SHA-256,MONGODB-OIDC"
    assert (
        json.loads(parameters["setParameter"]["oidcIdentityProviders"])[0]["issuer"]
        == "https://issuer.example"
    )

    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(relation_id, "config-server", {"oauth-issuer": ""})
    assert operator.config_manager.oauth_parameters == {}


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_issuer_change_requests_async_restart_and_updates_file(
    mongos_harness, mocker, leader
):
    from yaml import safe_load

    from single_kernel_mongo.config.literals import RollingOpsCallbackId
    from single_kernel_mongo.config.relations import RelationNames

    mongos_harness.set_leader(True)
    operator = mongos_harness.charm.operator
    operator.state.app_peer_data.db_initialised = True
    mongos_harness.set_leader(leader)
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
    mocker.patch.object(config.workload, "read", return_value=["{}"])
    mocker.patch.object(config.workload, "active", return_value=True)
    write = mocker.patch.object(config.workload, "write")
    restart = mocker.patch.object(config.workload, "restart")
    with mongos_harness.hooks_disabled():
        relation_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")
        mongos_harness.add_relation_unit(relation_id, "config-server/0")
        mongos_harness.update_relation_data(
            relation_id,
            "config-server",
            {"key-file": "keyfile", "config-server-db": "rs/10.0.0.1:27017"},
        )

    for issuer in ("https://first-issuer", "https://updated-issuer", ""):
        request.reset_mock()
        write.reset_mock()
        restart.reset_mock()
        mongos_harness.update_relation_data(relation_id, "config-server", {"oauth-issuer": issuer})

        request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        write.assert_not_called()
        restart.assert_not_called()

        # The rolling callback delegates to this method to write the config and restart.
        cluster.update_mongos_and_restart(force=False)

        write.assert_called_once()
        path, content = write.call_args.args
        assert path == config.file
        parameters = safe_load(content)["setParameter"]
        if issuer:
            assert json.loads(parameters["oidcIdentityProviders"])[0]["issuer"] == issuer
            assert parameters["authenticationMechanisms"] == "SCRAM-SHA-256,MONGODB-OIDC"
        else:
            assert "oidcIdentityProviders" not in parameters
        restart.assert_called_once()


@pytest.mark.parametrize("initialised", [True, False])
@pytest.mark.parametrize("leader", [True, False])
def test_oauth_relation_blocks_shard_and_clears_on_removal(harness, mocker, initialised, leader):
    from data_platform_helpers.advanced_statuses.models import StatusObject
    from data_platform_helpers.advanced_statuses.utils import as_status
    from ops.model import BlockedStatus

    from single_kernel_mongo.config.relations import ExternalRequirerRelations
    from single_kernel_mongo.config.statuses import OAuthStatuses

    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = MongoDBRoles.SHARD
    operator.state.app_peer_data.db_initialised = initialised
    harness.set_leader(leader)
    manager = operator.oauth_manager
    assert manager in operator.components
    assert manager.get_statuses("unit", recompute=True) == []
    # Isolate OAuth status selection from unrelated workload health checks.
    for component in harness.charm.status_handler.components:
        if component is not manager:
            mocker.patch.object(
                component, "get_statuses", return_value=[StatusObject(status="active", message="")]
            )

    relation_id = harness.add_relation(ExternalRequirerRelations.OAUTH.value, "hydra")

    expected = OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value
    assert manager.get_statuses("unit", recompute=True) == [expected]
    assert manager.get_statuses("unit") == [expected]
    assert manager.get_statuses("app", recompute=True) == []
    assert as_status(expected) == BlockedStatus("Cannot integrate OIDC with shard.")
    harness.evaluate_status()
    assert harness.model.unit.status == BlockedStatus("Cannot integrate OIDC with shard.")

    harness.remove_relation(relation_id)

    assert manager.get_statuses("unit", recompute=True) == []
    assert manager.get_statuses("unit") == []
    harness.evaluate_status()
    assert not isinstance(harness.model.unit.status, BlockedStatus)


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_oauth_relation_does_not_block_supported_roles(harness, role):
    from single_kernel_mongo.config.relations import ExternalRequirerRelations

    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = role
    harness.add_relation(ExternalRequirerRelations.OAUTH.value, "hydra")

    assert operator.oauth_manager.get_statuses("unit", recompute=True) == []
    assert operator.oauth_manager.get_statuses("unit") == []
