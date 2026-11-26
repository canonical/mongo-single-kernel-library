# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from dataclasses import replace

import pytest
import requests
from charmlibs.interfaces.certificate_transfer import CertificateTransferRequires
from ops.testing import Relation, Secret
from yaml import safe_dump

from single_kernel_mongo.config.literals import RollingOpsCallbackId
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles
from tests.unit.auth_scenario_helpers import (
    get_relation,
    mongo_state,
    mongos_state,
    oauth_certificate_transfer_relation,
)

pytest_plugins = ("tests.unit.auth_scenario_helpers",)
pytestmark = pytest.mark.usefixtures("isolate_oauth_events", "short_mock_fs_interactions")


def test_on_certificates_available_replica_set_updates_databag_and_restarts(
    mock_issuer_tls, mongodb_ctx, mongodb_container, certificates, mocker, registered_oauth
):
    oauth, secret = registered_oauth
    oauth_certs_relation = oauth_certificate_transfer_relation(certificates)
    state_in = replace(
        mongo_state(
            mongodb_container,
            role=MongoDBRoles.REPLICATION,
            leader=True,
            relations={oauth, oauth_certs_relation},
        ),
        secrets={secret},
    )
    event = mongodb_ctx.on.custom(
        CertificateTransferRequires.on.certificate_set_updated,
        certificates={certificates.root, certificates.intermediate},
        relation_id=oauth_certs_relation.id,
    )
    with mongodb_ctx(event, state_in) as scenario:
        # Scenario resolves custom events from objects exposed directly on the charm.
        scenario.charm.certificate_transfer = (
            scenario.charm.operator.oauth_manager.certificate_transfer
        )
        operator = scenario.charm.operator
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        request = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == "https://new-issuer"
    )
    bundle = "\n".join(sorted([certificates.root, certificates.intermediate]))
    ca_secret = next(
        secret
        for secret in state_out.secrets
        if secret.label == f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app"
    )
    assert ca_secret.latest_content["oauth-ca"] == bundle
    request.assert_called_once_with(force=False)


def test_on_certificates_available_config_server_propagates_ca_and_does_not_restart(
    mock_issuer_tls,
    mongodb_ctx,
    mongodb_container,
    certificates,
    mocker,
    registered_oauth,
    config_server_relations,
):
    oauth, secret = registered_oauth
    oauth_certs_relation = oauth_certificate_transfer_relation(certificates)
    first, second, pending = config_server_relations
    state_in = replace(
        mongo_state(
            mongodb_container,
            role=MongoDBRoles.CONFIG_SERVER,
            leader=True,
            relations={oauth, oauth_certs_relation, first, second, pending},
        ),
        secrets={secret},
    )
    event = mongodb_ctx.on.custom(
        CertificateTransferRequires.on.certificate_set_updated,
        certificates={certificates.root, certificates.intermediate},
        relation_id=oauth_certs_relation.id,
    )
    with mongodb_ctx(event, state_in) as scenario:
        # Scenario resolves custom events from objects exposed directly on the charm.
        scenario.charm.certificate_transfer = (
            scenario.charm.operator.oauth_manager.certificate_transfer
        )
        operator = scenario.charm.operator
        request = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == "https://new-issuer"
    )
    bundle = "\n".join(sorted([certificates.root, certificates.intermediate]))
    ca_secret = next(
        secret
        for secret in state_out.secrets
        if secret.label == f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app"
    )
    assert ca_secret.latest_content["oauth-ca"] == bundle
    assert state_out.get_relation(first.id).local_app_data["oauth-issuer"] == "https://new-issuer"
    for router in (first, second):
        data = state_out.get_relation(router.id).local_app_data
        assert "oauth-ca" not in data
        router_secret = state_out.get_secret(id=data["secret-extra"])
        assert router_secret.latest_content["oauth-ca"] == bundle
    assert state_out.get_relation(second.id).local_app_data["oauth-issuer"] == "https://new-issuer"
    assert "oauth-issuer" not in state_out.get_relation(pending.id).local_app_data
    assert "secret-extra" not in state_out.get_relation(pending.id).local_app_data
    request.assert_not_called()


def test_on_secret_changed_follower_replica_set_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    secret = Secret(
        tracked_content={"oauth-ca": "root-ca"},
        label=f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app",
    )
    state_in = replace(
        mongo_state(
            mongodb_container,
            leader=False,
            peer_data={"oauth-issuer": "https://issuer.example"},
        ),
        secrets={secret},
    )
    with mongodb_ctx(mongodb_ctx.on.secret_changed(secret), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        request = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

    request.assert_called_once_with(force=False)


def test_on_certificate_removed_replica_set_remove_ca_from_databag_and_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, certificates, mocker, registered_oauth
):
    oauth, oauth_secret = registered_oauth
    ca_secret = Secret(
        tracked_content={"oauth-ca": certificates.root, "keyfile": "keyfile"},
        owner="app",
        label=f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app",
    )
    relation = oauth_certificate_transfer_relation(certificates)
    state_in = replace(
        mongo_state(
            mongodb_container,
            peer_data={"oauth-issuer": "https://new-issuer"},
            relations={oauth, relation},
        ),
        secrets={oauth_secret, ca_secret},
    )
    event = mongodb_ctx.on.custom(
        CertificateTransferRequires.on.certificates_removed, relation_id=relation.id
    )
    with mongodb_ctx(event, state_in) as scenario:
        # Scenario resolves custom events from objects exposed directly on the charm.
        scenario.charm.certificate_transfer = (
            scenario.charm.operator.oauth_manager.certificate_transfer
        )
        operator = scenario.charm.operator
        assert operator.state.app_peer_data.oauth_ca == certificates.root
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    peer = get_relation(state_out, PeerRelationNames.PEERS.value)
    assert "oauth-ca" not in peer.local_app_data
    assert peer.local_app_data["oauth-issuer"] == "https://new-issuer"
    assert all("oauth-ca" not in secret.latest_content for secret in state_out.secrets)
    restart.assert_called_once_with(force=False)
    assert not state_out.deferred


def test_on_certificate_removed_ca_replica_set_restarts_with_unreachable_issuer(
    mock_issuer_tls,
    mongodb_ctx,
    mongodb_container,
    certificates,
    mocker,
    registered_oauth,
):
    oauth, oauth_secret = registered_oauth
    ca_secret = Secret(
        tracked_content={"oauth-ca": certificates.root, "keyfile": "keyfile"},
        owner="app",
        label=f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app",
    )
    relation = oauth_certificate_transfer_relation(certificates)
    state_in = replace(
        mongo_state(
            mongodb_container,
            peer_data={"oauth-issuer": "https://new-issuer"},
            relations={oauth, relation},
        ),
        secrets={oauth_secret, ca_secret},
    )
    event = mongodb_ctx.on.custom(
        CertificateTransferRequires.on.certificates_removed, relation_id=relation.id
    )
    with mongodb_ctx(event, state_in) as scenario:
        # Scenario resolves custom events from objects exposed directly on the charm.
        scenario.charm.certificate_transfer = (
            scenario.charm.operator.oauth_manager.certificate_transfer
        )
        operator = scenario.charm.operator
        assert operator.state.app_peer_data.oauth_ca == certificates.root
        workload = operator.config_manager.workload
        delete = mocker.patch.object(workload, "delete")
        mocker.patch.object(workload, "exists", side_effect=lambda path: not delete.called)
        current = safe_dump(operator.config_manager.build_config())
        assert "serverCAFile" in current
        mocker.patch.object(workload, "read", return_value=current.splitlines())
        mock_issuer_tls.request.side_effect = requests.ConnectionError("Issuer is unreachable")
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    peer = get_relation(state_out, PeerRelationNames.PEERS.value)
    assert "oauth-ca" not in peer.local_app_data
    assert peer.local_app_data["oauth-issuer"] == "https://new-issuer"
    assert all("oauth-ca" not in secret.latest_content for secret in state_out.secrets)
    delete.assert_called_once_with(workload.paths.oauth_ca_file)
    restart.assert_called_once_with(force=False)
    assert not state_out.deferred


def test_on_certificate_removed_config_server_ca_from_mongos_not_restart(
    mongodb_ctx, mongodb_container, certificates, mocker, registered_oauth, config_server_relations
):
    oauth, oauth_secret = registered_oauth
    ca_secret = Secret(
        tracked_content={"oauth-ca": certificates.root, "keyfile": "keyfile"},
        owner="app",
        label=f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app",
    )
    relation = oauth_certificate_transfer_relation(certificates)
    first, second, pending = config_server_relations
    router_secrets = {
        router.id: Secret(
            tracked_content={"oauth-ca": certificates.root, "keyfile": "keyfile"},
            owner="app",
            label=f"cluster.{router.id}.extra.secret",
        )
        for router in (first, second)
    }
    first, second = (
        replace(router, local_app_data={"secret-extra": router_secrets[router.id].id})
        for router in (first, second)
    )
    state_in = replace(
        mongo_state(
            mongodb_container,
            role=MongoDBRoles.CONFIG_SERVER,
            peer_data={"oauth-issuer": "https://new-issuer"},
            relations={oauth, relation, first, second, pending},
        ),
        secrets={oauth_secret, ca_secret, *router_secrets.values()},
    )
    event = mongodb_ctx.on.custom(
        CertificateTransferRequires.on.certificates_removed, relation_id=relation.id
    )
    with mongodb_ctx(event, state_in) as scenario:
        # Scenario resolves custom events from objects exposed directly on the charm.
        scenario.charm.certificate_transfer = (
            scenario.charm.operator.oauth_manager.certificate_transfer
        )
        operator = scenario.charm.operator
        assert operator.state.app_peer_data.oauth_ca == certificates.root
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert all("oauth-ca" not in secret.latest_content for secret in state_out.secrets)
    for router in (first, second, pending):
        assert "oauth-ca" not in state_out.get_relation(router.id).local_app_data
    for router in (first, second):
        data = state_out.get_relation(router.id).local_app_data
        secret = state_out.get_secret(id=data["secret-extra"])
        assert secret.id == router_secrets[router.id].id
        assert secret.latest_content == {"keyfile": "keyfile"}
    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == "https://new-issuer"
    )
    restart.assert_not_called()
    assert not state_out.deferred


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_on_certificate_available_without_issuer_does_not_store_in_databag_and_defer(
    mongodb_ctx, mongodb_container, certificates, mocker, role
):
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    relation = oauth_certificate_transfer_relation(certificates)
    state_in = mongo_state(mongodb_container, role=role, relations={oauth, relation})
    event = mongodb_ctx.on.custom(
        CertificateTransferRequires.on.certificate_set_updated,
        certificates={certificates.root, certificates.intermediate},
        relation_id=relation.id,
    )
    with mongodb_ctx(event, state_in) as scenario:
        # Scenario resolves custom events from objects exposed directly on the charm.
        scenario.charm.certificate_transfer = (
            scenario.charm.operator.oauth_manager.certificate_transfer
        )
        restart = mocker.patch.object(scenario.charm.operator, "async_restart_charm_services")

        state_out = scenario.run()

    peer = get_relation(state_out, PeerRelationNames.PEERS.value)
    assert "oauth-ca" not in peer.local_app_data
    assert "oauth-issuer" not in peer.local_app_data
    assert all("oauth-ca" not in secret.latest_content for secret in state_out.secrets)
    restart.assert_not_called()
    assert len(state_out.deferred) == 1


@pytest.mark.parametrize("leader", [True, False])
def test_replica_set_adds_oauth_ca_and_requests_restart(
    mongodb_ctx, mongodb_container, mocker, certificates, leader
):
    ca_secret = Secret(
        tracked_content={"oauth-ca": certificates.rotated},
        owner="app",
        label=f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app",
    )
    state_in = replace(
        mongo_state(
            mongodb_container,
            leader=leader,
            peer_data={"oauth-issuer": "https://issuer.example"},
        ),
        secrets={ca_secret},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        ca_file = operator.workload.paths.oauth_ca_file
        files = {}
        mocker.patch.object(operator.workload, "exists", side_effect=lambda path: path in files)
        write = mocker.patch.object(
            operator.workload,
            "write",
            side_effect=lambda path, content: files.update({path: content}),
        )
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.workload, "read", return_value=current.splitlines())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.restart_replica_set_when_ready()

        write.assert_called_once_with(ca_file, certificates.rotated)
        assert files[ca_file] == certificates.rotated
        request.assert_called_once_with(force=False)


@pytest.mark.parametrize("leader", [True, False])
def test_replica_set_removes_oauth_ca_and_requests_restart(
    mongodb_ctx, mongodb_container, mocker, certificates, leader
):
    state_in = replace(
        mongo_state(
            mongodb_container,
            leader=leader,
            peer_data={"oauth-issuer": "https://issuer.example"},
        ),
        secrets=set(),
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        ca_file = operator.workload.paths.oauth_ca_file
        files = {ca_file: certificates.root}
        mocker.patch.object(operator.workload, "exists", side_effect=lambda path: path in files)
        delete = mocker.patch.object(
            operator.workload, "delete", side_effect=lambda path: files.pop(path)
        )
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.workload, "read", return_value=current.splitlines())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.restart_replica_set_when_ready()

        delete.assert_called_once_with(ca_file)
        assert ca_file not in files
        request.assert_called_once_with(force=False)


@pytest.mark.parametrize("leader", [True, False])
def test_replica_set_rotates_oauth_ca_without_requesting_restart(
    mongodb_ctx, mongodb_container, mocker, certificates, leader
):
    ca_secret = Secret(
        tracked_content={"oauth-ca": certificates.rotated},
        owner="app",
        label=f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app",
    )
    state_in = replace(
        mongo_state(
            mongodb_container,
            leader=leader,
            peer_data={"oauth-issuer": "https://issuer.example"},
        ),
        secrets={ca_secret},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        ca_file = operator.workload.paths.oauth_ca_file
        files = {ca_file: certificates.root}
        mocker.patch.object(operator.workload, "exists", side_effect=lambda path: path in files)
        write = mocker.patch.object(
            operator.workload,
            "write",
            side_effect=lambda path, content: files.update({path: content}),
        )
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.workload, "read", return_value=current.splitlines())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.restart_replica_set_when_ready()

        write.assert_called_once_with(ca_file, certificates.rotated)
        assert files[ca_file] == certificates.rotated
        request.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_adds_oauth_ca_and_restarts(
    mongos_ctx,
    mongodb_container,
    mongos_cluster,
    mongos_oauth_restart,
    mocker,
    certificates,
    leader,
):
    ca_secret = Secret(tracked_content={"oauth-ca": certificates.rotated})
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://issuer.example",
            "secret-extra": ca_secret.id,
        },
    )
    state_in = replace(
        mongos_state(mongodb_container, leader=leader, relations={cluster}),
        secrets={ca_secret},
    )
    with mongos_oauth_restart(state_in, mongos_ctx.on.collect_unit_status()) as context:
        operator = context.scenario.charm.operator
        ca_file = operator.workload.paths.oauth_ca_file
        files = {}
        mocker.patch.object(operator.workload, "exists", side_effect=lambda path: path in files)
        context.write.side_effect = lambda path, content: files.update({path: content})
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.workload, "read", return_value=current.splitlines())
        mocker.patch.object(operator.tls_manager, "reconcile_tls", return_value=False)
        mocker.patch.object(operator, "finalize_after_restart")
        mocker.patch.object(operator, "recompute_statuses")

        context.cluster.async_update_mongos_and_restart()

        context.write.assert_called_once_with(ca_file, certificates.rotated)
        assert files[ca_file] == certificates.rotated
        context.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_removes_oauth_ca_and_restarts(
    mongos_ctx,
    mongodb_container,
    mongos_cluster,
    mongos_oauth_restart,
    mocker,
    certificates,
    leader,
):
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://issuer.example",
        },
    )
    state_in = replace(
        mongos_state(mongodb_container, leader=leader, relations={cluster}),
        secrets=set(),
    )
    with mongos_oauth_restart(state_in, mongos_ctx.on.collect_unit_status()) as context:
        operator = context.scenario.charm.operator
        ca_file = operator.workload.paths.oauth_ca_file
        files = {ca_file: certificates.root}
        mocker.patch.object(operator.workload, "exists", side_effect=lambda path: path in files)
        context.write.side_effect = lambda path, content: files.update({path: content})
        delete = mocker.patch.object(
            operator.workload, "delete", side_effect=lambda path: files.pop(path)
        )
        current = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.workload, "read", return_value=current.splitlines())
        mocker.patch.object(operator.tls_manager, "reconcile_tls", return_value=False)
        mocker.patch.object(operator, "finalize_after_restart")
        mocker.patch.object(operator, "recompute_statuses")

        context.cluster.async_update_mongos_and_restart()

        delete.assert_called_once_with(ca_file)
        assert ca_file not in files
        context.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
