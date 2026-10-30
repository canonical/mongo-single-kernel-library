# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from charmlibs.interfaces.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    CertificateSigningRequest,
    PrivateKey,
)
from data_platform_helpers.advanced_statuses.models import StatusObject
from ops.model import BlockedStatus
from ops.testing import Relation, Secret
from yaml import safe_dump

from single_kernel_mongo.config.literals import RollingOpsCallbackId
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from tests.unit.auth_scenario_helpers import get_relation, mongo_state, mongos_state, oauth_relation

pytest_plugins = ("tests.unit.auth_scenario_helpers",)

pytestmark = pytest.mark.usefixtures("short_mock_fs_interactions")


@pytest.fixture
def certificates():
    """Generate a PEM chain and a replacement CA with TLS charmlibs."""
    validity = timedelta(days=365)
    root_key = PrivateKey.generate()
    root = Certificate.generate_self_signed_ca(
        attributes=CertificateRequestAttributes(common_name="Root CA"),
        private_key=root_key,
        validity=validity,
    )
    intermediate_key = PrivateKey.generate()
    intermediate_csr = CertificateSigningRequest.generate(
        attributes=CertificateRequestAttributes(common_name="Intermediate CA"),
        private_key=intermediate_key,
    )
    intermediate = Certificate.generate(
        csr=intermediate_csr,
        ca=root,
        ca_private_key=root_key,
        validity=validity,
        is_ca=True,
    )
    leaf_csr = CertificateSigningRequest.generate(
        attributes=CertificateRequestAttributes(common_name="issuer.example"),
        private_key=PrivateKey.generate(),
    )
    leaf = Certificate.generate(
        csr=leaf_csr,
        ca=intermediate,
        ca_private_key=intermediate_key,
        validity=validity,
    )
    rotated = Certificate.generate_self_signed_ca(
        attributes=CertificateRequestAttributes(common_name="Rotated CA"),
        private_key=PrivateKey.generate(),
        validity=validity,
    )
    return SimpleNamespace(
        root=str(root), intermediate=str(intermediate), leaf=str(leaf), rotated=str(rotated)
    )


@pytest.fixture
def workload_files(mocker):
    """Keep workload I/O in memory while preserving read-after-write semantics."""

    def attach(workload):
        files = {}
        mocker.patch.object(
            workload, "read", side_effect=lambda path: files.get(path, "").splitlines()
        )
        mocker.patch.object(workload, "exists", side_effect=lambda path: path in files)
        write = mocker.patch.object(
            workload, "write", side_effect=lambda path, content: files.update({path: content})
        )
        delete = mocker.patch.object(
            workload, "delete", side_effect=lambda path: files.pop(path, None)
        )
        return SimpleNamespace(files=files, write=write, delete=delete)

    return attach


def certificate_relation(certificates, ca=None):
    return Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={
            "version": "1",
            "certificates": json.dumps([certificates.intermediate, ca or certificates.root]),
        },
    )


def test_replica_set_receives_pem_chain_in_peer_secret(
    mongodb_ctx, mongodb_container, certificates, workload_files, mocker
):
    relation = certificate_relation(certificates)
    state_in = mongo_state(
        mongodb_container,
        peer_data={"oauth-issuer": "https://issuer.example"},
        relations={relation},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(relation, remote_unit=0), state_in
    ) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        io.files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request_restart = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    bundle = "\n".join(sorted([certificates.root, certificates.intermediate]))
    secret = next(
        secret
        for secret in state_out.secrets
        if secret.label == f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app"
    )
    assert secret.latest_content["oauth-ca"] == bundle
    assert io.files[operator.workload.paths.oauth_ca_file] == bundle
    request_restart.assert_called_once_with(force=False)


def test_new_router_receives_ca_from_peer_secret(
    mongodb_ctx, mongodb_container, certificates, mocker
):
    relation = Relation(
        endpoint="cluster", remote_app_name="new-router", remote_app_data={"database": "mongos"}
    )
    state_in = mongo_state(mongodb_container, role=MongoDBRoles.CONFIG_SERVER, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation), state_in) as scenario:
        operator = scenario.charm.operator
        operator.state.app_peer_data.oauth_ca = certificates.root
        mocker.patch.object(operator.mongo_manager, "reconcile_mongo_users_and_dbs")
        mocker.patch.object(
            operator.state, "generate_config_server_db", return_value="rs/10.0.0.3:27017"
        )
        mocker.patch.object(operator.state, "get_keyfile", return_value="keyfile")

        state_out = scenario.run()

    assert state_out.get_relation(relation.id).local_app_data["oauth-ca"] == certificates.root


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_invalid_peer_ca_reports_tls_error(mongodb_ctx, mongodb_container, mocker, role):
    state_in = mongo_state(
        mongodb_container, role=role, relations={oauth_relation("https://issuer.example")}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        operator.state.app_peer_data.oauth_ca = "invalid PEM"
        mocker.patch.object(
            operator, "get_statuses", return_value=[StatusObject(status="active", message="")]
        )
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.configure()
        state_out = scenario.run()

        assert state_out.unit_status == BlockedStatus(OAuthStatuses.ISSUER_TLS_ERROR.value.message)
        restart.assert_not_called()


def test_certificate_available_writes_replica_set_ca(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={
            "version": "1",
            "certificates": json.dumps(["root-ca", "intermediate-ca"]),
        },
    )
    state_in = mongo_state(mongodb_container, leader=True, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation), state_in) as scenario:
        operator = scenario.charm.operator
        write = mocker.patch.object(operator.workload, "write")

        scenario.run()

        write.assert_called_once_with(
            operator.workload.paths.oauth_ca_file, "intermediate-ca\nroot-ca"
        )


def test_certificate_available_does_not_write_config_server_ca(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state_in = mongo_state(mongodb_container, role=MongoDBRoles.CONFIG_SERVER, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation), state_in) as scenario:
        write = mocker.patch.object(scenario.charm.operator.workload, "write")

        scenario.run()

        write.assert_not_called()


def test_certificate_removed_deletes_replica_set_ca(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state_in = mongo_state(mongodb_container, leader=True, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_broken(relation), state_in) as scenario:
        workload = scenario.charm.operator.workload
        mocker.patch.object(workload, "exists", return_value=True)
        delete = mocker.patch.object(workload, "delete")

        scenario.run()

        delete.assert_called_once_with(workload.paths.oauth_ca_file)


@pytest.mark.parametrize("bundle", ["first-ca", "updated-ca"])
def test_certificate_available_publishes_config_server_ca_to_mongos(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, config_server_relations, bundle
):
    first, second, pending = config_server_relations
    certificate_relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps([bundle])},
    )
    state_in = mongo_state(
        mongodb_container,
        role=MongoDBRoles.CONFIG_SERVER,
        relations={first, second, pending, certificate_relation},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificate_relation), state_in) as scenario:
        write = mocker.patch.object(scenario.charm.operator.workload, "write")

        state_out = scenario.run()

    assert state_out.get_relation(first.id).local_app_data["oauth-ca"] == bundle
    assert state_out.get_relation(second.id).local_app_data["oauth-ca"] == bundle
    assert "oauth-ca" not in state_out.get_relation(pending.id).local_app_data
    write.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
@pytest.mark.parametrize("bundle", ["first-ca", "updated-ca"])
def test_mongos_stores_oauth_ca_from_cluster_relation(
    mock_issuer_tls,
    mongos_ctx,
    mongodb_container,
    mongos_oauth_restart,
    mongos_cluster,
    leader,
    bundle,
):
    cluster = replace(
        mongos_cluster, remote_app_data={**mongos_cluster.remote_app_data, "oauth-ca": bundle}
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_oauth_restart(state_in, mongos_ctx.on.relation_changed(cluster)) as run:
        run.scenario.run()

        run.write.assert_called_once_with(run.config.workload.paths.oauth_ca_file, bundle)


def test_replica_set_oidc_provider_uses_local_ca(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    state_in = mongo_state(mongodb_container, peer_data={"oauth-issuer": "https://issuer.example"})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert providers[0]["serverCAFile"] == str(operator.workload.paths.oauth_ca_file)


def test_replica_set_oidc_provider_omits_missing_ca(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    state_in = mongo_state(mongodb_container, peer_data={"oauth-issuer": "https://issuer.example"})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=False)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert "serverCAFile" not in providers[0]


def test_replica_set_ca_alone_does_not_enable_oidc(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    state_in = mongo_state(
        mongodb_container,
    )
    with mongodb_ctx(
        mongodb_ctx.on.collect_unit_status(),
        state_in,
    ) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        assert operator.config_manager.oauth_parameters == {}


def test_mongos_oidc_provider_uses_local_ca(
    mock_issuer_tls, mongos_ctx, mongodb_container, mocker, mongos_cluster
):
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://issuer.example",
        },
    )
    state_in = mongos_state(mongodb_container, relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert providers[0]["serverCAFile"] == str(operator.workload.paths.oauth_ca_file)


def test_mongos_oidc_provider_omits_missing_ca(
    mock_issuer_tls, mongos_ctx, mongodb_container, mocker, mongos_cluster
):
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://issuer.example",
        },
    )
    state_in = mongos_state(mongodb_container, relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=False)

        config = operator.config_manager.build_config()

        providers = json.loads(config["setParameter"]["oidcIdentityProviders"])
        assert len(providers) == 1
        assert "serverCAFile" not in providers[0]


def test_mongos_ca_alone_does_not_enable_oidc(
    mock_issuer_tls, mongos_ctx, mongodb_container, mocker, mongos_cluster
):
    state_in = mongos_state(mongodb_container, relations={mongos_cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        assert operator.config_manager.oauth_parameters == {}


def test_replica_set_ca_removal_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, workload_files
):
    relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state_in = mongo_state(
        mongodb_container,
        leader=True,
        peer_data={"oauth-issuer": "https://issuer.example"},
        relations={relation},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_broken(relation), state_in) as scenario:
        operator = scenario.charm.operator
        files = workload_files(operator.workload).files
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

        request.assert_called_once_with(force=False)
        assert operator.workload.paths.oauth_ca_file not in files


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_ca_addition_requests_restart(
    mock_issuer_tls,
    mongos_oauth_restart,
    mongos_ctx,
    mongodb_container,
    mongos_cluster,
    workload_files,
    leader,
):
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": "root-ca",
        },
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_oauth_restart(state_in, mongos_ctx.on.relation_changed(cluster)) as run:
        operator = run.scenario.charm.operator
        files = workload_files(operator.workload).files
        files[run.config.file] = safe_dump(run.config.build_config())

        run.scenario.run()

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        assert files[operator.workload.paths.oauth_ca_file] == "root-ca"


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_ca_rotation_does_not_restart_service(
    mock_issuer_tls,
    mongos_oauth_restart,
    mongos_ctx,
    mongodb_container,
    mongos_cluster,
    workload_files,
    leader,
):
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": "updated-ca",
        },
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_oauth_restart(state_in, mongos_ctx.on.relation_changed(cluster)) as run:
        operator = run.scenario.charm.operator
        files = workload_files(operator.workload).files
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[run.config.file] = safe_dump(run.config.build_config())

        run.scenario.run()
        run.cluster.update_mongos_and_restart(force=False)

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        run.restart.assert_not_called()
        assert files[operator.workload.paths.oauth_ca_file] == "updated-ca"


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_ca_removal_requests_restart(
    mock_issuer_tls,
    mongos_oauth_restart,
    mongos_ctx,
    mongodb_container,
    mongos_cluster,
    workload_files,
    leader,
):
    cluster = replace(
        mongos_cluster,
        remote_app_data={
            **mongos_cluster.remote_app_data,
            "oauth-issuer": "https://issuer.example",
        },
    )
    state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
    with mongos_oauth_restart(state_in, mongos_ctx.on.relation_changed(cluster)) as run:
        operator = run.scenario.charm.operator
        files = workload_files(operator.workload).files
        path = operator.workload.paths.oauth_ca_file
        files[path] = "previous-ca"
        files[run.config.file] = safe_dump(run.config.build_config())

        run.scenario.run()

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        assert path not in files


def test_config_server_ca_removal_is_shared_with_mongos(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, config_server_relations
):
    first, second, pending = config_server_relations
    first = replace(first, local_app_data={"oauth-ca": "previous-ca"})
    second = replace(second, local_app_data={"oauth-ca": "previous-ca"})
    certificate_relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state_in = mongo_state(
        mongodb_container,
        role=MongoDBRoles.CONFIG_SERVER,
        relations={first, second, pending, certificate_relation},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_broken(certificate_relation), state_in) as scenario:
        restart = mocker.patch.object(scenario.charm.operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert "oauth-ca" not in state_out.get_relation(first.id).local_app_data
    assert "oauth-ca" not in state_out.get_relation(second.id).local_app_data
    assert "oauth-ca" not in state_out.get_relation(pending.id).local_app_data
    restart.assert_not_called()


def test_peer_change_writes_follower_ca_and_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, workload_files
):
    secret = Secret(
        tracked_content={"oauth-ca": "root-ca"},
        owner="app",
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
    original_peer = get_relation(state_in, PeerRelationNames.PEERS.value)
    peer = replace(original_peer, peers_data={1: {}})
    state_in = replace(state_in, relations=(state_in.relations - {original_peer}) | {peer})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(peer, remote_unit=1), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator, "peer_changed")
        files = workload_files(operator.workload).files
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        state_out = scenario.run()

    assert files[operator.workload.paths.oauth_ca_file] == "root-ca"
    request.assert_called_once_with(force=False)
    assert get_relation(state_out, peer.endpoint).local_app_data == peer.local_app_data


def test_peer_secret_rotation_updates_follower_ca_without_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, workload_files
):
    secret = Secret(
        tracked_content={"oauth-ca": "updated-ca"},
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
    peer = get_relation(state_in, PeerRelationNames.PEERS.value)
    with mongodb_ctx(mongodb_ctx.on.secret_changed(secret), state_in) as scenario:
        operator = scenario.charm.operator
        files = workload_files(operator.workload).files
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        state_out = scenario.run()

    assert files[operator.workload.paths.oauth_ca_file] == "updated-ca"
    request.assert_not_called()
    assert get_relation(state_out, peer.endpoint).local_app_data == peer.local_app_data


def test_peer_change_removes_follower_ca_and_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, workload_files
):
    state_in = mongo_state(
        mongodb_container, leader=False, peer_data={"oauth-issuer": "https://issuer.example"}
    )
    original_peer = get_relation(state_in, PeerRelationNames.PEERS.value)
    peer = replace(original_peer, peers_data={1: {}})
    state_in = replace(state_in, relations=(state_in.relations - {original_peer}) | {peer})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(peer, remote_unit=1), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator, "peer_changed")
        files = workload_files(operator.workload).files
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        state_out = scenario.run()

    assert operator.workload.paths.oauth_ca_file not in files
    request.assert_called_once_with(force=False)
    assert get_relation(state_out, peer.endpoint).local_app_data == peer.local_app_data
