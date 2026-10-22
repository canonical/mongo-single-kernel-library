# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import ssl
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import PropertyMock
from urllib.error import URLError

import pytest
from charmlibs.interfaces.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    CertificateSigningRequest,
    PrivateKey,
)
from ops.testing import Relation, Secret
from yaml import safe_dump

from single_kernel_mongo.config.literals import RollingOpsCallbackId
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from tests.unit.auth_scenario_helpers import get_relation, mongo_state, mongos_state, oauth_relation

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
        request = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    bundle = "\n".join(sorted([certificates.root, certificates.intermediate]))
    secret = next(
        secret
        for secret in state_out.secrets
        if secret.label == f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app"
    )
    assert secret.latest_content["oauth-ca"] == bundle
    assert "oauth-ca" not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    assert io.files[operator.workload.paths.oauth_ca_file] == bundle
    request.assert_called_once_with(force=False)


def test_ca_rotation_preserves_config_with_real_certificates(
    mongodb_ctx, mongodb_container, certificates, workload_files, mocker
):
    relation = certificate_relation(certificates, certificates.rotated)
    state_in = mongo_state(
        mongodb_container,
        peer_data={"oauth-issuer": "https://issuer.example"},
        relations={relation},
    )
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(relation, remote_unit=0), state_in
    ) as scenario:
        operator = scenario.charm.operator
        operator.state.app_peer_data.oauth_ca = certificates.root
        io = workload_files(operator.workload)
        io.files[operator.workload.paths.oauth_ca_file] = certificates.root
        current = safe_dump(operator.config_manager.build_config())
        io.files[operator.config_manager.file] = current
        request = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    bundle = "\n".join(sorted([certificates.rotated, certificates.intermediate]))
    assert io.files[operator.workload.paths.oauth_ca_file] == bundle
    assert io.files[operator.config_manager.file] == current
    secret = next(secret for secret in state_out.secrets if "oauth-ca" in secret.latest_content)
    assert secret.latest_content["oauth-ca"] == bundle
    request.assert_not_called()


def test_new_router_receives_ca_from_peer_secret(
    mongodb_ctx, mongodb_container, certificates, mocker
):
    relation = Relation(
        endpoint="cluster", remote_app_name="new-router", remote_app_data={"database": "mongos"}
    )
    state_in = mongo_state(mongodb_container, role=MongoDBRoles.CONFIG_SERVER, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        operator.state.app_peer_data.oauth_ca = certificates.root
        mocker.patch.object(operator.mongo_manager, "reconcile_mongo_users_and_dbs")
        mocker.patch.object(
            operator.state, "generate_config_server_db", return_value="rs/10.0.0.3:27017"
        )
        mocker.patch.object(operator.state, "get_keyfile", return_value="keyfile")

        operator.cluster_manager.share_secret_to_mongos(
            operator.charm.model.get_relation("cluster")
        )
        state_out = scenario.run()

    assert state_out.get_relation(relation.id).local_app_data["oauth-ca"] == certificates.root


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_issuer_ssl_context_loads_peer_pem_chain(
    mongodb_ctx, mongodb_container, certificates, role
):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        manager = scenario.charm.operator.oauth_manager
        manager.state.app_peer_data.oauth_ca = "\n".join(
            [certificates.root, certificates.intermediate]
        )

        context = manager._issuer_ssl_context()

        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert len(context.get_ca_certs(binary_form=True)) == 2


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_issuer_ssl_context_uses_system_trust_without_ca(mongodb_ctx, mongodb_container, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        context = scenario.charm.operator.oauth_manager._issuer_ssl_context()

        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert context.get_ca_certs(binary_form=True) == ssl.create_default_context().get_ca_certs(
            binary_form=True
        )


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_invalid_peer_ca_reports_tls_error(mongodb_ctx, mongodb_container, mocker, role):
    state_in = mongo_state(mongodb_container, role=role)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        manager = scenario.charm.operator.oauth_manager
        manager.state.app_peer_data.oauth_ca = "invalid PEM"
        request = mocker.patch("single_kernel_mongo.managers.oauth.urlopen")

        assert (
            manager.check_issuer_connection("https://issuer.example")
            == OAuthStatuses.ISSUER_TLS_ERROR.value
        )
        request.assert_not_called()


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


def test_mongos_oidc_provider_uses_local_ca(mock_issuer_tls, mongos_ctx, mongodb_container, mocker):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={"oauth-issuer": "https://issuer.example"},
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
    mock_issuer_tls, mongos_ctx, mongodb_container, mocker
):
    cluster = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={"oauth-issuer": "https://issuer.example"},
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
    mock_issuer_tls, mongos_ctx, mongodb_container, mocker
):
    cluster = Relation(endpoint="cluster", remote_app_name="config-server")
    state_in = mongos_state(mongodb_container, relations={cluster})
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "exists", return_value=True)

        assert operator.config_manager.oauth_parameters == {}


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


def test_replica_set_ca_removal_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, oauth_workload_files
):
    state_in = mongo_state(
        mongodb_container, leader=True, peer_data={"oauth-issuer": "https://issuer.example"}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        files = oauth_workload_files(operator.workload)
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.oauth_manager.remove_certificates()

        request.assert_called_once_with(force=False)
        assert operator.workload.paths.oauth_ca_file not in files


@pytest.fixture
def mongos_ca_restart(mongos_ctx, mongodb_container, mocker, oauth_workload_files, tmp_path):
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
        state_in = mongos_state(mongodb_container, leader=leader, relations={cluster})
        with mongos_ctx(mongos_ctx.on.relation_changed(cluster), state_in) as scenario:
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
def test_mongos_ca_addition_requests_restart(mock_issuer_tls, mongos_ca_restart, leader):
    with mongos_ca_restart("root-ca", leader=leader) as run:
        config = run.operator.config_manager
        run.files[config.file] = safe_dump(config.build_config())

        run.scenario.run()

        run.request.assert_called_once_with(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": False}
        )
        assert run.files[run.operator.workload.paths.oauth_ca_file] == "root-ca"


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_ca_rotation_does_not_restart_service(
    mock_issuer_tls, mongos_ca_restart, mocker, leader
):
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
def test_mongos_ca_removal_requests_restart(mock_issuer_tls, mongos_ca_restart, leader):
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


def test_replica_set_certificate_arrival_retries_pending_issuer(
    mongodb_ctx, mongodb_container, mocker, oauth_workload_files, mock_issuer_tls
):
    issuer = "https://issuer.example"
    certificates = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state_in = mongo_state(mongodb_container, relations={oauth_relation(issuer), certificates})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificates), state_in) as scenario:
        operator = scenario.charm.operator
        files = oauth_workload_files(operator.workload)
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        successful_response = mock_issuer_tls.request.side_effect
        mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
        operator.oauth_manager.configure()
        assert operator.state.app_peer_data.oauth_issuer is None
        mock_issuer_tls.request.side_effect = successful_response

        state_out = scenario.run()

    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == issuer
    )
    assert files[operator.workload.paths.oauth_ca_file] == "root-ca"
    assert OAuthStatuses.ISSUER_TLS_ERROR.value not in operator.oauth_manager.get_statuses("unit")
    request.assert_called_once_with(force=False)


def test_config_server_certificate_arrival_retries_and_shares_pending_issuer(
    mongodb_ctx, mongodb_container, mocker, mock_issuer_tls, config_server_relations
):
    issuer = "https://issuer.example"
    first, second, pending = config_server_relations
    certificates = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state_in = mongo_state(
        mongodb_container,
        role=MongoDBRoles.CONFIG_SERVER,
        relations={oauth_relation(issuer), certificates, first, second, pending},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificates), state_in) as scenario:
        operator = scenario.charm.operator
        request = mocker.patch.object(operator, "async_restart_charm_services")
        successful_response = mock_issuer_tls.request.side_effect
        mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
        operator.oauth_manager.configure()
        assert operator.state.app_peer_data.oauth_issuer is None
        mock_issuer_tls.request.side_effect = successful_response

        state_out = scenario.run()

    assert (
        get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data["oauth-issuer"]
        == issuer
    )
    assert state_out.get_relation(first.id).local_app_data["oauth-issuer"] == issuer
    assert state_out.get_relation(second.id).local_app_data["oauth-issuer"] == issuer
    assert "oauth-issuer" not in state_out.get_relation(pending.id).local_app_data
    assert OAuthStatuses.ISSUER_TLS_ERROR.value not in operator.oauth_manager.get_statuses("unit")
    request.assert_not_called()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_certificate_arrival_keeps_invalid_issuer_unstored(
    mongodb_ctx, mongodb_container, mocker, oauth_workload_files, mock_issuer_tls, role
):
    certificates = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state_in = mongo_state(
        mongodb_container,
        role=role,
        relations={oauth_relation("https://issuer.example"), certificates},
    )
    mock_issuer_tls.request.side_effect = URLError(ssl.SSLCertVerificationError("unknown CA"))
    with mongodb_ctx(mongodb_ctx.on.relation_changed(certificates), state_in) as scenario:
        operator = scenario.charm.operator
        oauth_workload_files(operator.workload)
        request = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

    assert (
        "oauth-issuer" not in get_relation(state_out, PeerRelationNames.PEERS.value).local_app_data
    )
    assert operator.oauth_manager.get_statuses("unit") == [OAuthStatuses.ISSUER_TLS_ERROR.value]
    request.assert_not_called()


@pytest.fixture
def config_server_oauth_secret(mongodb_container):
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
    state_in = replace(
        mongo_state(mongodb_container, role=MongoDBRoles.CONFIG_SERVER, relations={cluster}),
        secrets={secret},
    )
    return SimpleNamespace(cluster=cluster, secret=secret, state_in=state_in)


def test_certificate_available_follower_waits_for_peer_state(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["root-ca"])},
    )
    state_in = mongo_state(mongodb_container, leader=False, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation), state_in) as scenario:
        write = mocker.patch.object(scenario.charm.operator.workload, "write")
        state_out = scenario.run()

    write.assert_not_called()
    assert state_out.secrets == state_in.secrets


def test_peer_change_writes_follower_ca_and_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, oauth_workload_files
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
        files = oauth_workload_files(operator.workload)
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        state_out = scenario.run()

    assert files[operator.workload.paths.oauth_ca_file] == "root-ca"
    request.assert_called_once_with(force=False)
    assert get_relation(state_out, peer.endpoint).local_app_data == peer.local_app_data


def test_peer_secret_rotation_updates_follower_ca_without_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, oauth_workload_files
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
        files = oauth_workload_files(operator.workload)
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        state_out = scenario.run()

    assert files[operator.workload.paths.oauth_ca_file] == "updated-ca"
    request.assert_not_called()
    assert get_relation(state_out, peer.endpoint).local_app_data == peer.local_app_data


def test_peer_change_removes_follower_ca_and_requests_restart(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker, oauth_workload_files
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
        files = oauth_workload_files(operator.workload)
        files[operator.workload.paths.oauth_ca_file] = "previous-ca"
        files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")
        state_out = scenario.run()

    assert operator.workload.paths.oauth_ca_file not in files
    request.assert_called_once_with(force=False)
    assert get_relation(state_out, peer.endpoint).local_app_data == peer.local_app_data


def test_certificate_removal_clears_peer_ca(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    state_in = mongo_state(mongodb_container)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "write")
        mocker.patch.object(operator.workload, "exists", return_value=False)
        operator.oauth_manager.store_certificates({"root-ca"})

        operator.oauth_manager.remove_certificates()

        assert operator.state.app_peer_data.oauth_ca is None
        scenario.run()


def test_peer_secret_rotation_updates_existing_secret(
    mock_issuer_tls, mongodb_ctx, mongodb_container, mocker
):
    state_in = mongo_state(mongodb_container)
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.workload, "write")
        operator.oauth_manager.store_certificates({"previous-ca"})
        label = f"{PeerRelationNames.PEERS.value}.{mongodb_ctx.app_name}.app"
        secret_id = operator.charm.model.get_secret(label=label).get_info().id

        operator.oauth_manager.store_certificates({"updated-ca"})
        state_out = scenario.run()

    secret = next(secret for secret in state_out.secrets if secret.id == secret_id)
    assert secret.latest_content["oauth-ca"] == "updated-ca"
