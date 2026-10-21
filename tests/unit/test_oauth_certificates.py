# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import ssl
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import PropertyMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ops.testing import Relation
from yaml import safe_dump, safe_load

from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import MongosStatuses, OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.managers.oauth import verify_https_endpoint
from tests.unit.auth_scenario_helpers import get_relation

pytestmark = pytest.mark.usefixtures("short_mock_fs_interactions")


def issue_certificate(subject, key, issuer, issuer_key, is_ca):
    """Create real PEM certificates for trust-chain validation tests."""
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )


@pytest.fixture
def certificates():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Root CA")])
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Intermediate CA")])
    leaf_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "issuer.example")])
    rotated_key = ec.generate_private_key(ec.SECP256R1())
    rotated_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Rotated CA")])
    root = issue_certificate(root_name, root_key, root_name, root_key, True)
    intermediate = issue_certificate(intermediate_name, intermediate_key, root_name, root_key, True)
    leaf = issue_certificate(
        leaf_name,
        ec.generate_private_key(ec.SECP256R1()),
        intermediate_name,
        intermediate_key,
        False,
    )
    rotated = issue_certificate(rotated_name, rotated_key, rotated_name, rotated_key, True)
    return SimpleNamespace(root=root, intermediate=intermediate, leaf=leaf, rotated=rotated)


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


def test_replica_set_receives_ca_and_requests_restart(
    mongodb_ctx, mongo_auth_state, certificates, workload_files, mocker
):
    relation = certificate_relation(certificates)
    state = mongo_auth_state(
        peer_data={"oauth-issuer": "https://issuer.example"}, relations={relation}
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation, remote_unit=0), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        request = mocker.patch.object(operator, "async_restart_charm_services")
        current = safe_dump(operator.config_manager.build_config())
        io.files[operator.config_manager.file] = current

        result = scenario.run()

    bundle = get_relation(result, PeerRelationNames.PEERS.value).local_app_data["oauth-ca"]
    assert io.files[operator.workload.paths.oauth_ca_file] == bundle
    assert bundle == "\n".join(sorted([certificates.root, certificates.intermediate]))
    request.assert_called_once_with(force=False)


def test_replica_set_follower_reconciles_ca_from_peer_data(
    mongodb_ctx, mongo_auth_state, certificates, workload_files, mocker
):
    state = mongo_auth_state(
        leader=False,
        peer_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": certificates.root,
        },
    )
    original_peer = get_relation(state, PeerRelationNames.PEERS.value)
    peer = replace(original_peer, peers_data={1: {}})
    state = replace(state, relations=(state.relations - {original_peer}) | {peer})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(peer, remote_unit=1), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator, "peer_changed")
        io = workload_files(operator.workload)
        io.files[operator.config_manager.file] = "{}"
        request = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

    assert io.files[operator.workload.paths.oauth_ca_file] == certificates.root
    request.assert_called_once_with(force=False)


def test_ca_rotation_updates_file_without_restart(
    mongodb_ctx, mongo_auth_state, certificates, workload_files, mocker
):
    relation = certificate_relation(certificates, certificates.rotated)
    state = mongo_auth_state(
        peer_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": certificates.root,
        },
        relations={relation},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation, remote_unit=0), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        io.files[operator.workload.paths.oauth_ca_file] = certificates.root
        current = safe_dump(operator.config_manager.build_config())
        io.files[operator.config_manager.file] = current
        request = mocker.patch.object(operator, "async_restart_charm_services")

        scenario.run()

    assert certificates.rotated in io.files[operator.workload.paths.oauth_ca_file]
    assert io.files[operator.config_manager.file] == current
    request.assert_not_called()


@pytest.mark.parametrize(
    ("trust_status", "expected_statuses"),
    [(None, []), (OAuthStatuses.ISSUER_UNTRUSTED.value, [OAuthStatuses.ISSUER_UNTRUSTED.value])],
)
def test_ca_removal_restarts_for_setting_change_and_checks_remaining_trust(
    mongodb_ctx,
    mongo_auth_state,
    certificates,
    workload_files,
    mocker,
    mock_oauth_issuer_verification,
    trust_status,
    expected_statuses,
):
    relation = certificate_relation(certificates)
    state = mongo_auth_state(
        peer_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": certificates.root,
        },
        relations={relation},
    )
    mock_oauth_issuer_verification.return_value = trust_status
    with mongodb_ctx(mongodb_ctx.on.relation_broken(relation), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        path = operator.workload.paths.oauth_ca_file
        io.files[path] = certificates.root
        io.files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        result = scenario.run()

    assert "oauth-ca" not in get_relation(result, PeerRelationNames.PEERS.value).local_app_data
    # Preserve the old file until the rolling callback removes serverCAFile from the config.
    assert path in io.files
    request.assert_called_once_with(force=False)
    mock_oauth_issuer_verification.assert_called_with(
        operator.workload, "https://issuer.example", None
    )
    assert operator.oauth_certificate_manager.get_statuses("unit") == expected_statuses


def test_ca_file_deleted_after_config_no_longer_references_it(
    mongodb_ctx, mongo_auth_state, certificates, workload_files
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), mongo_auth_state()) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        path = operator.workload.paths.oauth_ca_file
        io.files[path] = certificates.root
        io.files[operator.config_manager.file] = "{}"

        operator.oauth_certificate_manager.cleanup_removed_ca()

        io.delete.assert_called_once_with(path)
        assert path not in io.files


def test_invalid_certificate_is_stored_but_not_written_to_workload(
    mongodb_ctx, mongo_auth_state, certificates, workload_files, mocker
):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_app_data={"version": "1", "certificates": json.dumps(["invalid"])},
    )
    state = mongo_auth_state(peer_data={"oauth-ca": certificates.root}, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation, remote_unit=0), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        io.files[operator.workload.paths.oauth_ca_file] = certificates.root
        request = mocker.patch.object(operator, "async_restart_charm_services")

        result = scenario.run()

    assert (
        get_relation(result, PeerRelationNames.PEERS.value).local_app_data["oauth-ca"] == "invalid"
    )
    assert result.unit_status.name == "blocked"
    assert operator.oauth_certificate_manager.get_statuses("unit") == [
        OAuthStatuses.INVALID_CA.value
    ]
    assert io.files[operator.workload.paths.oauth_ca_file] == certificates.root
    io.write.assert_not_called()
    request.assert_not_called()


@pytest.fixture
def router_relations():
    return (
        Relation(
            endpoint="cluster", remote_app_name="mongos-one", remote_app_data={"database": "mongos"}
        ),
        Relation(
            endpoint="cluster", remote_app_name="mongos-two", remote_app_data={"database": "mongos"}
        ),
        Relation(endpoint="cluster", remote_app_name="pending"),
    )


def test_config_server_distributes_ca_updates(
    mongodb_ctx, mongo_auth_state, certificates, workload_files, mocker, router_relations
):
    relation = certificate_relation(certificates)
    first, second, pending = router_relations
    state = mongo_auth_state(
        role=MongoDBRoles.CONFIG_SERVER,
        peer_data={"oauth-issuer": "https://issuer.example"},
        relations={relation, first, second, pending},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation, remote_unit=0), state) as scenario:
        operator = scenario.charm.operator
        workload_files(operator.workload)
        request = mocker.patch.object(operator, "async_restart_charm_services")

        result = scenario.run()

    bundle = get_relation(result, PeerRelationNames.PEERS.value).local_app_data["oauth-ca"]
    assert result.get_relation(first.id).local_app_data["oauth-ca"] == bundle
    assert result.get_relation(second.id).local_app_data["oauth-ca"] == bundle
    assert "oauth-ca" not in result.get_relation(pending.id).local_app_data
    request.assert_not_called()


def test_config_server_distributes_ca_removal(
    mongodb_ctx, mongo_auth_state, certificates, workload_files, mocker, router_relations
):
    relation = certificate_relation(certificates)
    first, second, pending = router_relations
    first = replace(first, local_app_data={"oauth-ca": certificates.root})
    second = replace(second, local_app_data={"oauth-ca": certificates.root})
    state = mongo_auth_state(
        role=MongoDBRoles.CONFIG_SERVER,
        peer_data={"oauth-ca": certificates.root},
        relations={relation, first, second, pending},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_broken(relation), state) as scenario:
        operator = scenario.charm.operator
        workload_files(operator.workload)
        request = mocker.patch.object(operator, "async_restart_charm_services")

        result = scenario.run()

    assert "oauth-ca" not in result.get_relation(first.id).local_app_data
    assert "oauth-ca" not in result.get_relation(second.id).local_app_data
    request.assert_not_called()


def test_new_router_receives_existing_ca(mongodb_ctx, mongo_auth_state, certificates, mocker):
    relation = Relation(
        endpoint="cluster", remote_app_name="new-router", remote_app_data={"database": "mongos"}
    )
    state = mongo_auth_state(
        role=MongoDBRoles.CONFIG_SERVER,
        peer_data={"oauth-ca": certificates.root},
        relations={relation},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.mongo_manager, "reconcile_mongo_users_and_dbs")
        mocker.patch.object(
            operator.state, "generate_config_server_db", return_value="rs/10.0.0.3:27017"
        )
        mocker.patch.object(operator.state, "get_keyfile", return_value="keyfile")

        operator.cluster_manager.share_secret_to_mongos(
            operator.charm.model.get_relation("cluster")
        )
        result = scenario.run()

    assert result.get_relation(relation.id).local_app_data["oauth-ca"] == certificates.root


@pytest.mark.parametrize("leader", [True, False])
def test_mongos_reconciles_received_ca_and_setting(
    mongos_ctx, mongos_auth_state, certificates, workload_files, mocker, leader
):
    relation = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": certificates.root,
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.3:27017",
        },
    )
    state = mongos_auth_state(leader=leader, relations={relation})
    with mongos_ctx(mongos_ctx.on.relation_changed(relation), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        mocker.patch.object(operator.cluster_manager, "assert_pass_hook_checks")
        mocker.patch.object(operator.cluster_manager, "share_credentials_to_clients")
        mocker.patch("pathlib.Path.unlink")
        request = operator.rollingops_manager.request_async_lock
        request.reset_mock()

        scenario.run()

    path = operator.workload.paths.oauth_ca_file
    assert io.files[path] == certificates.root
    request.assert_called_once()


@pytest.mark.parametrize("leader", [True, False])
@pytest.mark.parametrize("external_ca", [None, "existing-config-server-CA"])
def test_mongos_ca_rotation_needs_no_rolling_lock(
    mongos_ctx, mongos_auth_state, certificates, workload_files, mocker, leader, external_ca
):
    relation = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": certificates.rotated,
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.3:27017",
        },
    )
    state = mongos_auth_state(leader=leader, relations={relation})
    with mongos_ctx(mongos_ctx.on.relation_changed(relation), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        path = operator.workload.paths.oauth_ca_file
        io.files[path] = certificates.root
        io.files[operator.workload.paths.keyfile] = "keyfile"
        io.files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        mocker.patch.object(operator.cluster_manager, "assert_pass_hook_checks")
        mocker.patch.object(operator.cluster_manager, "share_credentials_to_clients")
        mocker.patch("pathlib.Path.exists", return_value=external_ca is not None)
        mocker.patch("pathlib.Path.read_text", return_value=external_ca)
        mocker.patch(
            "single_kernel_mongo.state.cluster_state.ClusterState.external_ca_secret",
            new_callable=PropertyMock,
            return_value=external_ca,
        )
        request = operator.rollingops_manager.request_async_lock
        request.reset_mock()

        scenario.run()

    assert io.files[path] == certificates.rotated
    request.assert_not_called()
    assert (
        MongosStatuses.WAITING_FOR_MONGOS_START.value
        not in operator.state.statuses.get(scope="unit", component=operator.name).root
    )


def test_certificate_relation_is_not_allowed_on_shard(mongodb_ctx, mongo_auth_state):
    relation = Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca")
    state = mongo_auth_state(role=MongoDBRoles.SHARD, relations={relation})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        statuses = scenario.charm.operator.oauth_certificate_manager.get_statuses(
            "unit", recompute=True
        )
        assert statuses == [OAuthStatuses.INVALID_CERT_REL_ON_SHARD.value]


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_certificate_relation_conflicts_with_ldap(mongodb_ctx, mongo_auth_state, role):
    state = mongo_auth_state(
        role=role,
        relations={
            Relation(endpoint="oauth-certificate-transfer", remote_app_name="idp-ca"),
            Relation(endpoint="ldap", remote_app_name="glauth"),
        },
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        assert scenario.charm.operator.state.authentication_conflict


@pytest.mark.parametrize(
    ("issuer", "hostname", "port"),
    [
        ("https://issuer.example/path", "issuer.example", 443),
        ("https://10.0.0.3", "10.0.0.3", 443),
        ("https://[::1]:8443", "::1", 8443),
    ],
)
def test_tls_verification_uses_workload_roots_and_hostname_check(
    mocker, certificates, issuer, hostname, port
):
    workload = mocker.Mock()
    workload.read.return_value = certificates.root.splitlines()
    context = mocker.patch("single_kernel_mongo.managers.oauth.ssl.create_default_context")
    connect = mocker.patch("single_kernel_mongo.managers.oauth.socket.create_connection")

    assert verify_https_endpoint(workload, issuer, "/etc/oauth/certs/oauth-ca.crt") is None

    workload.read.assert_called_once_with(Path("/etc/oauth/certs/oauth-ca.crt"))
    context.assert_called_once_with(cadata=certificates.root.strip())
    connect.assert_called_once_with((hostname, port), timeout=5)
    connection = connect.return_value.__enter__.return_value
    connection.settimeout.assert_called_once_with(5)
    context.return_value.wrap_socket.assert_called_once_with(connection, server_hostname=hostname)


def test_tls_verification_falls_back_to_workload_system_roots(mocker, certificates):
    workload = mocker.Mock()
    workload.read.return_value = certificates.root.splitlines()
    mocker.patch("single_kernel_mongo.managers.oauth.ssl.create_default_context")
    mocker.patch("single_kernel_mongo.managers.oauth.socket.create_connection")

    assert verify_https_endpoint(workload, "https://issuer.example", None) is None

    workload.read.assert_called_once_with(Path("/etc/ssl/certs/ca-certificates.crt"))


@pytest.mark.parametrize(
    "tls_error", [ssl.SSLCertVerificationError("untrusted issuer"), ssl.SSLError("invalid CA")]
)
def test_tls_verification_failures_are_blocked(mocker, certificates, tls_error):
    workload = mocker.Mock()
    workload.read.return_value = certificates.root.splitlines()
    mocker.patch(
        "single_kernel_mongo.managers.oauth.ssl.create_default_context",
        side_effect=tls_error,
    )

    assert (
        verify_https_endpoint(workload, "https://issuer.example", None)
        == OAuthStatuses.ISSUER_UNTRUSTED.value
    )


def test_tls_connection_failure_waits_instead_of_claiming_untrusted_ca(mocker, certificates):
    workload = mocker.Mock()
    workload.read.return_value = certificates.root.splitlines()
    mocker.patch(
        "single_kernel_mongo.managers.oauth.socket.create_connection",
        side_effect=OSError("connection refused"),
    )

    assert (
        verify_https_endpoint(workload, "https://issuer.example", None)
        == OAuthStatuses.ISSUER_UNREACHABLE.value
    )


@pytest.mark.parametrize(
    "issuer", ["http://issuer.example", "https://user:password@issuer.example"]
)
def test_invalid_or_non_https_issuer_is_blocked(mocker, issuer):
    workload = mocker.Mock()

    assert verify_https_endpoint(workload, issuer, None) == OAuthStatuses.ISSUER_UNTRUSTED.value

    workload.read.assert_not_called()


def test_provider_can_send_v0_certificate_chain(
    mongodb_ctx, mongo_auth_state, certificates, workload_files
):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_units_data={
            0: {
                "ca": json.dumps(certificates.root),
                "certificate": json.dumps(certificates.leaf),
                "chain": json.dumps([certificates.root]),
            }
        },
    )
    state = mongo_auth_state(relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation, remote_unit=0), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)

        result = scenario.run()

    assert (
        get_relation(result, PeerRelationNames.PEERS.value).local_app_data["oauth-ca"]
        == certificates.root
    )
    assert io.files[operator.workload.paths.oauth_ca_file] == certificates.root


def test_provider_can_withdraw_ca_without_removing_relation(
    mongodb_ctx, mongo_auth_state, certificates, workload_files, mocker
):
    relation = Relation(
        endpoint="oauth-certificate-transfer",
        remote_app_name="idp-ca",
        remote_units_data={0: {"version": "0"}},
    )
    state = mongo_auth_state(
        peer_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": certificates.root,
        },
        relations={relation},
    )
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation, remote_unit=0), state) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        io.files[operator.workload.paths.oauth_ca_file] = certificates.root
        io.files[operator.config_manager.file] = safe_dump(operator.config_manager.build_config())
        request = mocker.patch.object(operator, "async_restart_charm_services")

        result = scenario.run()

    assert "oauth-ca" not in get_relation(result, PeerRelationNames.PEERS.value).local_app_data
    request.assert_called_once_with(force=False)


def test_invalid_ca_status_survives_heartbeat_reconciliation(
    mongodb_ctx, mongo_auth_state, certificates, workload_files
):
    state = mongo_auth_state(
        peer_data={"oauth-ca": "invalid PEM"},
        relations={
            Relation(
                endpoint="oauth-certificate-transfer",
                remote_app_name="idp-ca",
                remote_app_data={"version": "1", "certificates": json.dumps(["invalid PEM"])},
            )
        },
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state) as scenario:
        operator = scenario.charm.operator
        workload_files(operator.workload)
        manager = operator.oauth_certificate_manager
        operator.state.statuses.add(
            OAuthStatuses.INVALID_CA.value, scope="unit", component=manager.name
        )

        scenario.charm.status_handler._recompute_statuses_for_scope("unit", manager)

        assert manager.get_statuses("unit", recompute=True) == [OAuthStatuses.INVALID_CA.value]


def test_mongos_rolling_callback_applies_ca_setting(
    mongos_ctx, mongos_auth_state, certificates, workload_files, mocker
):
    relation = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": certificates.root,
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.3:27017",
        },
    )
    with mongos_ctx(
        mongos_ctx.on.collect_unit_status(), mongos_auth_state(relations={relation})
    ) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        io.files[operator.config_manager.file] = "{}"
        mocker.patch.object(operator.cluster_manager, "assert_pass_hook_checks")
        mocker.patch.object(operator.cluster_manager, "_set_ldap_user_to_dn")
        mocker.patch.object(operator.cluster_manager, "_set_cluster_id")
        mocker.patch.object(operator, "update_keyfile", return_value=False)
        mocker.patch.object(operator, "update_config_server_db", return_value=False)
        restart = mocker.patch.object(operator.workload, "restart")

        operator.cluster_manager.update_mongos_and_restart()

        providers = json.loads(
            safe_load(io.files[operator.config_manager.file])["setParameter"][
                "oidcIdentityProviders"
            ]
        )
        assert providers[0]["serverCAFile"] == str(operator.workload.paths.oauth_ca_file)
        assert io.files[operator.workload.paths.oauth_ca_file] == certificates.root
        restart.assert_called_once()


def test_mongos_rolling_callback_removes_ca_setting_and_file(
    mongos_ctx, mongos_auth_state, certificates, workload_files, mocker
):
    relation = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={
            "oauth-issuer": "https://issuer.example",
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.3:27017",
        },
    )
    with mongos_ctx(
        mongos_ctx.on.collect_unit_status(), mongos_auth_state(relations={relation})
    ) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        path = operator.workload.paths.oauth_ca_file
        io.files[path] = certificates.root
        current = operator.config_manager.build_config()
        providers = json.loads(current["setParameter"]["oidcIdentityProviders"])
        providers[0]["serverCAFile"] = str(path)
        current["setParameter"]["oidcIdentityProviders"] = json.dumps(providers)
        io.files[operator.config_manager.file] = safe_dump(current)
        mocker.patch.object(operator.cluster_manager, "assert_pass_hook_checks")
        mocker.patch.object(operator.cluster_manager, "_set_ldap_user_to_dn")
        mocker.patch.object(operator.cluster_manager, "_set_cluster_id")
        mocker.patch.object(operator, "update_keyfile", return_value=False)
        mocker.patch.object(operator, "update_config_server_db", return_value=False)
        restart = mocker.patch.object(operator.workload, "restart")

        operator.cluster_manager.update_mongos_and_restart()

        providers = json.loads(
            safe_load(io.files[operator.config_manager.file])["setParameter"][
                "oidcIdentityProviders"
            ]
        )
        assert "serverCAFile" not in providers[0]
        assert path not in io.files
        restart.assert_called_once()


def test_valid_ca_update_clears_invalid_status(
    mongodb_ctx, mongo_auth_state, certificates, workload_files
):
    relation = certificate_relation(certificates)
    state = mongo_auth_state(relations={relation})
    with mongodb_ctx(mongodb_ctx.on.relation_changed(relation, remote_unit=0), state) as scenario:
        operator = scenario.charm.operator
        workload_files(operator.workload)
        operator.state.statuses.add(
            OAuthStatuses.INVALID_CA.value,
            scope="unit",
            component=operator.oauth_certificate_manager.name,
        )

        scenario.run()

    assert OAuthStatuses.INVALID_CA.value not in operator.oauth_certificate_manager.get_statuses(
        "unit"
    )


def test_invalid_cluster_ca_is_blocked_without_restarting_router(
    mongos_ctx, mongos_auth_state, workload_files, mocker
):
    relation = Relation(
        endpoint="cluster",
        remote_app_name="config-server",
        remote_app_data={
            "oauth-issuer": "https://issuer.example",
            "oauth-ca": "invalid PEM",
            "key-file": "keyfile",
            "config-server-db": "rs/10.0.0.3:27017",
        },
    )
    with mongos_ctx(
        mongos_ctx.on.relation_changed(relation), mongos_auth_state(relations={relation})
    ) as scenario:
        operator = scenario.charm.operator
        io = workload_files(operator.workload)
        mocker.patch.object(operator.cluster_manager, "assert_pass_hook_checks")
        mocker.patch.object(operator.cluster_manager, "share_credentials_to_clients")
        request = operator.rollingops_manager.request_async_lock
        request.reset_mock()

        result = scenario.run()

    assert result.deferred
    assert operator.oauth_certificate_manager.get_statuses("unit") == [
        OAuthStatuses.INVALID_CA.value
    ]
    io.write.assert_not_called()
    request.assert_not_called()
