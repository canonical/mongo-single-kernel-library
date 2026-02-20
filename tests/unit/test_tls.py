# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
)
from single_kernel_mongo.state.tls_state import SECRET_KEY_LABEL
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm


def get_certificate_mock(cert: str, chain: str, ca: str, csr: str) -> MagicMock:
    provider_certificate_mock = MagicMock()

    cert_mock = MagicMock()
    cert_mock.raw = cert
    csr_mock = MagicMock()
    csr_mock.raw = csr
    provider_certificate_mock.certificate = cert_mock
    provider_certificate_mock.certificate_signing_request = csr_mock

    chain_mock = MagicMock()
    chain_mock.raw = chain
    provider_certificate_mock.chain = [chain_mock]

    provider_certificate_mock.ca.raw = ca

    return provider_certificate_mock


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
    ],
)
def test_client_certificate_available(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, role
):
    manager = harness.charm.operator.tls_manager
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )

    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        return_value=([new_cert], new_private_key),
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate",
        return_value=(new_cert, new_private_key),
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role
    rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-chain-secret")
    cert_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-cert-secret")
    ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-ca-secret")
    private_key = manager.state.secrets.get_for_key(Scope.UNIT, "ext-key-secret")

    assert chain_secret == "new_chain"
    assert cert_secret == "new_certificate_external_value"
    assert ca_secret == "new_test_ca_server"
    assert private_key == "my_new_private_key"

    mock_restart.assert_called()

    assert harness.charm.operator.state.tls.client_enabled


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
    ],
)
def test_internal_certificate_available(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, role
):
    manager = harness.charm.operator.tls_manager
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([], None), ([new_cert], new_private_key)],
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate",
        side_effect=[
            (new_cert, new_private_key),
            (None, None),
        ],
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role
    rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret")
    cert_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret")
    ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret")
    private_key = manager.state.secrets.get_for_key(Scope.UNIT, "int-key-secret")

    assert chain_secret == "new_chain"
    assert cert_secret == "new_certificate_external_value"
    assert ca_secret == "new_test_ca_server"
    assert private_key == "my_new_private_key"
    assert harness.charm.operator.state.tls.peer_enabled

    mock_restart.assert_called()


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
    ],
)
def test_unknown_certificate_available(harness: Harness[MongoTestCharm], mocker, role):
    manager = harness.charm.operator.tls_manager
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([new_cert], new_private_key), ([new_cert], new_private_key)],
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role
    client_rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(client_rel_id, "self-signed-certificates/0")
    peer_rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(peer_rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("ext-chain-secret", "app-chain-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "app-cert-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-ca-secret", "app-ca-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-key-secret", "unit-key-1", Scope.UNIT)
    manager.state.secrets.set("int-chain-secret", "app-chain-old-2", Scope.UNIT)
    manager.state.secrets.set("int-cert-secret", "app-cert-old-2", Scope.UNIT)
    manager.state.secrets.set("int-ca-secret", "app-ca-old-2", Scope.UNIT)
    manager.state.secrets.set("int-key-secret", "unit-key-2", Scope.UNIT)

    # Mock an unknown certificate
    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = MagicMock()
    event.certificate.raw = "1234"

    harness.charm.operator.tls_events._on_certificate_available(event)

    ext_chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-chain-secret")
    ext_unit_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-cert-secret")
    ext_ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-ca-secret")
    ext_key_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-key-secret")
    int_chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret")
    int_unit_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret")
    int_ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret")
    int_key_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-key-secret")

    assert ext_chain_secret == "app-chain-old-1"
    assert ext_unit_secret == "app-cert-old-1"
    assert ext_ca_secret == "app-ca-old-1"
    assert ext_key_secret == "unit-key-1"

    assert int_chain_secret == "app-chain-old-2"
    assert int_unit_secret == "app-cert-old-2"
    assert int_ca_secret == "app-ca-old-2"
    assert int_key_secret == "unit-key-2"

    assert harness.charm.operator.state.tls.client_enabled
    assert harness.charm.operator.state.tls.peer_enabled

    mock_restart.assert_not_called()


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
    ],
)
def test_private_key_is_none_certificate_available(harness: Harness[MongoTestCharm], mocker, role):
    manager = harness.charm.operator.tls_manager
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([new_cert], None), ([new_cert], None)],
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role
    client_rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(client_rel_id, "self-signed-certificates/0")
    peer_rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(peer_rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-chain-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-cert-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-ca-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-key-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-key-secret") is None

    assert not harness.charm.operator.state.tls.client_enabled
    assert not harness.charm.operator.state.tls.peer_enabled

    mock_restart.assert_not_called()


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
    ],
)
def test_private_key_does_not_match_config_client_certificate_available(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, mongodb_name, role
):
    manager = harness.charm.operator.tls_manager
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )

    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        return_value=([new_cert], new_private_key),
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate",
        return_value=(new_cert, new_private_key),
    )

    private_key_content = Path("tests/unit/data/key.pem").read_text()
    secret_id = harness.add_model_secret(mongodb_name, {"private-key": private_key_content})
    harness.update_config({"tls-client-private-key": secret_id})

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role
    rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-chain-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-cert-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-ca-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "ext-key-secret") is not None

    assert not harness.charm.operator.state.tls.client_enabled
    mock_restart.assert_not_called()


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
    ],
)
def test_private_key_does_not_match_config_peer_certificate_available(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, mongodb_name, role
):
    manager = harness.charm.operator.tls_manager
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([], None), ([new_cert], new_private_key)],
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate",
        side_effect=[
            (new_cert, new_private_key),
            (None, None),
        ],
    )

    private_key_content = Path("tests/unit/data/key.pem").read_text()
    secret_id = harness.add_model_secret(mongodb_name, {"private-key": private_key_content})
    harness.update_config({"tls-peer-private-key": secret_id})

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role
    rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret") is None
    assert manager.state.secrets.get_for_key(Scope.UNIT, "int-key-secret") is not None

    assert not harness.charm.operator.state.tls.peer_enabled
    mock_restart.assert_not_called()


@pytest.mark.parametrize(
    "relation_type",
    [
        ExternalRequirerRelations.CLIENT_TLS.value,
        ExternalRequirerRelations.PEER_TLS.value,
    ],
)
def test_certificate_available_mongos_without_config_server_certificate_is_ignored(
    harness: Harness[MongoTestCharm], mocker, relation_type
):
    harness.set_leader(True)
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    get_assigned_certificates_mock = mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([new_cert], new_private_key), ([new_cert], new_private_key)],
    )
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    get_assigned_certificates_mock.assert_not_called()
    assert not harness.charm.operator.state.tls.client_enabled
    assert not harness.charm.operator.state.tls.peer_enabled


@pytest.mark.parametrize(
    ("relation_type", "role"),
    [
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.REPLICATION),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.SHARD),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.CONFIG_SERVER),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.REPLICATION),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.SHARD),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.CONFIG_SERVER),
    ],
)
def test_certificate_available_upgrade_in_progress_defer(
    harness: Harness[MongoTestCharm], mocker, relation_type, role
):
    harness.charm.operator.refresh.in_progress = True
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        cert="new_certificate_external_value",
        chain="new_chain",
        ca="new_test_ca_server",
        csr="new_csr",
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([new_cert], new_private_key), ([new_cert], new_private_key)],
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    event.defer.assert_called()
    assert not harness.charm.operator.state.tls.client_enabled
    assert not harness.charm.operator.state.tls.peer_enabled


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
        MongoDBRoles.SHARD,
    ],
)
def test_client_tls_relation_broken(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, role
):
    manager = harness.charm.operator.tls_manager

    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")
    harness.add_relation(ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates")

    manager.state.secrets.set("ext-chain-secret", "app-chain-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "app-cert-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-ca-secret", "app-ca-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-key-secret", "unit-key-1", Scope.UNIT)
    manager.state.secrets.set("int-chain-secret", "app-chain-old-2", Scope.UNIT)
    manager.state.secrets.set("int-cert-secret", "app-cert-old-2", Scope.UNIT)
    manager.state.secrets.set("int-ca-secret", "app-ca-old-2", Scope.UNIT)
    manager.state.secrets.set("int-key-secret", "unit-key-2", Scope.UNIT)

    harness.remove_relation(rel_id)

    for scope in Scope:
        ca_secret = manager.state.secrets.get_for_key(scope, "ext-ca-secret")
        cert_secret = manager.state.secrets.get_for_key(scope, "ext-cert-secret")
        chain_secret = manager.state.secrets.get_for_key(scope, "ext-chain-secret")
        key_secret = manager.state.secrets.get_for_key(scope, "ext-key-secret")

        assert ca_secret is None
        assert cert_secret is None
        assert chain_secret is None
        assert key_secret is None

    ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret")
    cert_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret")
    chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret")
    key_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-key-secret")

    assert ca_secret is not None
    assert cert_secret is not None
    assert chain_secret is not None
    assert key_secret is not None

    mock_restart.assert_called()
    assert not harness.charm.operator.state.tls.client_enabled
    assert harness.charm.operator.state.tls.peer_enabled


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION,
        MongoDBRoles.SHARD,
        MongoDBRoles.CONFIG_SERVER,
        MongoDBRoles.SHARD,
    ],
)
def test_peer_tls_relation_broken(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, role
):
    manager = harness.charm.operator.tls_manager

    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state.db_initialised = True
    harness.add_relation(ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates")
    rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("ext-chain-secret", "app-chain-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "app-cert-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-ca-secret", "app-ca-old-1", Scope.UNIT)
    manager.state.secrets.set("ext-key-secret", "unit-key-1", Scope.UNIT)
    manager.state.secrets.set("int-chain-secret", "app-chain-old-2", Scope.UNIT)
    manager.state.secrets.set("int-cert-secret", "app-cert-old-2", Scope.UNIT)
    manager.state.secrets.set("int-ca-secret", "app-ca-old-2", Scope.UNIT)
    manager.state.secrets.set("int-key-secret", "unit-key-2", Scope.UNIT)

    harness.remove_relation(rel_id)

    for scope in Scope:
        ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret")
        cert_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret")
        chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret")
        key_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-key-secret")

        assert ca_secret is None
        assert cert_secret is None
        assert chain_secret is None
        assert key_secret is None

    ca_secret = manager.state.secrets.get_for_key(scope, "ext-ca-secret")
    cert_secret = manager.state.secrets.get_for_key(scope, "ext-cert-secret")
    chain_secret = manager.state.secrets.get_for_key(scope, "ext-chain-secret")
    key_secret = manager.state.secrets.get_for_key(scope, "ext-key-secret")

    assert ca_secret is not None
    assert cert_secret is not None
    assert chain_secret is not None
    assert key_secret is not None

    mock_restart.assert_called()
    assert harness.charm.operator.state.tls.client_enabled
    assert not harness.charm.operator.state.tls.peer_enabled


@pytest.mark.parametrize(
    ("relation_type", "role"),
    [
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.REPLICATION),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.SHARD),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.CONFIG_SERVER),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.REPLICATION),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.SHARD),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.CONFIG_SERVER),
    ],
)
def test_tls_relation_broken_defers_due_to_db_not_initialised(
    harness: Harness[MongoTestCharm], mocker, relation_type, role
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state.db_initialised = False
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    harness.remove_relation(rel_id)


@pytest.mark.parametrize(
    ("relation_type", "role"),
    [
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.REPLICATION),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.SHARD),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.CONFIG_SERVER),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.MONGOS),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.REPLICATION),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.SHARD),
        (ExternalRequirerRelations.PEER_TLS.value, MongoDBRoles.CONFIG_SERVER),
        (ExternalRequirerRelations.CLIENT_TLS.value, MongoDBRoles.MONGOS),
    ],
)
def test_tls_relation_broken_log_upgrade_in_progress(
    harness: Harness[MongoTestCharm], mocker, caplog, relation_type, role
):
    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    harness.charm.operator.refresh.in_progress = True
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    caplog.clear()
    harness.remove_relation(rel_id)

    mock_defer.assert_called()


def test_tls_config_changed(
    harness: Harness[MongoTestCharm], mocker, mongodb_name, mock_fs_interactions
):
    manager = harness.charm.operator.tls_manager
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.add_relation(ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates")
    rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")
    private_key_content = Path("tests/unit/data/key.pem").read_text().strip()
    secret_id = harness.add_model_secret(mongodb_name, {"private-key": private_key_content})
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    spied = mocker.spy(harness.charm.operator.tls_events, "refresh_certificates")

    harness.update_config({"tls-peer-private-key": secret_id})

    assert (
        manager.state.tls.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )

    spied.assert_called()


def test_tls_config_changed_invalid_key(
    harness: Harness[MongoTestCharm], mocker, mongodb_name, mock_fs_interactions
):
    manager = harness.charm.operator.tls_manager
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.add_relation(ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates")
    rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")
    private_key_content = Path("tests/unit/data/key.pem").read_text().strip()
    secret_id = harness.add_model_secret(mongodb_name, {"private-key": private_key_content})
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.update_config({"tls-peer-private-key": secret_id})

    assert (
        manager.state.tls.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )

    secret_id_bis = harness.add_model_secret(
        mongodb_name, {"private-key": base64.b64encode(b"invalid_key").decode()}
    )
    harness.update_config({"tls-peer-private-key": secret_id_bis})

    harness.evaluate_status()

    assert harness.charm.model.unit.status.message == "Invalid peer private key"

    assert (
        manager.state.tls.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )


def test_tls_config_changed_invalid_keys(
    harness: Harness[MongoTestCharm], mocker, mongodb_name, mock_fs_interactions
):
    manager = harness.charm.operator.tls_manager
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates")
    rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )
    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    private_key_content = Path("tests/unit/data/key.pem").read_text().strip()
    secret_id = harness.add_model_secret(mongodb_name, {"private-key": private_key_content})
    secret_id_bis = harness.add_model_secret(
        mongodb_name, {"private-key": base64.b64encode(b"invalid_key").decode()}
    )

    # Valid secrets
    harness.update_config({"tls-peer-private-key": secret_id, "tls-client-private-key": secret_id})

    assert (
        manager.state.tls.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )
    assert (
        manager.state.tls.get_secret(internal=False, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )

    harness.update_config({"tls-peer-private-key": secret_id_bis})

    harness.evaluate_status()

    assert harness.charm.model.unit.status.message == "Invalid peer private key"

    assert (
        manager.state.tls.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )
    assert (
        manager.state.tls.get_secret(internal=False, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )

    harness.update_config({"tls-client-private-key": secret_id_bis})

    harness.evaluate_status()

    assert harness.charm.model.unit.status.message.startswith("Invalid peer private key")

    assert (
        manager.state.tls.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )
    assert (
        manager.state.tls.get_secret(internal=False, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )

    harness.update_config({"tls-peer-private-key": secret_id})

    harness.evaluate_status()
    assert harness.charm.model.unit.status.message.startswith("Invalid client private key")
    assert (
        manager.state.tls.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )
    assert (
        manager.state.tls.get_secret(internal=False, label_name=SECRET_KEY_LABEL)
        == private_key_content
    )
