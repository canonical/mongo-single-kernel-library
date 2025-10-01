# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from unittest.mock import MagicMock

import pytest
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
)
from single_kernel_mongo.state.tls_state import SECRET_CERT_LABEL, SECRET_KEY_LABEL
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm


# test for other roles?
def test_client_tls_relation_joined(harness: Harness[MongoTestCharm], mongodb_name: str):
    manager = harness.charm.operator.tls_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    external_key = manager.state.tls.get_secret(False, SECRET_KEY_LABEL)
    # external_csr = manager.state.tls.get_secret(False, SECRET_CSR_LABEL)
    external_cert = manager.state.tls.get_secret(False, SECRET_CERT_LABEL)

    # assert external_csr is not None
    assert external_key is None
    assert external_cert is None

    external_subject = manager.state.unit_peer_data.get("ext_certs_subject")
    assert external_subject == mongodb_name

    external_waiting = manager.state.unit_peer_data.get("ext-wait-cert-updated")
    assert external_waiting == "true"


# test for other roles?
def test_peer_tls_relation_joined(harness: Harness[MongoTestCharm], mongodb_name: str):
    manager = harness.charm.operator.tls_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    rel_id = harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    internal_key = manager.state.tls.get_secret(True, SECRET_KEY_LABEL)
    # internal_csr = manager.state.tls.get_secret(True, SECRET_CSR_LABEL)
    internal_cert = manager.state.tls.get_secret(True, SECRET_CERT_LABEL)

    # assert internal_csr is not None
    assert internal_key is None
    assert internal_cert is None

    internal_subject = manager.state.unit_peer_data.get("int_certs_subject")
    assert internal_subject == mongodb_name

    internal_waiting = manager.state.unit_peer_data.get("int-wait-cert-updated")
    assert internal_waiting == "true"


def test_tls_relation_joined_fails_condition_role(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)

    mock_defer = mocker.patch("ops.framework.EventBase.defer")

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS
    rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    mock_defer.assert_called()


# test for multiple roles
def test_tls_relation_joined_fails_upgrade_in_progress(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)

    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    mock_defer.assert_called()


def get_certificate_mock(ca: str, cert_text: str, chain_text: str) -> MagicMock:
    new_server_cert = MagicMock()
    new_server_cert.ca.raw = ca
    cert = MagicMock()
    cert.raw = cert_text
    new_server_cert.certificate = cert
    chain = MagicMock()
    chain.raw = chain_text
    new_server_cert.chain = [chain]
    return new_server_cert


def test_external_certificate_available(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
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
        ca="new_test_ca_server", cert_text="new_certificate_external_value", chain_text="new_chain"
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        return_value=([new_cert], new_private_key),
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
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

    assert harness.charm.operator.state.tls.external_enabled


def test_internal_certificate_available(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
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
        ca="new_test_ca_server", cert_text="new_certificate_external_value", chain_text="new_chain"
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([], None), ([new_cert], new_private_key)],
    )

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
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
    assert harness.charm.operator.state.tls.internal_enabled

    mock_restart.assert_called()


def test_unknown_certificate_available(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    manager = harness.charm.operator.tls_manager

    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        ca="new_test_ca_server", cert_text="new_certificate_external_value", chain_text="new_chain"
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        return_value=[
            ([new_cert], new_private_key),
            ([new_cert], new_private_key),
        ],
    )

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
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

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate
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

    assert harness.charm.operator.state.tls.external_enabled
    assert harness.charm.operator.state.tls.internal_enabled

    mock_restart.assert_not_called()


@pytest.mark.parametrize(
    "relation_type",
    [
        ExternalRequirerRelations.CLIENT_TLS.value,
        ExternalRequirerRelations.PEER_TLS.value,
    ],
)
def test_certificate_available_role_invalid_defer(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, relation_type
):
    harness.set_leader(True)
    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        ca="new_test_ca_server", cert_text="new_certificate_external_value", chain_text="new_chain"
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([], None), ([new_cert], new_private_key)],
    )
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    mock_defer.assert_called()


@pytest.mark.parametrize(
    "relation_type",
    [
        ExternalRequirerRelations.CLIENT_TLS.value,
        ExternalRequirerRelations.PEER_TLS.value,
    ],
)
def test_certificate_available_upgrade_in_progress_defer(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, relation_type
):
    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    new_private_key = MagicMock()
    new_private_key.raw = "my_new_private_key"
    new_cert = get_certificate_mock(
        ca="new_test_ca_server", cert_text="new_certificate_external_value", chain_text="new_chain"
    )
    mocker.patch(
        "single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificates",
        side_effect=[([], None), ([new_cert], new_private_key)],
    )
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    event = MagicMock(spec=CertificateAvailableEvent)
    event.certificate = new_cert.certificate

    harness.charm.operator.tls_events._on_certificate_available(event)

    mock_defer.assert_called()


def test_client_tls_relation_broken(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
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
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
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


def test_peer_tls_relation_broken(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
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
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.db_initialised = True
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


@pytest.mark.parametrize(
    "relation_type",
    [
        ExternalRequirerRelations.CLIENT_TLS.value,
        ExternalRequirerRelations.PEER_TLS.value,
    ],
)
def test_tls_relation_broken_fails_db_not_initialised(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, relation_type
):
    mock_defer = mocker.patch("ops.framework.EventBase.defer")

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.db_initialised = False
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    harness.remove_relation(rel_id)
    mock_defer.assert_called()


@pytest.mark.parametrize(
    "relation_type",
    [
        ExternalRequirerRelations.CLIENT_TLS.value,
        ExternalRequirerRelations.PEER_TLS.value,
    ],
)
def test_tls_relation_broken_log_upgrade_in_progress(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, caplog, relation_type
):
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=None,
    )

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(relation_type, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    caplog.clear()
    harness.remove_relation(rel_id)

    assert any(
        record.levelname == "WARNING" and "not supported during" in record.message
        for record in caplog.records
    )
