# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import pytest
from ops.testing import ActionFailed, Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    generate_private_key,
)
from single_kernel_mongo.state.tls_state import SECRET_CSR_LABEL, SECRET_KEY_LABEL

from .mongodb_test_charm.src.charm import MongoTestCharm


def test_tls_relation_joined(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.tls_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    external_key = manager.get_tls_secret(False, SECRET_KEY_LABEL)
    external_csr = manager.get_tls_secret(False, SECRET_CSR_LABEL)
    internal_key = manager.get_tls_secret(True, SECRET_KEY_LABEL)
    internal_csr = manager.get_tls_secret(True, SECRET_CSR_LABEL)

    assert external_csr is not None
    assert external_key is not None
    assert internal_csr is not None
    assert internal_key is not None

    internal_subject = manager.state.unit_peer_data.get("int_certs_subject")
    external_subject = manager.state.unit_peer_data.get("ext_certs_subject")

    assert internal_subject == "test-mongodb"
    assert external_subject == "test-mongodb"


def test_tls_relation_joined_fails_condition_role(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)

    mock_defer = mocker.patch("ops.framework.EventBase.defer")

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    mock_defer.assert_called()


def test_tls_relation_joined_fails_upgrade_in_progress(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)

    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    mock_defer.assert_called()


def test_set_private_key(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.tls_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    internal_key = generate_private_key().decode()
    external_key = generate_private_key().decode()

    harness.run_action(
        "set-tls-private-key", params={"internal-key": internal_key, "external-key": external_key}
    )

    external_key_from_secret = manager.get_tls_secret(False, SECRET_KEY_LABEL)
    internal_key_from_secret = manager.get_tls_secret(True, SECRET_KEY_LABEL)

    assert internal_key.rstrip() == internal_key_from_secret
    assert external_key.rstrip() == external_key_from_secret


def test_tls_set_private_key_fail_conditions(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    internal_key = generate_private_key().decode()
    external_key = generate_private_key().decode()

    with pytest.raises(ActionFailed):
        harness.run_action(
            "set-tls-private-key",
            params={"internal-key": internal_key, "external-key": external_key},
        )


def test_tls_set_private_key_fails_upgrade_in_progress(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    internal_key = generate_private_key().decode()
    external_key = generate_private_key().decode()

    with pytest.raises(ActionFailed):
        harness.run_action(
            "set-tls-private-key",
            params={"internal-key": internal_key, "external-key": external_key},
        )


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

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("ext-csr-secret", "csr-secret", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "unit-cert-old", Scope.UNIT)
    manager.state.secrets.set("int-cert-secret", "app-cert", Scope.UNIT)

    harness.charm.operator.tls_events.certs_client.on.certificate_available.emit(
        certificate_signing_request="csr-secret",
        chain=["unit-chain"],
        certificate="unit-cert",
        ca="unit-ca",
    )

    chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-chain-secret")
    unit_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-cert-secret")
    ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "ext-ca-secret")

    assert chain_secret == "unit-chain"
    assert unit_secret == "unit-cert"
    assert ca_secret == "unit-ca"

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

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("int-csr-secret", "int-csr", Scope.UNIT)
    manager.state.secrets.set("int-cert-secret", "int-cert-old", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "ext-cert", Scope.UNIT)

    harness.charm.operator.tls_events.certs_client.on.certificate_available.emit(
        certificate_signing_request="int-csr",
        chain=["int-chain"],
        certificate="int-cert",
        ca="int-ca",
    )

    chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret")
    unit_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret")
    ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret")

    assert chain_secret == "int-chain"
    assert unit_secret == "int-cert"
    assert ca_secret == "int-ca"

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

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("int-chain-secret", "app-chain-old", Scope.UNIT)
    manager.state.secrets.set("int-csr-secret", "app-csr-old", Scope.UNIT)
    manager.state.secrets.set("int-cert-secret", "app-cert-old", Scope.UNIT)
    manager.state.secrets.set("int-ca-secret", "app-ca-old", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "unit-cert", Scope.UNIT)

    harness.charm.operator.tls_events.certs_client.on.certificate_available.emit(
        certificate_signing_request="app-csr",
        chain=["app-chain"],
        certificate="app-cert",
        ca="app-ca",
    )

    chain_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-chain-secret")
    unit_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-cert-secret")
    ca_secret = manager.state.secrets.get_for_key(Scope.UNIT, "int-ca-secret")

    assert chain_secret == "app-chain-old"
    assert unit_secret == "app-cert-old"
    assert ca_secret == "app-ca-old"

    assert harness.charm.operator.state.tls.internal_enabled

    mock_restart.assert_not_called()


def test_certificate_available_role_invalid_defer(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    harness.charm.operator.tls_events.certs_client.on.certificate_available.emit(
        certificate_signing_request="app-csr",
        chain=["app-chain"],
        certificate="app-cert",
        ca="app-ca",
    )

    mock_defer.assert_called()


def test_certificate_available_upgrade_in_progress_defer(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    harness.charm.operator.tls_events.certs_client.on.certificate_available.emit(
        certificate_signing_request="app-csr",
        chain=["app-chain"],
        certificate="app-cert",
        ca="app-ca",
    )

    mock_defer.assert_called()


def test_tls_relation_broken(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
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
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    harness.remove_relation(rel_id)

    for scope in Scope:
        ca_secret = manager.state.secrets.get_for_key(scope, "ca-secret")
        cert_secret = manager.state.secrets.get_for_key(scope, "cert-secret")
        chain_secret = manager.state.secrets.get_for_key(scope, "chain-secret")

        assert ca_secret is None
        assert cert_secret is None
        assert chain_secret is None

    mock_restart.assert_called()


def test_tls_relation_broken_fails_db_not_initialised(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    mock_defer = mocker.patch("ops.framework.EventBase.defer")

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    harness.charm.operator.state.db_initialised = False
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    harness.remove_relation(rel_id)
    mock_defer.assert_called()


def test_tls_relation_broken_log_upgrade_in_progress(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, caplog
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
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    caplog.clear()
    harness.remove_relation(rel_id)

    assert any(
        record.levelname == "WARNING" and "not supported during" in record.message
        for record in caplog.records
    )


def test_external_certificate_expiring(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    """Verifies that when an external certificate expires a csr is made."""
    manager = harness.charm.operator.tls_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("int-cert-secret", "int-cert", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "ext-cert", Scope.UNIT)

    # simulate current certificate expiring
    old_csr = manager.state.secrets.get_for_key(Scope.UNIT, "ext-csr-secret")

    harness.charm.operator.tls_events.certs_client.on.certificate_expiring.emit(
        certificate="ext-cert", expiry=None
    )

    # verify a new csr was generated

    new_csr = manager.state.secrets.get_for_key(Scope.UNIT, "ext-csr-secret")
    assert old_csr != new_csr


def test_internal_certificate_expiring(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    """Verifies that when an external certificate expires a csr is made."""
    manager = harness.charm.operator.tls_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("int-cert-secret", "int-cert", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "ext-cert", Scope.UNIT)

    # simulate current certificate expiring
    old_csr = manager.state.secrets.get_for_key(Scope.UNIT, "int-csr-secret")

    harness.charm.operator.tls_events.certs_client.on.certificate_expiring.emit(
        certificate="int-cert", expiry=None
    )

    # verify a new csr was generated

    new_csr = manager.state.secrets.get_for_key(Scope.UNIT, "int-csr-secret")
    assert old_csr != new_csr


def test_certificate_expiring_fails_condition(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    """Verifies that when an external certificate expires a csr is made."""
    mock_defer = mocker.patch("ops.framework.EventBase.defer")
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS.value
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    harness.charm.operator.tls_events.certs_client.on.certificate_expiring.emit(
        certificate="int-cert", expiry=None
    )
    mock_defer.assert_called()


def test_unknown_certificate_expiring(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    """Verifies that when an external certificate expires a csr is made."""
    manager = harness.charm.operator.tls_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    harness.charm.operator.state.db_initialised = True
    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    harness.add_relation_unit(rel_id, "self-signed-certificates/0")

    manager.state.secrets.set("int-cert-secret", "int-cert", Scope.UNIT)
    manager.state.secrets.set("ext-cert-secret", "ext-cert", Scope.UNIT)

    # simulate current certificate expiring
    old_int_csr = manager.state.secrets.get_for_key(Scope.UNIT, "int-csr-secret")
    old_ext_csr = manager.state.secrets.get_for_key(Scope.UNIT, "ext-csr-secret")

    harness.charm.operator.tls_events.certs_client.on.certificate_expiring.emit(
        certificate="unknown-cert", expiry=None
    )

    # verify a new csr was generated

    post_event_int_csr = manager.state.secrets.get_for_key(Scope.UNIT, "int-csr-secret")
    post_event_ext_csr = manager.state.secrets.get_for_key(Scope.UNIT, "ext-csr-secret")
    assert old_int_csr == post_event_int_csr
    assert old_ext_csr == post_event_ext_csr
