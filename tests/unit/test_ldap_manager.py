# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from pathlib import Path

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.model import ActiveStatus, BlockedStatus, Relation, WaitingStatus
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.models import LdapState
from single_kernel_mongo.config.relations import ExternalRequirerRelations, RelationNames
from single_kernel_mongo.config.statuses import CharmStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
)
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.integration.helpers.types import Substrate


def test_valid_ldap_integration(harness: Harness[MongoTestCharm]):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    assert harness.charm.operator.ldap_manager.is_valid_ldap_integration()


def test_invalid_ldap_integration(harness: Harness[MongoTestCharm]):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    assert not harness.charm.operator.ldap_manager.is_valid_ldap_integration()


@pytest.mark.parametrize(
    ("db_initialised", "role", "upgrade_in_progress", "expected_error"),
    (
        (
            False,
            MongoDBRoles.REPLICATION,
            False,
            DeferrableFailedHookChecksError("DB is not initialised"),
        ),
        (
            True,
            MongoDBRoles.SHARD,
            False,
            NonDeferrableFailedHookChecksError("Cannot integrate LDAP with shard."),
        ),
        (
            True,
            MongoDBRoles.REPLICATION,
            True,
            DeferrableFailedHookChecksError(
                "Adding LDAP is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            ),
        ),
    ),
)
def test_ldap_hook_checks_fail(
    harness: Harness[MongoTestCharm],
    mocker,
    db_initialised: bool,
    role: MongoDBRoles,
    upgrade_in_progress: bool,
    expected_error: Exception,
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    harness.charm.operator.state.app_peer_data.db_initialised = db_initialised
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=upgrade_in_progress),
    )
    harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")

    with pytest.raises(expected_error.__class__) as err:
        harness.charm.operator.ldap_manager.assert_pass_hook_checks()

    assert err.value.args == expected_error.args


def test_ldap_ready_success(harness: Harness[MongoTestCharm], mock_fs_interactions):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.db_initialised = True
    relation_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    harness.add_relation_unit(relation_id, "glauth-k8s/0")
    harness.update_relation_data(
        relation_id,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_id": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    relation: Relation = harness.charm.operator.state.ldap_relation

    harness.charm.operator.ldap_manager.store_ldap_credentials_and_uri(relation)

    ldap_state = harness.charm.operator.state.ldap

    assert ldap_state.bind_user is not None
    assert ldap_state.bind_password is not None
    assert ldap_state.ldaps_urls == ["ldaps://ldap.glauth.com"]

    # We haven't integrated the tls certificates for ldap, no parameter generated.
    assert harness.charm.operator.config_manager.ldap_parameters == {}  # type: ignore


def test_ldap_get_status(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.db_initialised = True
    # Case 1: No integration
    assert harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True) == []

    # Case 2, wrong role
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    ldap_relation_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")

    assert as_status(
        harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True)[0]
    ) == BlockedStatus("Cannot integrate LDAP with shard.")

    # Case 3, correct role, but missing ldap_cert_relation
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    assert as_status(
        harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True)[0]
    ) == BlockedStatus("TLS is mandatory for LDAP transport.")

    # Case 4: Both relations good but not valid data.
    ldap_cert_relation_id = harness.add_relation(
        ExternalRequirerRelations.LDAP_CERT.value, "glauth-k8s"
    )

    assert as_status(
        harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True)[0]
    ) == WaitingStatus("Waiting for both LDAP data and Glauth certificates.")

    # Case 5: We received data from LDAP integration but not from cert integration
    harness.update_relation_data(
        ldap_relation_id,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_id": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    relation: Relation = harness.charm.operator.state.ldap_relation

    harness.charm.operator.ldap_manager.store_ldap_credentials_and_uri(relation)

    assert as_status(
        harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True)[0]
    ) == WaitingStatus("Waiting for Glauth certificates.")

    # Case 6: We received data from both integrations
    harness.add_relation_unit(ldap_cert_relation_id, "glauth-k8s/0")

    harness.update_relation_data(
        ldap_cert_relation_id,
        "glauth-k8s",
        {"ca": "deadbeef", "chain": '["feeddead"]', "certificate": "beefdead"},
    )
    mocker.patch(
        "single_kernel_mongo.managers.ldap.LDAPManager.get_ldap_connection_status",
        return_value=LdapState.ACTIVE,
    )
    harness.charm.operator.ldap_manager.store_ldap_certificates(
        "beefdead", "deadbeef", ["feeddead"]
    )

    assert as_status(
        harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True)[0]
    ) == ActiveStatus("")

    ldap_parameters = harness.charm.operator.config_manager.ldap_parameters["security"]["ldap"]  # type: ignore

    assert ldap_parameters["servers"] == "ldap.glauth.com"
    assert ldap_parameters["transportSecurity"] == "tls"
    assert ldap_parameters["bind"]["queryUser"] == "cn=user,ou=group,dc=glauth,dc=com"
    assert ldap_parameters["bind"]["queryPassword"] == "password"
    assert (
        ldap_parameters["authz"]["queryTemplate"]
        == "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
    )

    # Case 7: Begin of sundown, remove data from databag
    harness.charm.operator.state.ldap.clean_databag()
    assert as_status(
        harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True)[0]
    ) == WaitingStatus("Missing LDAP data from Glauth.")


def test_ldap_on_remove_clean_data(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.app_peer_data.db_initialised = True
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services"
    )

    ldap_relation_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    harness.update_relation_data(
        ldap_relation_id,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_id": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    relation: Relation = harness.charm.operator.state.ldap_relation

    harness.charm.operator.ldap_manager.store_ldap_credentials_and_uri(relation)

    mock_restart.assert_not_called()

    harness.charm.operator.ldap_manager.clean_ldap_credentials_and_uri()

    mock_restart.assert_called()

    ldap_state = harness.charm.operator.state.ldap

    assert ldap_state.bind_user is None
    assert ldap_state.bind_password is None
    assert ldap_state.ldaps_urls is None


def test_on_certificate_removed_clean_certs(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, substrate: Substrate
):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.app_peer_data.db_initialised = True
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services"
    )
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exists", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.exists", return_value=True
    )
    if substrate == "lxd":
        mock_remove_ca_cert = mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.delete")
    else:
        mock_remove_ca_cert = mocker.patch(
            "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.delete"
        )
    ldap_cert_relation_id = harness.add_relation(
        ExternalRequirerRelations.LDAP_CERT.value, "glauth-k8s"
    )
    harness.update_relation_data(
        ldap_cert_relation_id,
        "glauth-k8s",
        {"ca": "deadbeef", "chain": '["feeddead"]', "certificate": "beefdead"},
    )
    harness.charm.operator.ldap_manager.store_ldap_certificates(
        "beefdead", "deadbeef", ["feeddead"]
    )

    mock_restart.assert_not_called()

    harness.charm.operator.ldap_manager.remove_ldap_certificates()

    mock_restart.assert_called()
    mock_remove_ca_cert.assert_called()

    ldap_state = harness.charm.operator.state.ldap

    assert ldap_state.ca is None
    assert ldap_state.certificate is None
    assert ldap_state.chain is None


def test_ldap_full_integration_cycle(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.app_peer_data.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services"
    )
    mocker.patch(
        "single_kernel_mongo.managers.ldap.LDAPManager.get_ldap_connection_status",
        return_value=LdapState.ACTIVE,
    )

    ldap_relation_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    harness.update_relation_data(
        ldap_relation_id,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_id": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    harness.evaluate_status()

    assert harness.model.unit.status == BlockedStatus("TLS is mandatory for LDAP transport.")

    ldap_cert_relation_id = harness.add_relation(
        ExternalRequirerRelations.LDAP_CERT.value, "glauth-k8s"
    )
    harness.add_relation_unit(ldap_cert_relation_id, "glauth-k8s/0")

    harness.update_relation_data(
        ldap_cert_relation_id,
        "glauth-k8s/0",
        {"ca": "deadbeef", "chain": '["feeddead"]', "certificate": "beefdead"},
    )

    harness.evaluate_status()
    # All is good, we are green
    assert harness.model.unit.status == ActiveStatus("")

    assert (
        harness.charm.operator.ldap_manager.get_hash()
        == "ea94093f0d37df1ba61800afd667921396f1f6d7e9957832456058df2ad8602f"
    )

    # Check the parameters
    ldap_parameters = harness.charm.operator.config_manager.ldap_parameters["security"]["ldap"]  # type: ignore

    assert ldap_parameters["servers"] == "ldap.glauth.com"  # parsing adds port if non existent
    assert ldap_parameters["transportSecurity"] == "tls"
    assert ldap_parameters["bind"]["queryUser"] == "cn=user,ou=group,dc=glauth,dc=com"
    assert ldap_parameters["bind"]["queryPassword"] == "password"
    assert (
        ldap_parameters["authz"]["queryTemplate"]
        == "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
    )

    valid_mapping = [
        {
            "match": "([^@]+)@([^@\\.]+)\\.glauth\\.com",
            "substitution": "CN={0},CN=Users,DC={1},DC=glauth,DC=com",
        }
    ]

    harness.update_config({"ldap-user-to-dn-mapping": json.dumps(valid_mapping)})

    ldap_parameters = harness.charm.operator.config_manager.ldap_parameters["security"]["ldap"]  # type: ignore

    assert (
        ldap_parameters["authz"]["queryTemplate"]
        == "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))"
    )
    assert (
        ldap_parameters["userToDNMapping"]
        == '[{"match": "([^@]+)@([^@\\\\.]+)\\\\.glauth\\\\.com", "substitution": "CN={0},CN=Users,DC={1},DC=glauth,DC=com"}]'
    )


def test_ldap_unable_to_bind_defers(
    harness: Harness[MongoTestCharm], mongodb_name: str, mocker, mock_fs_interactions
):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.app_peer_data.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services"
    )
    mocker.patch(
        "single_kernel_mongo.managers.ldap.LDAPManager.get_ldap_connection_status",
        return_value=LdapState.UNABLE_TO_BIND,
    )

    ldap_relation_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    secret_id = harness.add_model_secret("glauth-k8s", {"password": "password"})
    harness.grant_secret(secret_id, mongodb_name)
    harness.update_relation_data(
        ldap_relation_id,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_id": "secret-id",
            "bind_password_secret": secret_id,
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    ldap_cert_relation_id = harness.add_relation(
        ExternalRequirerRelations.LDAP_CERT.value, "glauth-k8s"
    )
    harness.add_relation_unit(ldap_cert_relation_id, "glauth-k8s/0")

    defer = mocker.patch("ops.framework.EventBase.defer")
    harness.update_relation_data(
        ldap_cert_relation_id,
        "glauth-k8s/0",
        {"ca": "deadbeef", "chain": '["feeddead"]', "certificate": "beefdead"},
    )

    defer.assert_called()

    mocker.patch(
        "single_kernel_mongo.managers.ldap.LDAPManager.get_ldap_connection_status",
        return_value=LdapState.ACTIVE,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.get_statuses",
        return_value=[CharmStatuses.ACTIVE_IDLE.value],
    )

    harness.charm.on.update_status.emit()
    harness.evaluate_status()

    # All is good, we are green
    assert harness.model.unit.status == ActiveStatus("")


def test_ldaps_not_enabled(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.app_peer_data.db_initialised = True
    mock_restart = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services"
    )

    ldap_relation_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    harness.update_relation_data(
        ldap_relation_id,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_id": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": "[]",
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    harness.evaluate_status()

    assert harness.model.unit.status == BlockedStatus("LDAPS not enabled on LDAP application.")
    mock_restart.assert_not_called()


def test_ldaps_mongos_invalid_hash(
    mongos_harness: Harness[MongosTestCharm], mocker, mock_fs_interactions
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.db_initialised = True
    rel_id_ldap = mongos_harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")
    mongos_harness.update_relation_data(
        rel_id_ldap,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_id": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )
    rel_id_ldap_cert = mongos_harness.add_relation(
        ExternalRequirerRelations.LDAP_CERT.value, "glauth-k8s"
    )
    mongos_harness.add_relation_unit(rel_id_ldap_cert, "glauth-k8s/0")

    mongos_harness.update_relation_data(
        rel_id_ldap_cert,
        "glauth-k8s/0",
        {"ca": "deadbeef", "chain": '["feeddead"]', "certificate": "beefdead"},
    )

    mongos_harness.evaluate_status()

    assert mongos_harness.model.unit.status == BlockedStatus(
        "mongos and config-server not integrated with the same ldap server."
    )

    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.read",
        return_value=data,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read",
        return_value=data,
    )

    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")
    mongos_harness.add_relation_unit(rel_id_cluster, "test-mongodb/0")

    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {
            "key-file": "deadbeef",
            "config-server-db": "test-mongodb/2.2.2.2:27017",
            "ldap-hash": "deabeef",
        },
    )

    assert as_status(
        mongos_harness.charm.operator.ldap_manager.get_statuses(scope=Scope.UNIT, recompute=True)[0]
    ) == BlockedStatus("mongos and config-server not integrated with the same ldap server.")

    mocker.patch(
        "single_kernel_mongo.managers.ldap.LDAPManager.get_ldap_connection_status",
        return_value=LdapState.ACTIVE,
    )

    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {
            "ldap-hash": "ea94093f0d37df1ba61800afd667921396f1f6d7e9957832456058df2ad8602f",
        },
    )

    assert (
        as_status(
            mongos_harness.charm.operator.ldap_manager.get_statuses(
                scope=Scope.UNIT, recompute=True
            )[0]
        )
        == ActiveStatus()
    )
