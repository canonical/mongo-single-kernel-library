# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from ops.model import ActiveStatus, BlockedStatus, Relation
from ops.testing import Harness

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
)

from .mongodb_test_charm.src.charm import MongoTestCharm


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
            "bind_password_di": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    relation: Relation = harness.charm.operator.state.ldap_relation

    harness.charm.operator.ldap_manager.on_ldap_ready(relation)

    ldap_state = harness.charm.operator.state.ldap

    assert ldap_state.bind_user is not None
    assert ldap_state.bind_password is not None
    assert ldap_state.ldaps_urls == ["ldaps://ldap.glauth.com"]


def test_ldap_get_status(harness: Harness[MongoTestCharm], mock_fs_interactions):
    harness.set_leader()
    harness.charm.operator.state.app_peer_data.db_initialised = True
    # Case 1: No integration
    assert harness.charm.operator.ldap_manager.get_status() is None

    # Case 2, wrong role
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    ldap_relation_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth-k8s")

    assert harness.charm.operator.ldap_manager.get_status() == BlockedStatus(
        "Cannot integrate LDAP with shard."
    )

    # Case 3, correct role, but missing ldap_cert_relation
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    assert harness.charm.operator.ldap_manager.get_status() == BlockedStatus(
        "TLS is mandatory for LDAP transport."
    )

    # Case 4: Both relations good but not valid data.
    ldap_cert_relation_id = harness.add_relation(
        ExternalRequirerRelations.LDAP_CERT.value, "glauth-k8s"
    )

    assert harness.charm.operator.ldap_manager.get_status() == BlockedStatus(
        "Waiting for both LDAP data and Glauth certificates."
    )

    # Case 5: We received data from LDAP integration but not from cert integration
    harness.update_relation_data(
        ldap_relation_id,
        "glauth-k8s",
        {
            "base_dn": "dc=glauth,dc=com",
            "bind_dn": "cn=user,ou=group,dc=glauth,dc=com",
            "bind_password": "password",
            "bind_password_di": "secret-id",
            "auth_method": "simple",
            "starttls": "true",
            "ldaps_urls": '["ldaps://ldap.glauth.com"]',
            "urls": '["ldap://ldap.glauth.com"]',
        },
    )

    relation: Relation = harness.charm.operator.state.ldap_relation

    harness.charm.operator.ldap_manager.on_ldap_ready(relation)

    assert harness.charm.operator.ldap_manager.get_status() == BlockedStatus(
        "Waiting for Glauth certificates."
    )

    # Case 6: We received data from both integrations
    harness.add_relation_unit(ldap_cert_relation_id, "glauth-k8s/0")

    harness.update_relation_data(
        ldap_cert_relation_id,
        "glauth-k8s",
        {"ca": "deadbeef", "chain": '["feeddead"]', "certificate": "beefdead"},
    )
    harness.charm.operator.ldap_manager.on_certificate_available(
        "beefdead", "deadbeef", ["feeddead"]
    )
    assert harness.charm.operator.ldap_manager.get_status() == ActiveStatus()

    # Case 7: Begin of sundown, remove data from databag
    harness.charm.operator.state.ldap.clean_databag()
    assert harness.charm.operator.ldap_manager.get_status() == BlockedStatus(
        "Missing LDAP data from Glauth."
    )


def test_ldap_on_remove_clean_data(harness: Harness[MongoTestCharm], mock_fs_interactions):
    pass
