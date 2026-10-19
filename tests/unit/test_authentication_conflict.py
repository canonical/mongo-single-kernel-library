# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from unittest.mock import PropertyMock

import pytest
from ops.model import BlockedStatus
from yaml import safe_dump, safe_load

from single_kernel_mongo.config.relations import ExternalRequirerRelations, RelationNames
from single_kernel_mongo.config.statuses import AuthenticationStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import DeferrableFailedHookChecksError


@pytest.mark.parametrize("setup", ["ldap", "ldap-certificate-transfer", "mapping", "query"])
@pytest.mark.parametrize("oauth_first", [True, False])
@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def test_incomplete_setups_are_blocked(harness, setup, oauth_first, role):
    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = role
    oauth_id = None
    if oauth_first:
        oauth_id = harness.add_relation(ExternalRequirerRelations.OAUTH.value, "hydra")
    if setup in ("mapping", "query"):
        option = "ldap-user-to-dn-mapping" if setup == "mapping" else "ldap-query-template"
        with harness.hooks_disabled():
            harness.update_config({option: "configured"})
    else:
        harness.add_relation(setup, "glauth")
    if not oauth_first:
        assert not operator.state.authentication_conflict
        oauth_id = harness.add_relation(ExternalRequirerRelations.OAUTH.value, "hydra")

    assert operator.state.authentication_conflict
    for manager in (operator.oauth_manager, operator.ldap_manager):
        assert manager.get_statuses("unit") == [AuthenticationStatuses.LDAP_OIDC_CONFLICT.value]
        assert manager.get_statuses("unit", recompute=True) == [
            AuthenticationStatuses.LDAP_OIDC_CONFLICT.value
        ]
        with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
            manager.assert_pass_hook_checks()
        # Simulate the status heartbeat caching the blocked status.
        operator.state.statuses.add(
            AuthenticationStatuses.LDAP_OIDC_CONFLICT.value, scope="unit", component=manager.name
        )

    harness.evaluate_status()
    assert isinstance(harness.model.unit.status, BlockedStatus)

    harness.remove_relation(oauth_id)

    assert not operator.state.authentication_conflict
    for manager in (operator.oauth_manager, operator.ldap_manager):
        assert AuthenticationStatuses.LDAP_OIDC_CONFLICT.value not in manager.get_statuses("unit")


@pytest.mark.parametrize("active", ["none", "ldap", "oidc"])
@pytest.mark.parametrize("remove", ["ldap", "oidc"])
def test_conflict_preserves_enabled_authentication(harness, mocker, active, remove):
    harness.set_leader(True)
    operator = harness.charm.operator
    operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    operator.state.app_peer_data.db_initialised = True
    config = operator.config_manager
    current = {"security": {"authorization": "enabled"}, "setParameter": {}}
    if active == "ldap":
        current["security"]["ldap"] = {"servers": "existing-ldap", "bind": {"queryUser": "user"}}
        current["setParameter"] = {
            "authenticationMechanisms": "PLAIN,SCRAM-SHA-256",
            "ldapUserCacheInvalidationInterval": 30,
        }
    elif active == "oidc":
        current["setParameter"] = {
            "authenticationMechanisms": "SCRAM-SHA-256,MONGODB-OIDC",
            "oidcIdentityProviders": json.dumps([{"issuer": "https://existing-issuer"}]),
        }
    with harness.hooks_disabled():
        oauth_id = harness.add_relation(ExternalRequirerRelations.OAUTH.value, "hydra")
        ldap_id = harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth")
    mocker.patch.object(config.workload, "read", return_value=[safe_dump(current)])
    mocker.patch.object(config.workload, "active", return_value=True)
    write = mocker.patch.object(config.workload, "write")
    mocker.patch.object(config.workload, "restart")
    request = mocker.patch.object(operator, "async_restart_charm_services")
    ldap_params = mocker.patch.object(type(config), "ldap_parameters", new_callable=PropertyMock)
    oauth_params = mocker.patch.object(type(config), "oauth_parameters", new_callable=PropertyMock)
    ldap_params.side_effect = AssertionError("Must not enable or update LDAP during a conflict")
    oauth_params.side_effect = AssertionError("Must not enable or update OIDC during a conflict")

    with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
        operator.oauth_manager.configure()
    with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
        operator.ldap_manager.store_ldap_credentials_and_uri(
            harness.model.get_relation(ExternalRequirerRelations.LDAP.value, ldap_id)
        )
    operator.oauth_manager.restart_when_ready()
    operator.ldap_manager.restart_when_ready()
    request.assert_not_called()
    # Any other restart path must preserve exactly the existing authentication settings.
    config.configure_and_restart()
    rendered = safe_load(write.call_args.args[1])
    assert rendered["security"].get("ldap") == current["security"].get("ldap")
    for key in (
        "authenticationMechanisms",
        "oidcIdentityProviders",
        "ldapUserCacheInvalidationInterval",
    ):
        assert rendered["setParameter"].get(key) == current["setParameter"].get(key)
    ldap_params.assert_not_called()
    oauth_params.assert_not_called()

    with harness.hooks_disabled():
        harness.remove_relation(ldap_id if remove == "ldap" else oauth_id)
    assert not operator.state.authentication_conflict
    ldap_params.side_effect = None
    oauth_params.side_effect = None
    if remove == "ldap":
        ldap_params.return_value = {}
        oauth_params.return_value = {
            "setParameter": {"authenticationMechanisms": "SCRAM-SHA-256,MONGODB-OIDC"}
        }
        assert config.authentication_parameters == oauth_params.return_value
    else:
        ldap_params.return_value = {
            "setParameter": {"authenticationMechanisms": "PLAIN,SCRAM-SHA-256"}
        }
        oauth_params.return_value = {}
        assert config.authentication_parameters == ldap_params.return_value


def test_mongos_detects_oidc_from_config_server_with_incomplete_ldap(mongos_harness):
    operator = mongos_harness.charm.operator
    with mongos_harness.hooks_disabled():
        relation_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")
        mongos_harness.update_relation_data(
            relation_id, "config-server", {"oauth-issuer": "https://issuer"}
        )
        mongos_harness.add_relation(ExternalRequirerRelations.LDAP_CERT.value, "glauth")

    assert operator.state.authentication_conflict
    assert operator.oauth_manager.get_statuses("unit") == [
        AuthenticationStatuses.LDAP_OIDC_CONFLICT.value
    ]


def test_conflict_keeps_existing_ldap_credentials_and_certificates(harness, mocker):
    harness.set_leader(True)
    operator = harness.charm.operator
    with harness.hooks_disabled():
        harness.add_relation(ExternalRequirerRelations.OAUTH.value, "hydra")
        harness.add_relation(ExternalRequirerRelations.LDAP.value, "glauth")
    clean_credentials = mocker.patch("single_kernel_mongo.state.ldap_state.LdapState.clean_databag")
    clean_certificates = mocker.patch(
        "single_kernel_mongo.state.ldap_state.LdapState.clean_certificates"
    )
    delete = mocker.patch.object(operator.ldap_manager.workload, "delete")
    restart = mocker.patch.object(operator, "async_restart_charm_services")

    operator.ldap_manager.clean_ldap_credentials_and_uri()
    operator.ldap_manager.remove_ldap_certificates()

    clean_credentials.assert_not_called()
    clean_certificates.assert_not_called()
    delete.assert_not_called()
    restart.assert_not_called()
