# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from dataclasses import replace
from unittest.mock import PropertyMock

import pytest
from ops.model import BlockedStatus
from ops.testing import Relation
from yaml import safe_dump, safe_load

from single_kernel_mongo.config.relations import ExternalRequirerRelations, PeerRelationNames
from single_kernel_mongo.config.statuses import AuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import DeferrableFailedHookChecksError
from tests.unit.auth_scenario_helpers import get_relation, mongo_state, mongos_state


@pytest.fixture(params=[MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def authentication_state(mongodb_container, request):
    return mongo_state(mongodb_container, role=request.param, initialised=False)


@pytest.mark.parametrize("endpoint", ["ldap", "ldap-certificate-transfer"])
def test_oauth_blocks_existing_incomplete_ldap_relation(
    mongodb_ctx, authentication_state, endpoint
):
    ldap = Relation(endpoint=endpoint, remote_app_name="glauth")
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(authentication_state, relations={*authentication_state.relations, ldap})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    state_in = replace(state_in, relations={*state_in.relations, oauth})

    state_out = mongodb_ctx.run(mongodb_ctx.on.relation_created(oauth), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.mark.parametrize("endpoint", ["ldap", "ldap-certificate-transfer"])
def test_incomplete_ldap_relation_blocks_existing_oauth(
    mongodb_ctx, authentication_state, endpoint
):
    ldap = Relation(endpoint=endpoint, remote_app_name="glauth")
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(authentication_state, relations={*authentication_state.relations, oauth})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    state_in = replace(state_in, relations={*state_in.relations, ldap})

    state_out = mongodb_ctx.run(mongodb_ctx.on.relation_created(ldap), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.mark.parametrize("option", ["ldap-user-to-dn-mapping", "ldap-query-template"])
def test_oauth_blocks_existing_ldap_option(mongodb_ctx, authentication_state, option):
    state_in = replace(
        authentication_state, config={**authentication_state.config, option: "configured"}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(state_in, relations={*state_in.relations, oauth})

    state_out = mongodb_ctx.run(mongodb_ctx.on.relation_created(oauth), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.mark.parametrize("option", ["ldap-user-to-dn-mapping", "ldap-query-template"])
def test_ldap_option_blocks_existing_oauth(mongodb_ctx, authentication_state, mocker, option):
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(authentication_state, relations={*authentication_state.relations, oauth})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    state_in = replace(state_in, config={**state_in.config, option: "configured"})
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_config_and_restart"
    )

    state_out = mongodb_ctx.run(mongodb_ctx.on.config_changed(), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.fixture
def conflicting_authentication(mongodb_container):
    return mongo_state(
        mongodb_container,
        relations={
            Relation(endpoint="oauth", remote_app_name="hydra"),
            Relation(endpoint="ldap", remote_app_name="glauth"),
        },
    )


@pytest.mark.parametrize("manager_name", ["oauth_manager", "ldap_manager"])
def test_conflict_reports_blocked_status(mongodb_ctx, conflicting_authentication, manager_name):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        manager = getattr(scenario.charm.operator, manager_name)
        assert manager.get_statuses("unit") == [AuthStatuses.LDAP_OAUTH_CONFLICT.value]
        assert manager.get_statuses("unit", recompute=True) == [
            AuthStatuses.LDAP_OAUTH_CONFLICT.value
        ]


@pytest.mark.parametrize("manager_name", ["oauth_manager", "ldap_manager"])
@pytest.mark.parametrize("removed_relation", ["oauth", "ldap"])
def test_removing_setup_clears_cached_conflict_status(
    mongodb_ctx, conflicting_authentication, manager_name, removed_relation
):
    state_in = conflicting_authentication
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        manager = getattr(operator, manager_name)
        operator.state.statuses.add(
            AuthStatuses.LDAP_OAUTH_CONFLICT.value, scope="unit", component=manager.name
        )
        state_out = scenario.run()
    removed = get_relation(state_out, removed_relation)
    state_in = replace(state_out, relations=state_out.relations - {removed})

    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        manager = getattr(operator, manager_name)
        assert not operator.state.authentication_conflict
        assert AuthStatuses.LDAP_OAUTH_CONFLICT.value not in manager.get_statuses("unit")
        assert AuthStatuses.LDAP_OAUTH_CONFLICT.value not in manager.get_statuses(
            "unit", recompute=True
        )


def test_conflict_prevents_oauth_changes(mongodb_ctx, mocker, conflicting_authentication):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        operator = scenario.charm.operator
        request = mocker.patch.object(operator, "async_restart_charm_services")

        with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
            operator.oauth_manager.configure()
        with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
            operator.oauth_manager.restart_when_ready()

        request.assert_not_called()


def test_conflict_prevents_ldap_changes(mongodb_ctx, mocker, conflicting_authentication):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        operator = scenario.charm.operator
        request = mocker.patch.object(operator, "async_restart_charm_services")

        with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
            operator.ldap_manager.store_ldap_credentials_and_uri(
                operator.charm.model.get_relation("ldap")
            )
        with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
            operator.ldap_manager.restart_when_ready()

        request.assert_not_called()


@pytest.mark.parametrize(
    "current",
    [
        pytest.param(
            {"security": {"authorization": "enabled"}, "setParameter": {}},
            id="neither-enabled",
        ),
        pytest.param(
            {
                "security": {
                    "authorization": "enabled",
                    "ldap": {"servers": "existing-ldap", "bind": {"queryUser": "user"}},
                },
                "setParameter": {
                    "authenticationMechanisms": "PLAIN,SCRAM-SHA-256",
                    "ldapUserCacheInvalidationInterval": 30,
                },
            },
            id="ldap-enabled",
        ),
        pytest.param(
            {
                "security": {"authorization": "enabled"},
                "setParameter": {
                    "authenticationMechanisms": "SCRAM-SHA-256,MONGODB-OIDC",
                    "oidcIdentityProviders": json.dumps([{"issuer": "https://existing-issuer"}]),
                },
            },
            id="oidc-enabled",
        ),
    ],
)
def test_conflict_preserves_enabled_authentication(
    mongodb_ctx, mocker, conflicting_authentication, current
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        config = scenario.charm.operator.config_manager
        mocker.patch.object(config.workload, "read", return_value=[safe_dump(current)])
        mocker.patch.object(config.workload, "active", return_value=True)
        write = mocker.patch.object(config.workload, "write")
        mocker.patch.object(config.workload, "restart")
        ldap_params = mocker.patch.object(
            type(config), "ldap_parameters", new_callable=PropertyMock
        )
        oauth_params = mocker.patch.object(
            type(config), "oauth_parameters", new_callable=PropertyMock
        )
        ldap_params.side_effect = AssertionError("Must not enable or update LDAP during a conflict")
        oauth_params.side_effect = AssertionError(
            "Must not enable or update OIDC during a conflict"
        )

        config.configure_and_restart()

        write.assert_called_once()
        rendered = safe_load(write.call_args.args[1])
        assert rendered["security"]["authorization"] == current["security"]["authorization"]
        assert rendered["security"].get("ldap") == current["security"].get("ldap")
        assert rendered["setParameter"] == {"processUmask": "037", **current["setParameter"]}
        ldap_params.assert_not_called()
        oauth_params.assert_not_called()


@pytest.mark.parametrize(
    ("removed_relation", "ldap_parameters", "oauth_parameters", "expected"),
    [
        pytest.param(
            ExternalRequirerRelations.LDAP.value,
            {},
            {"setParameter": {"authenticationMechanisms": "SCRAM-SHA-256,MONGODB-OIDC"}},
            {"setParameter": {"authenticationMechanisms": "SCRAM-SHA-256,MONGODB-OIDC"}},
            id="remove-ldap-enables-oidc",
        ),
        pytest.param(
            ExternalRequirerRelations.OAUTH.value,
            {"setParameter": {"authenticationMechanisms": "PLAIN,SCRAM-SHA-256"}},
            {},
            {"setParameter": {"authenticationMechanisms": "PLAIN,SCRAM-SHA-256"}},
            id="remove-oidc-enables-ldap",
        ),
    ],
)
def test_removing_setup_allows_remaining_authentication(
    mongodb_ctx,
    mocker,
    conflicting_authentication,
    removed_relation,
    ldap_parameters,
    oauth_parameters,
    expected,
):
    removed = get_relation(conflicting_authentication, removed_relation)
    state_in = replace(
        conflicting_authentication, relations=conflicting_authentication.relations - {removed}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        config = operator.config_manager
        mocker.patch.object(
            type(config), "ldap_parameters", new_callable=PropertyMock, return_value=ldap_parameters
        )
        mocker.patch.object(
            type(config),
            "oauth_parameters",
            new_callable=PropertyMock,
            return_value=oauth_parameters,
        )

        assert not operator.state.authentication_conflict
        assert config.authentication_parameters == expected


def test_mongos_detects_oidc_from_config_server_with_incomplete_ldap(mongos_ctx, mongodb_container):
    state_in = mongos_state(
        mongodb_container,
        relations={
            Relation(
                endpoint="cluster",
                remote_app_name="config-server",
                remote_app_data={"oauth-issuer": "https://issuer"},
            ),
            Relation(endpoint="ldap-certificate-transfer", remote_app_name="glauth"),
        },
    )
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        assert operator.state.authentication_conflict
        assert operator.ldap_manager.get_statuses("unit") == [
            AuthStatuses.LDAP_OAUTH_CONFLICT.value
        ]


def test_conflict_keeps_existing_ldap_credentials_and_certificates(
    mongodb_ctx, mocker, conflicting_authentication
):
    clean_credentials = mocker.patch("single_kernel_mongo.state.ldap_state.LdapState.clean_databag")
    clean_certificates = mocker.patch(
        "single_kernel_mongo.state.ldap_state.LdapState.clean_certificates"
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        operator = scenario.charm.operator
        delete = mocker.patch.object(operator.ldap_manager.workload, "delete")
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
            operator.ldap_manager.clean_ldap_credentials_and_uri()
        with pytest.raises(DeferrableFailedHookChecksError, match="mutually exclusive"):
            operator.ldap_manager.remove_ldap_certificates()

        clean_credentials.assert_not_called()
        clean_certificates.assert_not_called()
        delete.assert_not_called()
        restart.assert_not_called()


def test_ldap_unavailable_defers_during_authentication_conflict(
    mongodb_ctx, conflicting_authentication, mocker
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        event = mocker.Mock()

        scenario.charm.operator.ldap_events._on_ldap_unavailable(event)

        event.defer.assert_called_once_with()


def test_ldap_certificate_removal_defers_during_authentication_conflict(
    mongodb_ctx, conflicting_authentication, mocker
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        event = mocker.Mock()

        scenario.charm.operator.ldap_events._on_certificate_removed(event)

        event.defer.assert_called_once_with()


@pytest.mark.parametrize("role", [MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
@pytest.mark.parametrize("option", ["ldap-user-to-dn-mapping", "ldap-query-template"])
def test_deferred_ldap_config_is_applied_after_oauth_removal(
    mongodb_ctx, mongodb_container, mocker, role, option
):
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = mongo_state(
        mongodb_container, role=role, config={option: "configured"}, relations={oauth}
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_config_and_restart",
        autospec=True,
        side_effect=lambda operator: operator._handle_ldap_config_changes(),
    )
    mocker.patch("single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_status")

    state_out = mongodb_ctx.run(mongodb_ctx.on.config_changed(), state_in)

    assert any(event.observer == "on_config_changed" for event in state_out.deferred)
    assert option not in get_relation(state_out, PeerRelationNames.LDAP_PEERS.value).local_app_data
    state_in = replace(
        state_out,
        relations={relation for relation in state_out.relations if relation.id != oauth.id},
    )

    state_out = mongodb_ctx.run(mongodb_ctx.on.collect_unit_status(), state_in)

    assert not any(event.observer == "on_config_changed" for event in state_out.deferred)
    assert (
        get_relation(state_out, PeerRelationNames.LDAP_PEERS.value).local_app_data[option]
        == "configured"
    )
