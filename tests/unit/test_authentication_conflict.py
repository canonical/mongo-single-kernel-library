# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from dataclasses import replace
from unittest.mock import PropertyMock

import pytest
from ops.model import BlockedStatus
from ops.testing import Relation, Secret
from yaml import safe_dump, safe_load

from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import AuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from tests.unit.auth_scenario_helpers import get_relation, mongo_state, mongos_state, oauth_relation


@pytest.fixture(params=[MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def authentication_state(mongodb_container, request):
    return mongo_state(mongodb_container, role=request.param, initialised=False)


@pytest.mark.parametrize("endpoint", ["ldap", "ldap-certificate-transfer"])
@pytest.mark.parametrize("oauth_endpoint", ["oauth", "oauth-certificate-transfer"])
def test_oauth_blocks_existing_incomplete_ldap_relation(
    mongodb_ctx, authentication_state, endpoint, oauth_endpoint
):
    ldap = Relation(endpoint=endpoint, remote_app_name="glauth")
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    initial_state = replace(authentication_state, relations={*authentication_state.relations, ldap})
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), initial_state) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    state_in = replace(
        authentication_state, relations={*authentication_state.relations, ldap, oauth}
    )

    state_out = mongodb_ctx.run(mongodb_ctx.on.relation_created(oauth), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.mark.parametrize("endpoint", ["ldap", "ldap-certificate-transfer"])
@pytest.mark.parametrize("oauth_endpoint", ["oauth", "oauth-certificate-transfer"])
def test_incomplete_ldap_relation_blocks_existing_oauth(
    mongodb_ctx, authentication_state, endpoint, oauth_endpoint
):
    ldap = Relation(endpoint=endpoint, remote_app_name="glauth")
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    initial_state = replace(
        authentication_state, relations={*authentication_state.relations, oauth}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), initial_state) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    state_in = replace(
        authentication_state, relations={*authentication_state.relations, oauth, ldap}
    )

    state_out = mongodb_ctx.run(mongodb_ctx.on.relation_created(ldap), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.mark.parametrize("option", ["ldap-user-to-dn-mapping", "ldap-query-template"])
def test_oauth_blocks_existing_ldap_option(mongodb_ctx, authentication_state, option):
    initial_state = replace(
        authentication_state, config={**authentication_state.config, option: "configured"}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), initial_state) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    state_in = replace(
        authentication_state,
        config={**authentication_state.config, option: "configured"},
        relations={*authentication_state.relations, oauth},
    )

    state_out = mongodb_ctx.run(mongodb_ctx.on.relation_created(oauth), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.mark.parametrize("option", ["ldap-user-to-dn-mapping", "ldap-query-template"])
def test_ldap_option_blocks_existing_oauth(mongodb_ctx, authentication_state, mocker, option):
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    initial_state = replace(
        authentication_state, relations={*authentication_state.relations, oauth}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), initial_state) as scenario:
        assert not scenario.charm.operator.state.authentication_conflict
    state_in = replace(
        authentication_state,
        relations={*authentication_state.relations, oauth},
        config={**authentication_state.config, option: "configured"},
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_config_and_restart"
    )

    state_out = mongodb_ctx.run(mongodb_ctx.on.config_changed(), state_in)

    assert isinstance(state_out.unit_status, BlockedStatus)


@pytest.fixture
def conflicting_authentication(mongodb_container):
    secret = Secret(tracked_content={"secret": "client-secret"})
    return replace(
        mongo_state(
            mongodb_container,
            relations={
                oauth_relation(client_id="client-id", client_secret_id=secret.id),
                Relation(endpoint="ldap", remote_app_name="glauth"),
            },
        ),
        secrets={secret},
    )


@pytest.mark.parametrize("manager_name", ["oauth_manager", "ldap_manager"])
def test_conflict_reports_blocked_status(mongodb_ctx, conflicting_authentication, manager_name):
    state_in = conflicting_authentication
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        manager = getattr(scenario.charm.operator, manager_name)
        assert manager.get_statuses("unit") == [AuthStatuses.LDAP_OAUTH_CONFLICT.value]


def test_conflict_prevents_oauth_changes(mongodb_ctx, mocker, conflicting_authentication):
    with mongodb_ctx(
        mongodb_ctx.on.relation_changed(get_relation(conflicting_authentication, "oauth")),
        conflicting_authentication,
    ) as scenario:
        operator = scenario.charm.operator
        request = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

        request.assert_not_called()
    assert len(state_out.deferred) == 1


def test_oauth_removal_resolves_authentication_conflict(
    mongodb_ctx, mocker, conflicting_authentication
):
    with mongodb_ctx(
        mongodb_ctx.on.relation_broken(get_relation(conflicting_authentication, "oauth")),
        conflicting_authentication,
    ) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        request = mocker.patch.object(operator, "async_restart_charm_services")

        state_out = scenario.run()

        request.assert_not_called()
        assert not operator.state.authentication_conflict
    assert not state_out.deferred


def test_conflict_prevents_ldap_changes(mongodb_ctx, mocker, conflicting_authentication):
    state_in = conflicting_authentication
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        request = mocker.patch.object(operator, "async_restart_charm_services")

        operator.ldap_manager.ldap_requirer.on.ldap_ready.emit(
            scenario.charm.model.get_relation("ldap")
        )
        scenario.charm.on[PeerRelationNames.LDAP_PEERS.value].relation_changed.emit(
            scenario.charm.model.get_relation(PeerRelationNames.LDAP_PEERS.value),
            scenario.charm.app,
        )

        state_out = scenario.run()

        request.assert_not_called()
    assert len(state_out.deferred) == 2


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
    state_in = conflicting_authentication
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
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
    certificates = Relation(endpoint="ldap-certificate-transfer", remote_app_name="glauth")
    state_in = replace(
        conflicting_authentication,
        relations={*conflicting_authentication.relations, certificates},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        delete = mocker.patch.object(operator.ldap_manager.workload, "delete")
        restart = mocker.patch.object(operator, "async_restart_charm_services")

        operator.ldap_manager.ldap_requirer.on.ldap_unavailable.emit(
            scenario.charm.model.get_relation("ldap")
        )
        operator.ldap_manager.certificate_transfer.on.certificate_removed.emit(
            relation_id=certificates.id
        )

        state_out = scenario.run()

        clean_credentials.assert_not_called()
        clean_certificates.assert_not_called()
        delete.assert_not_called()
        restart.assert_not_called()
    assert len(state_out.deferred) == 2
