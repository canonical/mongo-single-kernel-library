# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from dataclasses import replace
from unittest.mock import PropertyMock

import pytest
from ops.testing import Relation, Secret
from yaml import safe_dump

from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import AuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from tests.unit.auth_scenario_helpers import get_relation, mongo_state, mongos_state, oauth_relation


@pytest.fixture(params=[MongoDBRoles.REPLICATION, MongoDBRoles.CONFIG_SERVER])
def authentication_state(mongodb_container, request):
    return mongo_state(mongodb_container, role=request.param, initialised=False)


@pytest.mark.parametrize("endpoint", ["ldap", "ldap-certificate-transfer"])
def test_mongodb_blocks_on_oauth_and_incomplete_ldap_relation(
    mongodb_ctx, authentication_state, endpoint
):
    ldap = Relation(endpoint=endpoint, remote_app_name="glauth")
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    initial_state = replace(
        authentication_state, relations={*authentication_state.relations, ldap, oauth}
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), initial_state) as scenario:
        statuses = scenario.charm.operator.get_statuses("app", recompute=True)

    assert AuthStatuses.LDAP_OAUTH_CONFLICT.value in statuses


@pytest.mark.parametrize("option", ["ldap-user-to-dn-mapping", "ldap-query-template"])
def test_mongodb_blocks_on_oauth_and_ldap_option(mongodb_ctx, authentication_state, option):
    oauth = Relation(endpoint="oauth", remote_app_name="hydra")
    initial_state = replace(
        authentication_state,
        config={**authentication_state.config, option: "configured"},
        relations={*authentication_state.relations, oauth},
    )
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), initial_state) as scenario:
        statuses = scenario.charm.operator.get_statuses("app", recompute=True)

    assert AuthStatuses.LDAP_OAUTH_CONFLICT.value in statuses


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
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
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


def test_authentication_selects_ldap_from_current_config(
    mongodb_ctx, mocker, conflicting_authentication
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        config = scenario.charm.operator.config_manager
        ldap_parameters = {"security": {"ldap": {"servers": "ldap.example"}}}
        read = mocker.patch.object(
            config.workload, "read", return_value=[safe_dump(ldap_parameters)]
        )
        mocker.patch.object(
            type(config),
            "ldap_parameters",
            new_callable=PropertyMock,
            return_value=ldap_parameters,
        )
        oauth_params = mocker.patch.object(
            type(config), "oauth_parameters", new_callable=PropertyMock
        )

        assert config.authentication_parameters == ldap_parameters
        oauth_params.assert_not_called()
        read.assert_called_once_with(config.file)


def test_authentication_selects_oidc_from_current_config(
    mongodb_ctx, mocker, conflicting_authentication
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        config = scenario.charm.operator.config_manager
        oauth_parameters = {"setParameter": {"oidcIdentityProviders": "providers"}}
        read = mocker.patch.object(
            config.workload, "read", return_value=[safe_dump(oauth_parameters)]
        )
        mocker.patch.object(
            type(config),
            "oauth_parameters",
            new_callable=PropertyMock,
            return_value=oauth_parameters,
        )
        ldap_params = mocker.patch.object(
            type(config), "ldap_parameters", new_callable=PropertyMock
        )

        assert config.authentication_parameters == oauth_parameters
        ldap_params.assert_not_called()
        read.assert_called_once_with(config.file)


def test_authentication_remains_disabled_during_conflict(
    mongodb_ctx,
    mocker,
    conflicting_authentication,
):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        config = scenario.charm.operator.config_manager
        read = mocker.patch.object(config.workload, "read", return_value=[safe_dump({})])
        ldap_params = mocker.patch.object(
            type(config), "ldap_parameters", new_callable=PropertyMock
        )
        oauth_params = mocker.patch.object(
            type(config), "oauth_parameters", new_callable=PropertyMock
        )

        assert config.authentication_parameters == {}
        ldap_params.assert_not_called()
        oauth_params.assert_not_called()
        read.assert_called_once_with(config.file)


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
        assert AuthStatuses.LDAP_OAUTH_CONFLICT.value in operator.get_statuses(
            "app", recompute=True
        )


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


def test_mongos_conflict_without_configured_auth_does_not_enable_oidc(
    mongos_ctx, mongodb_container, mocker
):
    state_in = mongos_state(
        mongodb_container,
        relations={
            Relation(
                endpoint="cluster",
                remote_app_name="config-server",
                remote_app_data={"oauth-issuer": "https://possibly-new-issuer"},
            ),
            Relation(endpoint="ldap", remote_app_name="glauth"),
        },
    )
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        mocker.patch.object(operator.config_manager.workload, "read", return_value=["{}"])
        assert operator.config_manager.authentication_parameters == {}
