# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from dataclasses import replace

import pytest
from charmlibs.rollingops import OperationResult
from ops.testing import Relation, Secret

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


def test_conflict_blocks_ldap_cleanup_restart(mongodb_ctx, mocker, conflicting_authentication):
    with mongodb_ctx(mongodb_ctx.on.collect_unit_status(), conflicting_authentication) as scenario:
        operator = scenario.charm.operator
        configure = mocker.patch.object(operator.config_manager, "configure_and_restart")
        restart = mocker.patch.object(operator.workload, "restart")

        assert (
            operator.restart_charm_services_callback(force=False) == OperationResult.RETRY_RELEASE
        )

        configure.assert_not_called()
        restart.assert_not_called()


def test_mongos_holds_pending_restart_on_authentication_conflict(
    mongos_ctx, mongodb_container, mocker
):
    state_in = mongos_state(
        mongodb_container,
        relations={
            Relation(
                endpoint="cluster",
                remote_app_data={
                    "oauth-issuer": "https://issuer",
                    "config-server-db": "config-server/10.0.0.1:27017",
                },
            ),
            Relation(endpoint="ldap"),
        },
    )
    with mongos_ctx(mongos_ctx.on.collect_unit_status(), state_in) as scenario:
        operator = scenario.charm.operator
        restart = mocker.patch.object(operator.cluster_manager, "update_mongos_and_restart")
        assert operator.state.authentication_conflict
        assert operator.restart_charm_services_callback(force=True) == OperationResult.RETRY_RELEASE
        restart.assert_not_called()
