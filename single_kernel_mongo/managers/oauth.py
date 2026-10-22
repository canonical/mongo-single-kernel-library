#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for the OAuth integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from charmlibs.interfaces.oauth import ClientConfig, OAuthRequirer
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import AbstractManagerStatus
from data_platform_helpers.advanced_statuses.types import Scope
from ops.framework import Object
from yaml import safe_load

from single_kernel_mongo.config.literals import CharmKind
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import AuthStatuses, OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
)
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol


class OAuthManager(Object, AbstractManagerStatus[CharmState]):
    """Own the OAuth requirer and OAuth workload operations."""

    def __init__(self, dependent: OperatorProtocol, state: CharmState):
        self.name = ExternalRequirerRelations.OAUTH.value
        super().__init__(parent=dependent, key=self.name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state

        self.oauth_requirer = OAuthRequirer(
            self.charm,
            client_config=ClientConfig(
                # TODO: Remove the dummy URI once providers accept client_credentials
                # registrations without redirect_uri. This grant does not use redirects.
                redirect_uri="https://mongodb.invalid/oauth/callback",
                audience=["mongodb"],
                grant_types=["client_credentials"],
                scope="openid profile",
                token_endpoint_auth_method="client_secret_basic",
            ),
            relation_name=self.name,
        )

    def assert_pass_hook_checks(self) -> None:
        """Reject unsupported roles and defer OAuth hooks until MongoDB is ready.

        Raises:
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            DeferrableFailedHookChecksError: The database is not initialised, Vault
                is degraded, a refresh is in progress, or LDAP setup conflicts with OIDC.
        """
        if self.state.is_role(MongoDBRoles.SHARD):
            raise NonDeferrableFailedHookChecksError("Cannot integrate OAuth with shard.")
        if self.state.authentication_conflict:
            raise DeferrableFailedHookChecksError("LDAP and OIDC are mutually exclusive.")
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("DB is not initialised")
        if (
            self.dependent.name == CharmKind.MONGOD
            and self.dependent.vault_manager.get_degraded_state()  # type: ignore[attr-defined]
        ):
            raise DeferrableFailedHookChecksError("Encryption at rest is not working properly.")
        if self.dependent.refresh_in_progress:
            raise DeferrableFailedHookChecksError("OAuth hooks are not supported during a refresh.")

    def configure(self) -> None:
        """Store and propagate the OAuth issuer on the leader.

        The leader stores the issuer in application peer databag.

        Config servers propagate the issuer to Mongos through the cluster relation.
        Replica sets request an asynchronous rolling restart if the configuration
        has changed. Followers reconcile through peer relation events.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            RollingOpsNoRelationError: A rolling restart is requested before its
                relation is available.
        """
        if not self.charm.unit.is_leader():
            return
        self.assert_pass_hook_checks()

        provider = self.oauth_requirer.get_provider_info()
        if provider is None or not provider.issuer_url:
            raise DeferrableFailedHookChecksError("Waiting for OAuth issuer information.")

        self.state.app_peer_data.oauth_issuer = provider.issuer_url
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.dependent.cluster_manager.update_oauth_issuer_to_mongos()  # type: ignore[attr-defined]
            return
        self.restart_when_ready()

    def remove(self) -> None:
        """Remove and propagate the OAuth issuer on the leader.

        The leader clears the issuer from application peer databag.
        Config servers withdraw it from Mongos through the cluster relation.
        Replica sets request an asynchronous rolling restart if the configuration
        has changed. Followers reconcile through peer relation events.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            RollingOpsNoRelationError: A rolling restart is requested before its
                relation is available.
        """
        if not self.charm.unit.is_leader():
            return
        self.assert_pass_hook_checks()

        self.state.app_peer_data.oauth_issuer = None
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.dependent.cluster_manager.update_oauth_issuer_to_mongos()  # type: ignore[attr-defined]
        self.restart_when_ready()

    def restart_when_ready(self) -> None:
        """Request a rolling restart to reconcile the replica set's OAuth configuration.

        Skip the request if neither the peer databag nor the current configuration
        contains the oauth issuer.
        Request a rolling restart if configuration has changed.

        Raises:
            RollingOpsNoRelationError: If an async lock is requested too early.
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: Hook checks reject the configuration.
        """
        if not self.state.is_role(MongoDBRoles.REPLICATION):
            return
        self.assert_pass_hook_checks()
        manager = self.dependent.config_manager
        current = safe_load("\n".join(manager.workload.read(manager.file)))
        if not self.state.app_peer_data.oauth_issuer and not (current or {}).get(
            "setParameter", {}
        ).get("oidcIdentityProviders"):
            return
        if current != manager.build_config():
            self.dependent.async_restart_charm_services(force=False)

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Report the oauth status."""
        if scope == "unit" and self.state.authentication_conflict:
            return [AuthStatuses.LDAP_OAUTH_CONFLICT.value]
        if not recompute:
            # The current conflict is checked above. Ignore a stale cached result.
            return [
                status
                for status in self.state.statuses.get(scope=scope, component=self.name).root
                if status != AuthStatuses.LDAP_OAUTH_CONFLICT.value
            ]
        if scope == "app":
            return []
        if self.state.is_role(MongoDBRoles.SHARD) and self.model.relations.get(self.name, []):
            return [OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value]
        return []
