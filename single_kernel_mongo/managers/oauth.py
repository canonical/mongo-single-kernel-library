#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for the OAuth integration.

This class is only instantiated by the MongoDBOperator manager.
The oauth relation only exists in the MongoDB charm. It does not exist in the mongos charm.

For replica sets: it validates the integration, stores the issuer in the application peer databag,
and requests a rolling restart if the configuration has changed.
For config servers: it validates the integration, stores the issuer in the application peer databag,
and propagates the issuer to all mongos through the cluster relation.

Shards do not integrate with OAuth. The charm will reject the relation if the role is a shard.
Oauth and LDAP are mutually exclusive.
"""

from __future__ import annotations

import json
import ssl
from logging import getLogger
from typing import TYPE_CHECKING, final
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from charmlibs.interfaces.certificate_transfer import CertificateTransferRequires
from charmlibs.interfaces.oauth import ClientConfig, OAuthRequirer
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import AbstractManagerStatus
from data_platform_helpers.advanced_statuses.types import Scope
from ops.framework import Object

from single_kernel_mongo.config.models import OAuthState
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    LdapAndOauthConflictError,
    NonDeferrableFailedHookChecksError,
    WorkloadServiceError,
)
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


logger = getLogger(__name__)


@final
class OAuthManager(Object, AbstractManagerStatus[CharmState]):
    """Own the OAuth requirer and OAuth workload operations."""

    def __init__(self, dependent: MongoDBOperator, state: CharmState):
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
                grant_types=["client_credentials"],
                scope="openid profile",
                token_endpoint_auth_method="client_secret_basic",
            ),
            relation_name=self.name,
        )

        self.certificate_transfer = CertificateTransferRequires(
            self.charm, ExternalRequirerRelations.OAUTH_CERT.value
        )

    def _assert_pass_hook_checks(self) -> None:
        """Reject unsupported roles and defer OAuth hooks until MongoDB is ready.

        Raises:
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            DeferrableFailedHookChecksError: The database is not initialised, Vault
                is degraded, a refresh is in progress, or LDAP setup conflicts with OIDC.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
        """
        if self.state.is_role(MongoDBRoles.SHARD):
            self.state.statuses.add(
                OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value,
                scope="app",
                component=self.name,
            )
            raise NonDeferrableFailedHookChecksError("Cannot integrate OAuth with shard.")
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("DB is not initialised")
        if self.dependent.refresh_in_progress:
            raise DeferrableFailedHookChecksError("OAuth hooks are not supported during a refresh.")
        if self.state.authentication_conflict:
            raise LdapAndOauthConflictError("LDAP and OIDC are mutually exclusive.")
        if self.dependent.vault_manager.get_degraded_state():
            raise DeferrableFailedHookChecksError("Encryption at rest is not working properly.")

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
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
        """
        if not self.state.oauth_relation:
            return
        if not self.charm.unit.is_leader():
            return

        self._assert_pass_hook_checks()
        self.reconcile()

    def _validate_and_store_issuer(self, issuer: str) -> bool:
        """Validate the issuer and store/share it only after successful validation."""
        self._clear_issuer_statuses()
        if connection_state := self.get_issuer_connection_state(issuer):
            for status in self.map_state_to_statuses(connection_state):
                self.state.statuses.add(status, scope="unit", component=self.name)
            return False
        if self.charm.unit.is_leader():
            self.state.app_peer_data.oauth_issuer = issuer
            self.dependent.cluster_manager.update_oauth_issuer_to_mongos()
        return True

    def remove(self) -> None:
        """Remove and propagate the OAuth issuer on the leader.

        The leader clears the issuer from application peer databag.
        Config servers withdraw it from all Mongos through the cluster relation.
        Replica sets request an asynchronous rolling restart if the configuration
        has changed. Followers reconcile through peer relation events.

        We allow clean up even if there is a conflict with LDAP,
        because the relation is being removed.

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
        self.dependent.cluster_manager.update_oauth_issuer_to_mongos()
        self.restart_when_ready()

    def reconcile(self) -> None:
        """Apply validated OAuth configuration or finish removing it.

        The leader publishes the desired issuer; followers consume the shared
        issuer. Invalid or incomplete provider data leaves the previous issuer
        unchanged. Hook prerequisites and rolling restart errors propagate to
        the event handler for deferral.
        """
        integration_state = self.oauth_state()
        self.state.statuses.clear(scope="unit", component=self.name)
        for status in self.map_state_to_statuses(integration_state):
            self.state.statuses.add(status, scope="unit", component=self.name)
        if integration_state == OAuthState.EMPTY:
            return

        self.assert_pass_hook_checks()
        self.reconcile_certificates()

        if integration_state == OAuthState.REMOVING:
            if self.charm.unit.is_leader():
                self.remove()
            else:
                self.restart_when_ready()
            return
        if integration_state != OAuthState.ACTIVE:
            return

        if self.charm.unit.is_leader():
            provider = self.oauth_requirer.get_provider_info()
            if provider is None or not provider.issuer_url:
                return
            self.state.app_peer_data.oauth_issuer = provider.issuer_url
            self.dependent.cluster_manager.update_oauth_issuer_to_mongos()
            self.dependent.cluster_manager.update_oauth_ca_to_mongos()
        self.restart_when_ready()

    def restart_when_ready(self) -> None:
        """Request a rolling restart to reconcile the replica set's OAuth configuration.

        Skip the request if there is no OAuth relation or issuer to reconcile.
        Keep reconciling an existing issuer after the relation is removed.
        Request a rolling restart if configuration has changed.

        Raises:
            RollingOpsNoRelationError: If an async lock is requested too early.
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: Hook checks reject the configuration.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
        """
        if not self.state.is_role(MongoDBRoles.REPLICATION):
            return
        file_has_oauth_configuration = self.dependent.config_manager.file_has_oauth_configuration()
        if not self.state.app_peer_data.oauth_issuer and not file_has_oauth_configuration:
            return

        self._assert_pass_hook_checks()

        if self.dependent.config_manager.config_changed():
            self.dependent.async_restart_charm_services(force=False)

    def store_certificates(self, certificates: set[str]) -> None:
        """Publish the CA in the peer secret and reconcile it on the leader.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
        """
        if not self.charm.unit.is_leader():
            return
        self.assert_pass_hook_checks()
        if not certificates:
            self.remove_certificates()
            return
        bundle = "\n".join(sorted(certificates))
        self.state.app_peer_data.oauth_ca = bundle
        self.dependent.cluster_manager.update_oauth_ca_to_mongos()
        self.reconcile()

    def remove_certificates(self) -> None:
        """Withdraw the CA from the peer secret and reconcile it on the leader.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
        """
        if not self.charm.unit.is_leader():
            return
        self.assert_pass_hook_checks()
        self.state.app_peer_data.oauth_ca = None
        self.reconcile_certificates()
        self.dependent.cluster_manager.update_oauth_ca_to_mongos()
        self.restart_when_ready()

    def reconcile_certificates(self) -> None:
        """Reconcile the replica's CA file with the application peer secret.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
        """
        if not self.state.is_role(MongoDBRoles.REPLICATION):
            return
        self.assert_pass_hook_checks()
        workload = self.dependent.workload
        if bundle := self.state.app_peer_data.oauth_ca:
            workload.write(workload.paths.oauth_ca_file, bundle)
        elif workload.exists(workload.paths.oauth_ca_file):
            workload.delete(workload.paths.oauth_ca_file)

    def get_issuer_connection_state(self, issuer: str) -> OAuthState | None:
        """Verify HTTPS discovery metadata against the OAuth relation."""
        try:
            if urlsplit(issuer).scheme != "https":
                return OAuthState.ISSUER_TLS_ERROR
            context = self._issuer_ssl_context()
            discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
            with urlopen(discovery_url, context=context, timeout=5) as response:
                document = json.load(response)
            if self._is_valid_discovery(document, issuer):
                return None
            return OAuthState.INVALID_DISCOVERY
        except (json.JSONDecodeError, UnicodeDecodeError, HTTPError):
            return OAuthState.INVALID_DISCOVERY
        except (ssl.SSLError, ValueError):
            return OAuthState.ISSUER_TLS_ERROR
        except URLError as err:
            if isinstance(err.reason, ssl.SSLError):
                return OAuthState.ISSUER_TLS_ERROR
            return OAuthState.ISSUER_UNREACHABLE
        except (OSError, WorkloadServiceError):
            return OAuthState.ISSUER_UNREACHABLE

    def _is_valid_discovery(self, document: object, issuer: str) -> bool:
        """Compare required discovery fields with the corresponding relation fields."""
        if not isinstance(document, dict):
            return False

        for key in ("issuer", "token_endpoint", "jwks_uri"):
            value = document.get(key)
            if not isinstance(value, str) or not value:
                return False

        if document["issuer"] != issuer:
            return False

        provider = self.oauth_requirer.get_provider_info()
        if provider:
            if document["token_endpoint"] != provider.token_endpoint:
                return False
            if document["jwks_uri"] != provider.jwks_endpoint:
                return False

        return True

    def _issuer_ssl_context(self) -> ssl.SSLContext:
        """Use transferred CA certificates when available, or system trust otherwise."""
        ca = self.state.app_peer_data.oauth_ca
        return ssl.create_default_context(cadata=ca) if ca else ssl.create_default_context()

    def oauth_state(self) -> OAuthState:
        """Evaluate OAuth readiness without changing shared or workload configuration.

        ACTIVE means discovery validation succeeded, not that a rolling restart has
        completed. Operational prerequisites remain in assert_pass_hook_checks().
        A transferred CA is optional when no certificate relation is present.
        """
        if not self.state.db_initialised:
            return OAuthState.EMPTY

        oauth_relation = self.state.oauth_relation
        cert_relation = self.state.oauth_cert_relation

        if oauth_relation is None and self._has_oauth_configuration():
            return OAuthState.REMOVING
        if oauth_relation is None and cert_relation is None:
            return OAuthState.EMPTY

        if self.state.is_role(MongoDBRoles.SHARD):
            return OAuthState.WRONG_ROLE

        if self.state.authentication_conflict:
            return OAuthState.LDAP_CONFLICT

        if oauth_relation is None and cert_relation is not None:
            return OAuthState.MISSING_OAUTH_RELATION

        issuer = self.state.app_peer_data.oauth_issuer
        if self.charm.unit.is_leader():
            provider = self.oauth_requirer.get_provider_info()
            issuer = provider.issuer_url if provider else None
        if not issuer:
            return OAuthState.WAITING_FOR_PROVIDER_DATA

        if state := self.get_issuer_connection_state(issuer):
            return state

        return OAuthState.ACTIVE

    def map_state_to_statuses(self, state: OAuthState) -> list[StatusObject]:
        """Maps a OAuth integration state to a list of status objects."""
        match state:
            case OAuthState.EMPTY | OAuthState.REMOVING:
                return []
            case OAuthState.WRONG_ROLE:
                return [OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value]
            case OAuthState.LDAP_CONFLICT:
                return []
            case OAuthState.MISSING_OAUTH_RELATION:
                return [OAuthStatuses.MISSING_OAUTH_RELATION.value]
            case OAuthState.WAITING_FOR_PROVIDER_DATA:
                return [OAuthStatuses.WAITING_FOR_OAUTH_DATA.value]
            case OAuthState.INVALID_DISCOVERY:
                return [OAuthStatuses.INVALID_DISCOVERY.value]
            case OAuthState.ISSUER_TLS_ERROR:
                return [OAuthStatuses.ISSUER_TLS_ERROR.value]
            case OAuthState.ISSUER_UNREACHABLE:
                return [OAuthStatuses.ISSUER_UNREACHABLE.value]
            case OAuthState.ACTIVE:
                return [OAuthStatuses.ACTIVE_IDLE.value]

    def _clear_issuer_statuses(self) -> None:
        """Clear previous issuer connection and discovery errors."""
        for status in (
            OAuthStatuses.ISSUER_TLS_ERROR,
            OAuthStatuses.ISSUER_UNREACHABLE,
            OAuthStatuses.INVALID_DISCOVERY,
        ):
            self.state.statuses.delete(status.value, scope="unit", component=self.name)

    def _has_oauth_configuration(self) -> bool:
        """Whether a shared issuer or local configuration still needs reconciliation."""
        return bool(self.state.app_peer_data.oauth_issuer) or (
            self.state.is_role(MongoDBRoles.REPLICATION)
            and self.dependent.config_manager.file_has_oauth_configuration()
        )

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Report the oauth status."""
        if self.state.authentication_conflict:
            return []
        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root
        if scope == "app":
            if self.state.is_role(MongoDBRoles.SHARD) and self.state.oauth_relation:
                return [OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value]
        return self.map_state_to_statuses(self.oauth_state())
