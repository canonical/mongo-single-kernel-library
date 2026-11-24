#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for the OAuth and the oauth certificate transfer integration.

This class is only instantiated by the MongoDBOperator manager.
The oauth relation only exists in the MongoDB charm. It does not exist in the mongos charm.

For replica sets: it validates the integrations, stores the issuer and CA in the application
peer databag, and requests a rolling restart if the configuration has changed.
For config servers: it validates the integrations, stores the issuer and CA in the application
peer databag, and propagates the issuer to all mongos through the cluster relation.

Shards do not integrate with OAuth. The charm will reject the relation if the role is a shard.
Oauth and LDAP are mutually exclusive.
"""

from __future__ import annotations

import json
from logging import getLogger
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING, Literal, final
from urllib.parse import urlsplit

import requests
from charmlibs.interfaces.certificate_transfer import CertificateTransferRequires
from charmlibs.interfaces.oauth import ClientConfig, OauthProviderConfig, OAuthRequirer
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import AbstractManagerStatus
from data_platform_helpers.advanced_statuses.types import Scope
from ops.framework import Object

from single_kernel_mongo.config.models import OAuthState
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableError,
    DeferrableFailedHookChecksError,
    LdapAndOauthConflictError,
    NonDeferrableFailedHookChecksError,
    OauthInvalidDiscoveryError,
    OauthIssuerTLSError,
    OauthIssuerUnreachableError,
    OauthProviderDataMissingError,
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
            self.set_status(OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value, scope="app")
            raise NonDeferrableFailedHookChecksError("Cannot integrate OAuth with shard.")
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("DB is not initialised")
        if self.dependent.refresh_in_progress:
            raise DeferrableFailedHookChecksError("OAuth hooks are not supported during a refresh.")
        if self.state.authentication_conflict:
            raise LdapAndOauthConflictError("LDAP and OIDC are mutually exclusive.")
        if self.dependent.vault_manager.get_degraded_state():
            raise DeferrableFailedHookChecksError("Encryption at rest is not working properly.")

    def configure_oauth(self) -> None:
        """Store and propagate the OAuth issuer on the leader.

        The leader stores the issuer in application peer databag.

        Config servers propagate the issuer to Mongos through the cluster relation.
        Replica sets request an asynchronous rolling restart if the configuration
        has changed.
        Followers will reconcile through peer relation events.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            RollingOpsNoRelationError: A rolling restart is requested before its
                relation is available.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
            OauthIssuerUnreachableError: The issuer URL is unreachable or times out.
        """
        if not self.state.oauth_relation:
            return
        if not self.charm.unit.is_leader():
            return
        self._assert_pass_hook_checks()

        provider = self.oauth_requirer.get_provider_info()
        ca = self.state.app_peer_data.oauth_ca
        if not self._is_valid_provider(provider, ca):
            return

        self.state.app_peer_data.oauth_issuer = provider.issuer_url
        self.dependent.cluster_manager.update_oauth_issuer_to_mongos()
        self.restart_replica_set_when_ready()

    def _is_valid_provider(self, provider: OauthProviderConfig | None, ca: str | None) -> bool:
        """Validate the issuer URL and discovery document against the relation data.

        Returns:
            bool: True if the issuer is valid and reachable, False otherwise.

        Raises:
            OauthIssuerUnreachableError: The issuer URL is unreachable or times out.
        """
        self._clear_issuer_statuses()
        if status := self._get_provider_connection_status(provider, ca):
            self.set_status(status, scope="unit")
            if status == OAuthStatuses.ISSUER_UNREACHABLE.value:
                raise OauthIssuerUnreachableError("OAuth issuer is unreachable.")
            return False

        return True

    def remove_oauth(self) -> None:
        """Remove and propagate the OAuth issuer on the leader.

        The leader clears the issuer from application peer databag.
        Config servers withdraw it from all Mongos through the cluster relation.
        Replica sets request an asynchronous rolling restart if the configuration
        has changed.
        Followers will reconcile through peer relation events.

        We allow clean up even if there is a conflict with LDAP,
        because the relation is being removed.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            RollingOpsNoRelationError: A rolling restart is requested before its
                relation is available.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
        """
        if not self.charm.unit.is_leader():
            return

        self.state.app_peer_data.oauth_issuer = None
        self.dependent.cluster_manager.update_oauth_issuer_to_mongos()
        self.restart_replica_set_when_ready()

    def restart_replica_set_when_ready(self) -> None:
        """Request a rolling restart to reconcile the replica set's OAuth configuration.

        Request a rolling restart if configuration has changed.

        Raises:
            RollingOpsNoRelationError: If an async lock is requested too early.
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: Hook checks reject the configuration.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
            OauthIssuerUnreachableError: The issuer URL is unreachable or times out.
            WorkloadServiceError: The workload cannot write or remove the OAuth CA file.
        """
        if not self.state.is_role(MongoDBRoles.REPLICATION):
            return
        file_has_oauth_configuration = self.dependent.config_manager.file_has_oauth_configuration()
        issuer = self.state.app_peer_data.oauth_issuer
        if not issuer and not file_has_oauth_configuration:
            # No need to restart, nothing to clean up
            return

        self._assert_pass_hook_checks()

        if issuer and not self._is_issuer_reachable(issuer, self.state.app_peer_data.oauth_ca):
            raise OauthIssuerUnreachableError("Replica set is unable to reach the issuer.")

        self.reconcile_certificates_in_replica_set()

        if self.dependent.config_manager.config_changed():
            self.dependent.async_restart_charm_services(force=False)

    def _is_issuer_reachable(self, issuer: str, ca: str | None) -> bool:
        """Check if the replica set can reach the issuer stored in the app databag.

        This function assumes that the issuer was already validated by the leader.
        """
        try:
            self._fetch_issuer_discovery(issuer, ca)
        except (requests.RequestException, OSError, ValueError) as e:
            logger.error("The replica set was not able to reach the issuer %s: %s", issuer, e)
            return False
        return True

    def store_certificates(self, certificates: set[str]) -> None:
        """Store and propagate the CA.

        The leader stores the CA in application peer databag.

        Config servers propagate the CA to Mongos through the cluster relation.
        Replica sets request an asynchronous rolling restart if the configuration
        has changed.
        Followers will reconcile through peer relation events.

        Raises:
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
            OauthIssuerUnreachableError: The issuer URL is unreachable or times out.
            DeferrableError: if issuer is unknown.
        """
        if not self.charm.unit.is_leader():
            return
        self._assert_pass_hook_checks()

        if self.state.oauth_relation is None:
            raise DeferrableError("Cannot store certificates without oauth relation.")

        provider = self.oauth_requirer.get_provider_info()
        if not provider:
            raise DeferrableError("Cannot store certificates without provider info.")

        oauth_ca = "\n".join(sorted(certificates))

        if not self._is_valid_provider(provider, oauth_ca):
            return

        self.state.app_peer_data.oauth_issuer = provider.issuer_url
        self.state.app_peer_data.oauth_ca = oauth_ca
        self.dependent.cluster_manager.update_oauth_ca_to_mongos()
        self.dependent.cluster_manager.update_oauth_issuer_to_mongos()
        self.restart_replica_set_when_ready()

    def remove_certificates(self) -> None:
        """Remove and propagate the CA.

        The leader clears the CA from application peer databag.
        Config servers withdraw it from all Mongos through the cluster relation.
        Replica sets request an asynchronous rolling restart if the configuration
        has changed.
        Followers will reconcile through peer relation events.

        We allow clean up even if there is a conflict with LDAP,
        because the relation is being removed.

        Raises:
            RollingOpsNoRelationError: If an async lock is requested too early.
            DeferrableFailedHookChecksError: Preconditions are temporarily unmet.
            NonDeferrableFailedHookChecksError: Hook checks reject the configuration.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
        """
        if not self.charm.unit.is_leader():
            return

        self.state.app_peer_data.oauth_ca = None
        self.dependent.cluster_manager.update_oauth_ca_to_mongos()
        self.restart_replica_set_when_ready()

    def reconcile_certificates_in_replica_set(self) -> None:
        """Reconcile the replica set's oauth CA file using the information from the peer relation.

        Raises:
            WorkloadServiceError: If the workload is not available to write the certificates.
        """
        if not self.state.is_role(MongoDBRoles.REPLICATION):
            return

        workload = self.dependent.workload
        if oauth_ca := self.state.app_peer_data.oauth_ca:
            workload.write(workload.paths.oauth_ca_file, oauth_ca)
        elif workload.exists(workload.paths.oauth_ca_file):
            workload.delete(workload.paths.oauth_ca_file)

    def _update_status(self) -> None:
        """Reconcile the replica set with the current OAuth integration state and report it.

        Raises:
            NonDeferrableFailedHookChecksError: OAuth is integrated with a shard.
            DeferrableFailedHookChecksError: The database is not initialised, Vault
                is degraded, a refresh is in progress, or LDAP setup conflicts with OIDC.
            LdapAndOauthConflictError: LDAP and OIDC are mutual exclusivity is not respected.
            RollingOpsNoRelationError: If an async lock is requested too early.
            OauthIssuerUnreachableError: The issuer URL is unreachable or times out.
        """
        self._assert_pass_hook_checks()

        match self.oauth_state():
            case OAuthState.EMPTY:
                return
            case OAuthState.ACTIVE | OAuthState.REMOVING:
                self.restart_replica_set_when_ready()
                self.set_status(OAuthStatuses.ACTIVE_IDLE.value, scope="both")

            case OAuthState.MISSING_OAUTH_RELATION:
                self.set_status(OAuthStatuses.MISSING_OAUTH_RELATION.value, scope="app")
                return
            case state:
                self.state.statuses.clear(scope="unit", component=self.name)
                if status := self._map_state_to_status(state):
                    self.set_status(status, scope="unit")

    @staticmethod
    def _check_provider_connection(provider: OauthProviderConfig | None, ca: str | None) -> None:
        """Validate HTTPS discovery metadata of the oauth provider.

        Raises:
            OauthProviderDataMissingError: Provider information is missing.
            OauthIssuerTLSError: HTTPS is required or certificate verification failed.
            OauthIssuerUnreachableError: A network failure or retryable HTTP error occurred.
            OauthInvalidDiscoveryError: The URL, response, or metadata is invalid.
        """
        if provider is None or not provider.issuer_url:
            raise OauthProviderDataMissingError("Waiting for OAuth provider information.")

        try:
            if urlsplit(provider.issuer_url).scheme != "https":
                raise OauthIssuerTLSError("The OAuth issuer must use HTTPS.")

            payload = OAuthManager._fetch_issuer_discovery(provider.issuer_url, ca)
            document = json.loads(payload)
            if not OAuthManager._is_valid_discovery(document, provider):
                raise OauthInvalidDiscoveryError("Discovery metadata does not match the provider.")

        except requests.HTTPError as err:
            if 500 <= err.response.status_code < 600:
                raise OauthIssuerUnreachableError(
                    "OAuth issuer is temporarily unavailable."
                ) from err
            raise OauthInvalidDiscoveryError("Discovery request failed.") from err

        except requests.exceptions.SSLError as err:
            raise OauthIssuerTLSError("OAuth issuer certificate verification failed.") from err

        except (requests.exceptions.InvalidURL, ValueError) as err:
            raise OauthInvalidDiscoveryError("Discovery URL or response is invalid.") from err

        except (requests.RequestException, OSError) as err:
            raise OauthIssuerUnreachableError("OAuth issuer is unreachable.") from err

    @staticmethod
    def _get_provider_connection_state(
        provider: OauthProviderConfig | None, ca: str | None
    ) -> OAuthState | None:
        """Translate provider check failures into oauth states."""
        try:
            OAuthManager._check_provider_connection(provider, ca)
        except OauthProviderDataMissingError:
            return OAuthState.WAITING_FOR_PROVIDER_DATA
        except OauthIssuerTLSError:
            return OAuthState.ISSUER_TLS_ERROR
        except OauthIssuerUnreachableError:
            return OAuthState.ISSUER_UNREACHABLE
        except OauthInvalidDiscoveryError:
            return OAuthState.INVALID_DISCOVERY
        return None

    def _get_provider_connection_status(
        self, provider: OauthProviderConfig | None, ca: str | None
    ) -> StatusObject | None:
        """Map provider check failures to a status. Return None on success."""
        state = self._get_provider_connection_state(provider, ca)
        return self._map_state_to_status(state) if state is not None else None

    @staticmethod
    def _fetch_issuer_discovery(issuer: str, ca: str | None) -> bytes:
        """Fetch discovery metadata using a temporary CA bundle when supplied.

        Request errors propagate for callers to interpret. The temporary CA
        file is cleaned up on success and failure.
        """
        discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        if ca:
            with NamedTemporaryFile(mode="w", encoding="utf-8") as bundle:
                bundle.write(ca)
                bundle.flush()
                response = requests.get(discovery_url, verify=bundle.name, timeout=5)
        else:
            response = requests.get(discovery_url, timeout=5)
        response.raise_for_status()
        return response.content

    @staticmethod
    def _is_valid_discovery(document: object, provider: OauthProviderConfig) -> bool:
        """Compare required discovery fields with the corresponding relation fields."""
        if not isinstance(document, dict):
            return False

        for key in ("issuer", "token_endpoint", "jwks_uri"):
            value = document.get(key)
            if not isinstance(value, str) or not value:
                return False

        if document["issuer"] != provider.issuer_url:
            return False
        if document["token_endpoint"] != provider.token_endpoint:
            return False
        if document["jwks_uri"] != provider.jwks_endpoint:
            return False

        return True

    def _is_replica_set_removing(self) -> bool:
        """Whether a shared issuer or local configuration still needs reconciliation."""
        return (
            self.state.is_role(MongoDBRoles.REPLICATION)
            and self.state.app_peer_data.oauth_issuer is None
            and self.dependent.config_manager.file_has_oauth_configuration()
        )

    def oauth_state(self) -> OAuthState:
        """Evaluate OAuth readiness without changing shared or workload configuration."""
        if self.state.is_role(MongoDBRoles.SHARD):
            return OAuthState.WRONG_ROLE

        if not self.state.db_initialised:
            return OAuthState.EMPTY

        oauth_relation = self.state.oauth_relation
        cert_relation = self.state.oauth_cert_relation

        if self._is_replica_set_removing():
            return OAuthState.REMOVING

        if self.state.authentication_conflict:
            return OAuthState.LDAP_CONFLICT

        if oauth_relation is None and cert_relation is None:
            return OAuthState.EMPTY

        if oauth_relation is None and cert_relation:
            return OAuthState.MISSING_OAUTH_RELATION

        issuer = self.state.app_peer_data.oauth_issuer
        if not issuer:
            return OAuthState.WAITING_FOR_PROVIDER_DATA

        provider = self.oauth_requirer.get_provider_info()
        ca = self.state.app_peer_data.oauth_ca
        if state := OAuthManager._get_provider_connection_state(provider, ca):
            return state

        return OAuthState.ACTIVE

    @staticmethod
    def _map_state_to_status(state: OAuthState) -> StatusObject | None:
        """Maps a OAuth integration state to a list of status objects."""
        match state:
            case OAuthState.EMPTY | OAuthState.REMOVING | OAuthState.LDAP_CONFLICT:
                return None
            case OAuthState.WRONG_ROLE:
                return OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value
            case OAuthState.MISSING_OAUTH_RELATION:
                return OAuthStatuses.MISSING_OAUTH_RELATION.value
            case OAuthState.WAITING_FOR_PROVIDER_DATA:
                return OAuthStatuses.WAITING_FOR_OAUTH_DATA.value
            case OAuthState.INVALID_DISCOVERY:
                return OAuthStatuses.INVALID_DISCOVERY.value
            case OAuthState.ISSUER_TLS_ERROR:
                return OAuthStatuses.ISSUER_TLS_ERROR.value
            case OAuthState.ISSUER_UNREACHABLE:
                return OAuthStatuses.ISSUER_UNREACHABLE.value
            case OAuthState.ACTIVE:
                return OAuthStatuses.ACTIVE_IDLE.value

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Report the oauth status."""
        if self.state.authentication_conflict:
            return []
        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        charm_statuses: dict[Scope, list[StatusObject]] = {"app": [], "unit": []}
        state = self.oauth_state()
        status = self._map_state_to_status(state)

        if status is None:
            return charm_statuses[scope]

        match state:
            case OAuthState.WRONG_ROLE | OAuthState.MISSING_OAUTH_RELATION:
                charm_statuses["app"].append(status)

            case _:
                charm_statuses["unit"].append(status)
        return charm_statuses[scope]

    def set_status(self, status: StatusObject, scope: Literal["both"] | Scope) -> None:
        """Sets a status for scope app or unit, or both."""
        if scope == "unit" or scope == "both":
            self.state.statuses.set(status, component=self.name, scope="unit")
        if not self.charm.model.unit.is_leader():
            return
        if scope == "app" or scope == "both":
            self.state.statuses.set(status, component=self.name, scope="app")

    def _clear_issuer_statuses(self) -> None:
        """Clear previous issuer connection and discovery errors."""
        for status in (
            OAuthStatuses.WAITING_FOR_OAUTH_DATA,
            OAuthStatuses.ISSUER_TLS_ERROR,
            OAuthStatuses.ISSUER_UNREACHABLE,
            OAuthStatuses.INVALID_DISCOVERY,
        ):
            self.state.statuses.delete(status.value, scope="unit", component=self.name)
