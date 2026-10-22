#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for the OAuth integration."""

from __future__ import annotations

import json
import ssl
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from charmlibs.interfaces.certificate_transfer import CertificateTransferRequires
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
    WorkloadServiceError,
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

        self.certificate_transfer = CertificateTransferRequires(
            self.charm, ExternalRequirerRelations.OAUTH_CERT.value
        )

    def store_certificates(self, certificates: set[str]) -> None:
        """Write the CA bundle on replica sets or share it with mongos from a config server."""
        self.assert_pass_hook_checks()
        if not certificates:
            self.remove_certificates()
            return
        bundle = "\n".join(sorted(certificates))
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            if self.charm.unit.is_leader():
                self.dependent.cluster_manager.update_oauth_ca_to_mongos(bundle)  # type: ignore[attr-defined]
        elif self.state.is_role(MongoDBRoles.REPLICATION):
            self.dependent.workload.write(self.dependent.workload.paths.oauth_ca_file, bundle)
        else:
            return
        provider = self.oauth_requirer.get_provider_info()
        if provider and not self._validate_and_store_issuer(provider.issuer_url):
            return
        self.restart_when_ready()

    def remove_certificates(self) -> None:
        """Remove the CA bundle locally or withdraw it from mongos relations."""
        self.assert_pass_hook_checks()
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            if self.charm.unit.is_leader():
                self.dependent.cluster_manager.update_oauth_ca_to_mongos("")  # type: ignore[attr-defined]
            return
        if not self.state.is_role(MongoDBRoles.REPLICATION):
            return
        workload = self.dependent.workload
        if workload.exists(workload.paths.oauth_ca_file):
            workload.delete(workload.paths.oauth_ca_file)
        self.restart_when_ready()

    def check_issuer_connection(self, issuer: str) -> StatusObject | None:
        """Verify HTTPS discovery metadata against the OAuth relation."""
        try:
            endpoint = urlsplit(issuer)
            if endpoint.scheme != "https" or not endpoint.hostname:
                return OAuthStatuses.ISSUER_TLS_ERROR.value
            context = self._issuer_ssl_context()
            discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
            with urlopen(discovery_url, context=context, timeout=5) as response:
                document = json.load(response)
            return self._discovery_status(document, issuer)
        except (json.JSONDecodeError, UnicodeDecodeError, HTTPError):
            return OAuthStatuses.INVALID_DISCOVERY.value
        except URLError as err:
            if isinstance(err.reason, ssl.SSLError):
                return OAuthStatuses.ISSUER_TLS_ERROR.value
            return OAuthStatuses.ISSUER_UNREACHABLE.value
        except (ssl.SSLError, ValueError):
            return OAuthStatuses.ISSUER_TLS_ERROR.value
        except (OSError, WorkloadServiceError):
            return OAuthStatuses.ISSUER_UNREACHABLE.value

    def _discovery_status(self, document: object, issuer: str) -> StatusObject | None:
        """Compare required discovery fields with the corresponding relation fields."""
        if not isinstance(document, dict):
            return OAuthStatuses.INVALID_DISCOVERY.value
        expected = {"issuer": issuer}
        if provider := self.oauth_requirer.get_provider_info():
            expected.update(token_endpoint=provider.token_endpoint, jwks_uri=provider.jwks_endpoint)
        if any(
            not isinstance(document.get(key), str) or not document[key]
            for key in ("issuer", "token_endpoint", "jwks_uri")
        ):
            return OAuthStatuses.INVALID_DISCOVERY.value
        if any(document[key] != value for key, value in expected.items()):
            return OAuthStatuses.INVALID_DISCOVERY.value
        return None

    def _issuer_ssl_context(self) -> ssl.SSLContext:
        """Use transferred CA certificates when available, or system trust otherwise."""
        workload = self.dependent.workload
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            ca = "\n".join(sorted(self.certificate_transfer.get_all_certificates()))
        elif workload.exists(workload.paths.oauth_ca_file):
            ca = "\n".join(workload.read(workload.paths.oauth_ca_file))
        else:
            ca = ""
        return ssl.create_default_context(cadata=ca) if ca else ssl.create_default_context()

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
        if self._validate_and_store_issuer(provider.issuer_url):
            self.restart_when_ready()

    def _validate_and_store_issuer(self, issuer: str) -> bool:
        """Validate the issuer and store/share it only after successful validation."""
        self._clear_issuer_statuses()
        if status := self.check_issuer_connection(issuer):
            self.state.statuses.add(status, scope="unit", component=self.name)
            return False
        if self.charm.unit.is_leader():
            self.state.app_peer_data.oauth_issuer = issuer
            if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
                self.dependent.cluster_manager.update_oauth_issuer_to_mongos()  # type: ignore[attr-defined]
        return True

    def _clear_issuer_statuses(self) -> None:
        """Clear previous issuer connection and discovery errors."""
        for status in (
            OAuthStatuses.ISSUER_TLS_ERROR,
            OAuthStatuses.ISSUER_UNREACHABLE,
            OAuthStatuses.INVALID_DISCOVERY,
        ):
            self.state.statuses.delete(status.value, scope="unit", component=self.name)

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
            DeferrableFailedHookChecksError: If the unit is not ready to restart.
            NonDeferrableFailedHookChecksError: If OAuth is integrated with a shard.
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
        """Report integration conflicts, unsupported roles, and issuer discovery failures."""
        if scope == "unit" and self.state.authentication_conflict:
            return [AuthStatuses.LDAP_OAUTH_CONFLICT.value]
        if not recompute:
            return [
                status
                for status in self.state.statuses.get(scope=scope, component=self.name).root
                if status != AuthStatuses.LDAP_OAUTH_CONFLICT.value
            ]
        if scope == "app":
            return []
        if self.state.is_role(MongoDBRoles.SHARD) and self.model.relations.get(self.name, []):
            return [OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value]
        provider = self.oauth_requirer.get_provider_info()
        issuer = provider.issuer_url if provider else self.state.app_peer_data.oauth_issuer
        if issuer and (status := self.check_issuer_connection(issuer)):
            return [status]
        return []
