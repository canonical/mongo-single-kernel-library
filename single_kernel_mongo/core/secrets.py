# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Secrets related helper classes/functions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops import Secret, SecretInfo
from ops.charm import CharmBase
from ops.model import ModelError, SecretNotFoundError

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.exceptions import SecretAlreadyExistsError

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
SECRET_DELETED_LABEL = "None"

logger = logging.getLogger(__name__)


def generate_secret_label(app_name: str, scope: Scope, relation: str | None = None) -> str:
    """Generate unique group_mappings for secrets within a relation context.

    Defined as a standalone function, as the choice on secret labels definition belongs to the
    Application Logic. To be kept separate from classes below, which are simply to provide a
    (smart) abstraction layer above Juju Secrets.
    """
    members = [app_name, scope.value]
    if relation:
        members = [relation, app_name, scope.value]
    return f"{'.'.join(members)}"


# Secret cache


class CachedSecret:
    """Abstraction layer above direct Juju access with caching.

    The data structure is precisely reusing/simulating Juju Secrets behavior, while
    also making sure not to fetch a secret multiple times within the same event scope.
    """

    def __init__(self, charm: CharmBase, label: str, secret_uri: str | None = None):
        self._secret_meta: Secret | None = None
        self._secret_content: dict = {}
        self._secret_uri = secret_uri
        self.label = label
        self.charm = charm

    def add_secret(self, content: dict[str, str], scope: Scope) -> Secret:
        """Create a new secret."""
        if self._secret_uri:
            raise SecretAlreadyExistsError(
                "Secret is already defined with uri %s", self._secret_uri
            )

        if scope == Scope.APP:
            secret = self.charm.app.add_secret(content, label=self.label)
        else:
            secret = self.charm.unit.add_secret(content, label=self.label)
        self._secret_uri = secret.id
        self._secret_meta = secret
        return self._secret_meta

    @property
    def meta(self) -> Secret | None:
        """Getting cached secret meta-information."""
        if self._secret_meta:
            return self._secret_meta

        if not (self._secret_uri or self.label):
            return None

        try:
            self._secret_meta = self.charm.model.get_secret(label=self.label)
        except SecretNotFoundError:
            if self._secret_uri:
                self._secret_meta = self.charm.model.get_secret(
                    id=self._secret_uri, label=self.label
                )
        return self._secret_meta

    def get_content(self) -> dict[str, str]:
        """Getting cached secret content."""
        if not self._secret_content:
            if self.meta:
                try:
                    self._secret_content = self.meta.get_content(refresh=True)
                except (ValueError, ModelError) as err:
                    # https://bugs.launchpad.net/juju/+bug/2042596
                    # Only triggered when 'refresh' is set
                    known_model_errors = [
                        "ERROR either URI or label should be used for getting an owned secret but not both",
                        "ERROR secret owner cannot use --refresh",
                    ]
                    if isinstance(err, ModelError) and not any(
                        msg in str(err) for msg in known_model_errors
                    ):
                        raise
                    # Due to: ValueError: Secret owner cannot use refresh=True
                    self._secret_content = self.meta.get_content()
        return self._secret_content

    def set_content(self, content: dict[str, str]) -> None:
        """Setting cached secret content."""
        if self.meta:
            self.meta.set_content(content)
            self._secret_content = content

    def get_info(self) -> SecretInfo | None:
        """Wrapper function for get the corresponding call on the Secret object if any."""
        if self.meta:
            return self.meta.get_info()
        return None


class SecretCache:
    """A data structure storing CachedSecret objects."""

    def __init__(self, charm: AbstractMongoCharm, relation: str | None = None):
        self.charm = charm
        self.relation = relation
        self._secrets: dict[str, CachedSecret] = {}

    def get(self, scope: Scope, uri: str | None = None) -> CachedSecret | None:
        """Getting a secret from Juju Secret store or cache."""
        label = generate_secret_label(self.charm.app.name, scope, self.relation)
        if not self._secrets.get(label):
            secret = CachedSecret(self.charm, label, uri)
            if secret.meta:
                self._secrets[label] = secret
        return self._secrets.get(label)

    def get_for_key(self, scope: Scope, key: str, uri: str | None = None) -> str | None:
        """Get this key in the secret."""
        secret = self.get(scope, uri)
        if not secret:
            return None
        value = secret.get_content().get(key)
        if value != SECRET_DELETED_LABEL:
            return value
        return None

    def add(self, content: dict[str, str], scope: Scope) -> CachedSecret:
        """Adding a secret to Juju Secret."""
        label = generate_secret_label(self.charm.app.name, scope, self.relation)
        if self._secrets.get(label):
            raise SecretAlreadyExistsError(f"Secret {label} already exists")

        secret = CachedSecret(self.charm, label)
        secret.add_secret(content, scope)
        self._secrets[label] = secret
        return self._secrets[label]

    def set(self, key: str, content: str, scope: Scope) -> CachedSecret:
        """Set or Add secret."""
        secret = self.get(scope)
        if not secret:
            return self.add({key: content}, scope)
        secret_content = secret.get_content()
        secret_content.update({key: content})
        secret.set_content(secret_content)
        return secret

    def remove(self, scope: Scope, key: str) -> None:
        """Removing a secret."""
        secret = self.get(scope)

        if not secret:
            return

        content = secret.get_content()

        if not content.get(key) or content[key] == SECRET_DELETED_LABEL:
            logger.error(f"Non-existing secret {scope}:{key} was attempted to be removed.")
            return

        content[key] = SECRET_DELETED_LABEL
        secret.set_content(content)


# END: Secret cache
