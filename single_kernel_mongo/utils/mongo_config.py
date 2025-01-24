# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Code for interactions with MongoDB."""

from dataclasses import dataclass
from itertools import chain
from urllib.parse import quote_plus, urlencode

from single_kernel_mongo.config.literals import MongoPorts
from single_kernel_mongo.exceptions import AmbiguousConfigError
from single_kernel_mongo.utils.mongodb_users import (
    REGULAR_ROLES,
    DBPrivilege,
    UserRole,
)

ADMIN_AUTH_SOURCE = {"authSource": "admin"}


@dataclass
class MongoConfiguration:
    """Class for Mongo configurations usable my mongos and mongodb.

    — replset: name of replica set
    — database: database name.
    — username: username.
    — password: password.
    — hosts: full list of hosts to connect to, needed for the URI.
    — tls_external: indicator for use of internal TLS connection.
    — tls_internal: indicator for use of external TLS connection.
    """

    database: str
    username: str
    password: str
    hosts: set[str]
    roles: set[str]
    tls_external: bool
    tls_internal: bool
    port: int | None = None
    replset: str | None = None
    standalone: bool = False

    @property
    def formatted_hosts(self) -> set[str]:
        """The formatted list of hosts."""
        if self.port:
            return {f"{host}:{self.port}" for host in self.hosts}
        return self.hosts

    @property
    def formatted_replset(self) -> dict:
        """Formatted replicaSet parameter."""
        if self.replset:
            return {"replicaSet": quote_plus(self.replset)}
        return {}

    @property
    def formatted_auth_source(self) -> dict:
        """Formatted auth source."""
        if self.database != "admin":
            return ADMIN_AUTH_SOURCE
        return {}

    @property
    def uri(self) -> str:
        """Return URI concatenated from fields."""
        if self.port == MongoPorts.MONGOS_PORT and self.replset:
            raise AmbiguousConfigError("Mongos cannot support replica set")

        if self.standalone and not self.port:
            raise AmbiguousConfigError("Standalone connection needs a port")

        if self.standalone:
            return (
                f"mongodb://{quote_plus(self.username)}:"
                f"{quote_plus(self.password)}@"
                f"localhost:{self.port}/?authSource=admin"
            )

        complete_hosts = ",".join(sorted(self.formatted_hosts))
        replset = self.formatted_replset
        auth_source = self.formatted_auth_source

        # Dict of all parameters.
        parameters = replset | auth_source

        return (
            f"mongodb://{quote_plus(self.username)}:"
            f"{quote_plus(self.password)}@"
            f"{complete_hosts}/{quote_plus(self.database)}?"
            f"{urlencode(parameters)}"
        )

    @property
    def supported_roles(self) -> list[DBPrivilege]:
        """The supported roles for this configuration."""
        default_role = UserRole(
            [
                DBPrivilege(role="readWrite", db=self.database),
                DBPrivilege(role="enableSharding", db=self.database),
            ]
        )
        all_roles = REGULAR_ROLES | {"default": default_role}
        return list(chain.from_iterable(all_roles[role] for role in self.roles))


EMPTY_CONFIGURATION = MongoConfiguration(
    "",
    "",
    "",
    set(),
    set(),
    False,
    False,
)
