# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Code for interactions with MongoDB."""

from dataclasses import dataclass, field
from itertools import chain
from pathlib import Path
from urllib.parse import quote_plus, urlencode

from single_kernel_mongo.config.literals import MongoPorts
from single_kernel_mongo.exceptions import AmbiguousConfigError
from single_kernel_mongo.utils.mongodb_users import (
    REGULAR_ROLES,
    AuthRestrictions,
    DBPrivilege,
    UserRole,
)

ADMIN_AUTH_SOURCE = {"authSource": "admin"}


@dataclass
class MongoConfiguration:
    """Class for Mongo configurations usable my mongos and mongodb.

    Args:
        replset: name of replica set
        database: database name.
        username: username.
        password: password.
        hosts: full set of hosts to connect to, needed for the URI.
        roles: set of roles for that user.
        tls_enabled: Is TLS enabled on that configuration?
        tls_external_ca: The path of the tls external CA certificate
        port: The port used to connect
        replset: The replica set we connect to
        standalone: Should that be a standalone connection ?
        auth_restrictions: The list of authentication restrictions for that user
    """

    database: str
    username: str
    password: str
    hosts: set[str]
    roles: set[str]
    tls_enabled: bool
    tls_external_ca: Path = Path("")
    port: int | None = None
    replset: str | None = None
    standalone: bool = False
    auth_restrictions: list[AuthRestrictions] = field(default_factory=list)

    @property
    def formatted_hosts(self) -> set[str]:
        """The formatted list of hosts."""
        if self.port:
            return {f"{host}:{self.port}" for host in self.hosts}
        return self.hosts

    @property
    def formatted_replset(self) -> dict[str, str]:
        """Formatted replicaSet parameter."""
        if self.replset:
            return {"replicaSet": quote_plus(self.replset)}
        return {}

    @property
    def formatted_auth_source(self) -> dict[str, str]:
        """Formatted auth source."""
        result = {"authMechanism": "SCRAM-SHA-256"}
        if self.database != "admin":
            result |= ADMIN_AUTH_SOURCE
        return result

    @property
    def tls_config(self) -> dict[str, str]:
        """TLS Config."""
        if not self.tls_enabled:
            return {}
        config = {
            "tls": "true",
            "tlsCaFile": f"{self.tls_external_ca}",
        }
        # Edge case: MongoDB TLS with Unix Socket requires disabling client hostname verification.
        # This is because the reported remote is the unix socket, which is not in the SANS list.
        if len(self.hosts) == 1 and list(self.hosts)[0].endswith("27018.sock"):
            config["tlsAllowInvalidHostnames"] = "true"

        return config

    def _uri(self, tls: bool):
        if self.port == MongoPorts.MONGOS_PORT and self.replset:
            raise AmbiguousConfigError("Mongos cannot support replica set")

        if self.standalone and not self.port:
            raise AmbiguousConfigError("Standalone connection needs a port")

        tls_config = self.tls_config if tls else {}
        auth_source = self.formatted_auth_source

        if self.standalone:
            return (
                f"mongodb://{quote_plus(self.username)}:"
                f"{quote_plus(self.password)}@"
                f"localhost:{self.port}/?{urlencode(auth_source | tls_config)}"
            )

        complete_hosts = ",".join(sorted(self.formatted_hosts))
        replset = self.formatted_replset

        # Dict of all parameters.
        parameters = replset | auth_source | tls_config

        return (
            f"mongodb://{quote_plus(self.username)}:"
            f"{quote_plus(self.password)}@"
            f"{complete_hosts}/{quote_plus(self.database)}?"
            f"{urlencode(parameters)}"
        )

    @property
    def uri(self) -> str:
        """Return URI concatenated from fields."""
        return self._uri(tls=True)

    @property
    def uri_without_tls(self) -> str:
        """Return URI concatenated from fields without tls params."""
        return self._uri(tls=False)

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
    database="",
    username="",
    password="",  # nosec: B106
    hosts=set(),
    roles=set(),
    tls_enabled=False,
    tls_external_ca=Path(""),
)
