# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Literal string for the different charms.

This module should contain the literals used in the charms (paths, enums, etc).
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Generic, TypeVar

LOCALHOST = "127.0.0.1"


class Substrates(str, Enum):
    """Possible substrates."""

    VM = "vm"
    K8S = "k8s"


class KindEnum(str, Enum):
    """The two possible role names."""

    MONGOD = "mongod"
    MONGOS = "mongos"


class Scope(str, Enum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"


class MongoPorts(int, Enum):
    """The default Mongo ports."""

    MONGODB_PORT = 27017
    MONGOS_PORT = 27018


class InternalUsers(str, Enum):
    """The three allowed internal users."""

    OPERATOR = "operator"
    BACKUP = "backup"
    MONITOR = "monitor"


SECRETS_APP = [f"{user}-password" for user in InternalUsers] + ["keyfile"]


@dataclass(frozen=True)
class Snap:
    """The Snap related information."""

    name: str = "charmed-mongodb"
    channel: str = "6/edge"
    revision: str = "123"


SNAP = Snap(channel="6/edge/use-snap-config-for-services", revision="124")

T = TypeVar("T", bound=str | int)


@dataclass(frozen=True)
class WorkloadUser(Generic[T]):
    """The system users for a workload."""

    user: T
    group: T


@dataclass(frozen=True)
class KubernetesUser(WorkloadUser[str]):
    """The system user for kubernetes pods."""

    user: str = "mongodb"
    group: str = "mongodb"


@dataclass(frozen=True)
class VmUser(WorkloadUser[int]):
    """The system users for vm workloads."""

    user: int = 584788
    group: int = 0


CRON_FILE = Path("/etc/cron.d/mongodb")
ENVIRONMENT_FILE = Path("/etc/environment")

SECRETS_UNIT: list[str] = []

MAX_PASSWORD_LENGTH = 4096
