# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Literal string for the different charms.

This module should contain the literals used in the charms (paths, enums, etc).
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Generic, TypeVar

from ops.model import BlockedStatus, WaitingStatus

LOCALHOST = "127.0.0.1"


class Substrates(str, Enum):
    """Possible substrates."""

    K8S = "k8s"
    VM = "vm"


class CharmKind(str, Enum):
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


class UnitState(str, Enum):
    """Unit upgrade state."""

    HEALTHY = "healthy"
    RESTARTING = "restarting"  # Kubernetes only
    UPGRADING = "upgrading"  # Machines only
    OUTDATED = "outdated"  # Machines only


SECRETS_APP = [f"{user}-password" for user in InternalUsers] + ["keyfile"]


@dataclass(frozen=True)
class Snap:
    """The Snap related information."""

    name: str = "charmed-mongodb"
    channel: str = "6/edge"
    revision: str = "129"


SNAP = Snap(channel="6/edge", revision="129")

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
    """The system users for vm workloads, this user corresponds to the snap user."""

    user: int = 584788
    group: int = 0


CRON_FILE = Path("/etc/cron.d/mongodb")


SECRETS_UNIT: list[str] = []

MAX_PASSWORD_LENGTH = 4096

PBM_RESTART_DELAY = 5

FEATURE_VERSION_6 = "6.0"

UNHEALTHY_UPGRADE = BlockedStatus("Unhealthy after refresh.")
INCOMPATIBLE_UPGRADE = BlockedStatus(
    "Refresh incompatible. Rollback to previous revision with `juju refresh`"
)
WAITING_POST_UPGRADE_STATUS = WaitingStatus("Waiting for post upgrade checks")

OS_REQUIREMENTS = {
    "vm.max_map_count": "262144",
}

TRUST_STORE_PATH = Path("/usr/local/share/ca-certificates")


class TrustStoreFiles(str, Enum):
    """The different files we store in the trust store."""

    PBM = "pbm.crt"
