# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Literal string for the different charms."""

from dataclasses import dataclass
from enum import Enum
from typing import Literal

Substrates = Literal["vm", "k8s"]


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


@dataclass
class SnapPackage:
    """The definition of a snap."""

    name: str
    track: str
    revision: int


@dataclass
class Snap:
    """The Snap related information."""

    user: int = 584788
    package: SnapPackage = SnapPackage("charmed-mongodb", "6/edge", 123)
