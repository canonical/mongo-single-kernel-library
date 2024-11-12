# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Configuration for MongoDB Charm."""

from enum import Enum


class RelationNames(str, Enum):
    """The different relations."""

    NAME = "database"
    PEERS = "database-peers"
    SHARDING_RELATIONS_NAME = "sharding"
    CONFIG_SERVER_RELATIONS_NAME = "config-server"
    CLUSTER_RELATIONS_NAME = "cluster"


class Scopes(str, Enum):
    """The two scopes."""

    APP_SCOPE = "app"
    UNIT_SCOPE = "unit"


class RequirerRelations(str, Enum):
    """The relations we require externally."""

    TLS = "certificates"
    S3_CREDENTIALS = "s3-credentials"
