# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Configuration for MongoDB Charm."""

from enum import Enum


class PeerRelationNames(str, Enum):
    """The peer relation names."""

    PEERS = "database-peers"
    ROUTER_PEERS = "router-peers"
    STATUS_PEERS = "status-peers"
    LDAP_PEERS = "ldap-peers"


class RelationNames(str, Enum):
    """The different relations."""

    DATABASE = "database"
    SHARDING = "sharding"
    CONFIG_SERVER = "config-server"
    CLUSTER = "cluster"
    MONGOS_PROXY = "mongos_proxy"
    UPGRADE_VERSION = "upgrade-version-a"


class Scopes(str, Enum):
    """The two scopes."""

    APP_SCOPE = "app"
    UNIT_SCOPE = "unit"


class ExternalRequirerRelations(str, Enum):
    """The relations we require externally."""

    TLS = "certificates"
    S3_CREDENTIALS = "s3-credentials"
    LDAP = "ldap"
    LDAP_CERT = "ldap-certificate-transfer"


class ExternalProviderRelations(str, Enum):
    """The relations we provide to non mongo related charms."""

    LOGGING = "logging"  # This is used for mongodb k8s charms
