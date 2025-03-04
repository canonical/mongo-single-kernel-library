#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""File containing all possible statuses for Mongo* charms.

TODO (Future PR(s)):
- Add all statuses here
- Update to be consistent with the spec

Note: The structure of this file is subject to change, as the implementation spec is still in
progress. However the idea that all statuses belong in one file holds true regardless of the spec.
"""

from enum import Enum

from ops.model import BlockedStatus, WaitingStatus


class MongoDB(Enum):
    """MongoDB related statuses.

    TODO: add the remaining statuses for mongodb charm.
    """

    MONGODB_NOT_STARTED = WaitingStatus("Waiting to start mongod...")
    EXPORTER_NOT_STARTED = WaitingStatus("Waiting to start mongodb-exporter...")
    SHARDING_ON_REPLICA = BlockedStatus("sharding interface cannot be used by replicas")
    UNSUPPORTED_MONGOS_REL = BlockedStatus(
        "Relation to mongos not supported, config role must be config-server"
    )
    INVALID_S3_INTEGRATION_STATUS = BlockedStatus(
        "Relation to s3-integrator is not supported, config role must be config-server."
    )


class Mongos(Enum):
    """Mongos related statuses.

    TODO: add the remaining statuses for mongos charm.
    """

    ...


class CharmStatuses(Enum):
    """Charm Statuses.

    TODO: add remaining statuses related to the two charms.
    """

    MONGODB_NOT_INSTALLED = BlockedStatus("MongoDB not installed")
    mongodb = MongoDB
    mongos = Mongos


class BackupStatuses(Enum):
    """Backup manager related statuses.

    TODO: add the remaining statuses for backup manager.
    """

    # note unlike other daemons (exporter and mongod) this status belongs to the backup manager
    # since certain configurations are required for pbm to be active and running.
    PBM_NOT_STARTED = WaitingStatus("waiting for pbm to start")
    PBM_MISSING_CONFIGS = BlockedStatus("s3 configurations missing.")
    PBM_INCORRECT_CREDS = BlockedStatus("s3 credentials are incorrect.")
    PBM_INCOMPATIBLE_CONF = BlockedStatus("s3 configurations are incompatible.")
    UNKNOWN_PBM_ERROR = BlockedStatus("Unknown PBM error, check logs")
