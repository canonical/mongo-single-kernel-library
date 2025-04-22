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

from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    StatusBase,
    WaitingStatus,
)


class MongoDBStatuses(Enum):
    """MongoDB related statuses."""

    # STATE statuses:
    MONGODB_NOT_STARTED = WaitingStatus("Waiting to start mongod...")
    EXPORTER_NOT_STARTED = WaitingStatus("Waiting to start mongodb-exporter...")
    SHARDING_ON_REPLICA = BlockedStatus("Sharding interface cannot be used by replicas.")
    UNSUPPORTED_MONGOS_REL = BlockedStatus(
        "Relation to mongos not supported, config role must be config-server."
    )
    INVALID_S3_INTEGRATION_STATUS = BlockedStatus(
        "Relation to s3-integrator is not supported, config role must be config-server."
    )

    DB_REl_ON_SHARD = BlockedStatus("Sharding roles do not support database interface.")

    # RUNNING statuses:
    STARTING_MONGODB = MaintenanceStatus("Starting MongoDB.")


class MongosStatuses(Enum):
    """Mongos related statuses."""

    INVALD_EXPOSE_EXTERNAL = BlockedStatus("Config option for expose-external not valid.")
    NEED_CONF_SERVER = BlockedStatus("Missing relation to config-server.")
    CONNECTING_TO_CONFIG_SERVER = WaitingStatus("Connecting to config-server...")
    WAITING_FOR_SECRETS = WaitingStatus("Waiting for secrets from config-server")
    REQUIRES_TLS = BlockedStatus("mongos requires TLS to be enabled.")
    REQUIRES_NO_TLS = BlockedStatus("mongos has TLS enabled, but config-server does not.")
    CA_MISMATCH = BlockedStatus("mongos CA and Config-Server CA don't match.")

    # Running statuses:
    STARTING_MONGOS = MaintenanceStatus("Starting mongos.")


class CharmStatuses(Enum):
    """Charm Statuses."""

    ACTIVE_IDLE = ActiveStatus()
    MONGODB_NOT_INSTALLED = BlockedStatus("MongoDB not installed.")
    MONGODB_INSTALLED = MaintenanceStatus("Installed MongoDB")
    MONGOS_NOT_STARTED = WaitingStatus("Waiting to start mongos...")
    FAILED_TO_INSTALL = BlockedStatus("couldn't install MongoDB")
    mongodb = MongoDBStatuses
    mongos = MongosStatuses

    # RUNNING Statuses
    INSTALLING_MONGODB = MaintenanceStatus("installing MongoDB")


class TLSStatuses(Enum):
    """TLS statuses."""

    ACTIVE_IDLE = ActiveStatus()

    # RUNNING statuses:
    DISABLING_TLS = MaintenanceStatus("Disabling TLS...")
    ENABLING_TLS = MaintenanceStatus("Enabling TLS...")


class BackupStatuses(Enum):
    """Backup manager related statuses."""

    # note unlike other daemons (exporter and mongod) this status belongs to the backup manager
    # since certain configurations are required for pbm to be active and running.
    PBM_NOT_STARTED = WaitingStatus("Waiting for pbm to start...")
    PBM_MISSING_CONFIGS = BlockedStatus("s3 configurations missing.")
    PBM_INCORRECT_CREDS = BlockedStatus("s3 credentials are incorrect.")
    PBM_INCOMPATIBLE_CONF = BlockedStatus("s3 configurations are incompatible.")
    UNKNOWN_PBM_ERROR = BlockedStatus("Unknown PBM error, check logs.")
    CANT_CONFIGURE = BlockedStatus("Couldn't configure s3 backup options.")
    PBM_WAITING_TO_SYNC = WaitingStatus("Waiting to sync s3 configurations...")
    ACTIVE_IDLE = ActiveStatus()

    @staticmethod
    def backup_running(backup_id: str) -> StatusBase:
        """Returns backup starting status based on id."""
        return MaintenanceStatus(f"Backup started/running, backup id: '{backup_id}'")

    @staticmethod
    def restore_running(backup_id: str) -> StatusBase:
        """Returns restore starting status based on id."""
        return MaintenanceStatus(f"Restore started/running, backup id: '{backup_id}'")


class ConfigServerStatuses(Enum):
    """Config server statuses."""

    # todo consider this status to be put in charm
    MONGOS_NOT_RUNNING = BlockedStatus("Internal mongos is not running.")
    NEED_SHARDS = BlockedStatus("Missing relation to shard(s).")
    SYNCING_PASSWORDS = WaitingStatus("Waiting to sync passwords across the cluster...")
    ACTIVE_IDLE = ActiveStatus()

    @staticmethod
    def adding_shard(shard: str) -> StatusBase:
        """Returns add shard status."""
        return MaintenanceStatus(f"Adding shard {shard} to config-server.")

    @staticmethod
    def draining_shard(shard: str) -> StatusBase:
        """Returns draining shard status based on shard."""
        return MaintenanceStatus(f"Draining shard {shard}")

    @staticmethod
    def unreachable_shards(unreachable_shards: list[str]) -> StatusBase:
        """Returns unreachable shard status based on list."""
        unreachable = ", ".join(unreachable_shards)
        return BlockedStatus(f"Shards: {unreachable} are unreachable.")

    @staticmethod
    def waiting_for_shard_upgrade(current_charms_version: str, local_identifier: str) -> StatusBase:
        """Returns waiting for shard upgrade status."""
        return WaitingStatus(
            f"Waiting for shards to upgrade/downgrade to revision {current_charms_version}{local_identifier}."
        )


class ShardStatuses(Enum):
    """Shard statuses."""

    REQUIRES_TLS = BlockedStatus("Shard requires TLS to be enabled.")
    REQUIRES_NO_TLS = BlockedStatus("Shard has TLS enabled, but config-server does not.")
    CA_MISMATCH = BlockedStatus("Shard CA and Config-Server CA don't match.")

    NEED_CONF_SERVER = BlockedStatus("Missing relation to config-server.")
    SHARD_DRAINED = ActiveStatus("Shard drained from cluster, ready for removal.")
    FAILED_TO_DRAIN = BlockedStatus("Failed to drain shard from cluster")
    WAITING_TO_REMOVE = WaitingStatus("Waiting for config-server to remove shard")
    SYNCING_PASSWORDS = WaitingStatus("Waiting to sync passwords across the cluster...")
    ADDING_TO_CLUSTER = MaintenanceStatus("Adding shard to config-server")
    SHARD_NOT_AWARE = BlockedStatus("Shard is not yet shard aware.")
    ACTIVE_IDLE = ActiveStatus()

    # RUNNING status:
    DRAINING_SHARD = MaintenanceStatus("Draining shard from cluster...")

    @staticmethod
    def shard_needs_upgrade(
        current_charms_version: str,
        local_identifier: str,
        config_server_revision: str,
        remote_local_identifier: str,
    ) -> StatusBase:
        """Returns needs shard upgrade status."""
        return BlockedStatus(
            f"Charm revision ({current_charms_version}{local_identifier}) is not up-to date with config-server ({config_server_revision}{remote_local_identifier})."
        )

    @staticmethod
    def older_version_shard_needs_upgrade(
        current_charms_version: str,
        local_identifier: str,
    ) -> StatusBase:
        """Returns needs shard upgrade status."""
        return BlockedStatus(
            f"Charm revision ({current_charms_version}{local_identifier}) is not up-to date with config-server."
        )


class MongodStatuses(Enum):
    """MongoD statuses."""

    WAITING_REPL_SET_INIT = WaitingStatus("Waiting for replica set initialisation...")
    WAITING_RECONFIG = WaitingStatus("Waiting to reconfigure replica set...")
    WAITING_ELECTION = WaitingStatus("Waiting for primary re-election...")
    WAITING_RECONNECT = WaitingStatus("Waiting to reconnect to unit...")
    MEMBER_BEING_ADDED = WaitingStatus("Member being added...")
    MEMBER_REMOVING = WaitingStatus("Member is removing...")
    MEMBER_SYNCING = WaitingStatus("Member is syncing...")
    PRIMARY = ActiveStatus("Primary.")
    SECONDARY = ActiveStatus()


class UpgradeStatuses(Enum):
    """Upgrade statuses."""

    UNHEALTHY_UPGRADE = BlockedStatus("Unhealthy after refresh.")
    INCOMPATIBLE_UPGRADE = BlockedStatus(
        "Refresh incompatible. Rollback to previous revision with `juju refresh`"
    )
    ACTIVE_IDLE = ActiveStatus()
    WAITING_POST_UPGRADE_STATUS = WaitingStatus("Waiting for post upgrade checks...")
    REFRESH_IN_PROG = MaintenanceStatus(
        "Refreshing. To rollback, `juju refresh` to the previous revision"
    )

    @staticmethod
    def vm_active_upgrade(
        unit_workload_version: str | None,
        unit_workload_container_version: str | None,
        current_versions: str,
        outdated: bool = False,
    ) -> StatusBase:
        """Returns the active status for a vm unit."""
        outdated_str = " (outdated)" if outdated else ""
        return ActiveStatus(
            f"MongoDB {unit_workload_version} running; "
            f"Snap revision {unit_workload_container_version}{outdated_str}; "
            f"Charm revision {current_versions}"
        )

    @staticmethod
    def k8s_active_upgrade(workload_version: str, charm_version: str, outdated=False) -> StatusBase:
        """Returns the active status for a k8s unit."""
        outdated_str = " (restart pending)" if outdated else ""
        return ActiveStatus(
            f"MongoDB {workload_version} running{outdated_str};  Charm revision {charm_version}"
        )

    @staticmethod
    def refreshing_needs_resume(
        resume_string: str,
    ) -> StatusBase:
        """Returns refreshing status."""
        return BlockedStatus(
            f"Refreshing. {resume_string}To rollback, `juju refresh` to last revision"
        )
