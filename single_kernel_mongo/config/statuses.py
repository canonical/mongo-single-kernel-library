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

from data_platform_helpers.advanced_statuses.models import StatusObject
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
    MONGODB_NOT_STARTED = StatusObject(status=WaitingStatus("Waiting to start mongod..."))
    EXPORTER_NOT_STARTED = StatusObject(
        status=WaitingStatus("Waiting to start mongodb-exporter...")
    )
    SHARDING_ON_REPLICA = StatusObject(
        status=BlockedStatus("Sharding interface cannot be used by replicas.")
    )
    UNSUPPORTED_MONGOS_REL = StatusObject(
        status=BlockedStatus("Relation to mongos not supported, config role must be config-server.")
    )
    INVALID_S3_INTEGRATION_STATUS = StatusObject(
        status=BlockedStatus(
            "Relation to s3-integrator is not supported, config role must be config-server."
        )
    )

    DB_REL_ON_SHARD = StatusObject(
        status=BlockedStatus("Sharding roles do not support database interface.")
    )

    # RUNNING statuses:
    STARTING_MONGODB = StatusObject(
        status=MaintenanceStatus("Starting MongoDB."), running="blocking"
    )


class MongosStatuses(Enum):
    """Mongos related statuses."""

    INVALID_EXPOSE_EXTERNAL = StatusObject(
        status=BlockedStatus("Config option for expose-external not valid.")
    )
    CONNECTING_TO_CONFIG_SERVER = StatusObject(
        status=WaitingStatus("Connecting to config-server...")
    )
    WAITING_FOR_SECRETS = StatusObject(
        status=WaitingStatus("Waiting for secrets from config-server")
    )
    REQUIRES_TLS = StatusObject(status=BlockedStatus("mongos requires TLS to be enabled."))
    REQUIRES_NO_TLS = StatusObject(
        status=BlockedStatus("mongos has TLS enabled, but config-server does not.")
    )
    CA_MISMATCH = StatusObject(status=BlockedStatus("mongos CA and Config-Server CA don't match."))
    MONGOS_NOT_STARTED = StatusObject(status=WaitingStatus("Waiting to start mongos..."))

    # Running statuses:
    NEED_CONF_SERVER = StatusObject(
        status=BlockedStatus("Missing relation to config-server."), running="async"
    )
    STARTING_MONGOS = StatusObject(status=MaintenanceStatus("Starting mongos."), running="blocking")


class CharmStatuses(Enum):
    """Charm Statuses."""

    ACTIVE_IDLE = StatusObject(status=ActiveStatus())
    MONGODB_NOT_INSTALLED = StatusObject(status=BlockedStatus("MongoDB not installed."))
    MONGOS_NOT_STARTED = StatusObject(status=WaitingStatus("Waiting to start mongos..."))

    mongodb = MongoDBStatuses
    mongos = MongosStatuses

    # RUNNING Statuses
    MONGODB_INSTALLED = StatusObject(
        status=MaintenanceStatus("Installed MongoDB"), running="blocking"
    )
    INSTALLING_MONGODB = StatusObject(
        status=MaintenanceStatus("installing MongoDB"), running="blocking"
    )
    DEPLOYED_WITHOUT_TRUST = StatusObject(
        status=BlockedStatus("Charm deployed without `trust`"), running="async"
    )


class TLSStatuses(Enum):
    """TLS statuses."""

    ACTIVE_IDLE = StatusObject(status=ActiveStatus())

    # RUNNING statuses:
    DISABLING_TLS = StatusObject(status=MaintenanceStatus("Disabling TLS..."), running="blocking")
    # Enabling TLS takes a while because we wait for multiple certs so it's
    # async to span over multiple events.
    ENABLING_TLS = StatusObject(status=MaintenanceStatus("Enabling TLS..."), running="blocking")


class BackupStatuses(Enum):
    """Backup manager related statuses."""

    # note unlike other daemons (exporter and mongod) this status belongs to the backup manager
    # since certain configurations are required for pbm to be active and running.
    PBM_NOT_STARTED = StatusObject(status=WaitingStatus("Waiting for pbm to start..."))
    PBM_MISSING_CONFIGS = StatusObject(status=BlockedStatus("s3 configurations missing."))
    PBM_INCORRECT_CREDS = StatusObject(status=BlockedStatus("s3 credentials are incorrect."))
    PBM_INCOMPATIBLE_CONF = StatusObject(
        status=BlockedStatus("s3 configurations are incompatible.")
    )
    UNKNOWN_PBM_ERROR = StatusObject(status=BlockedStatus("Unknown PBM error, check logs."))
    CANT_CONFIGURE = StatusObject(status=BlockedStatus("Couldn't configure s3 backup options."))
    ACTIVE_IDLE = StatusObject(status=ActiveStatus())

    # Running status
    PBM_WAITING_TO_SYNC = StatusObject(
        status=WaitingStatus("Waiting to sync s3 configurations..."), running="async"
    )

    @staticmethod
    def backup_running(backup_id: str) -> StatusBase:
        """Returns backup starting status based on id."""
        return StatusObject(
            status=MaintenanceStatus(f"Backup started/running, backup id: '{backup_id}'"),
            running="async",
        )

    @staticmethod
    def restore_running(backup_id: str) -> StatusBase:
        """Returns restore starting status based on id."""
        return StatusObject(
            status=MaintenanceStatus(f"Restore started/running, backup id: '{backup_id}'"),
            running="async",
        )


class ConfigServerStatuses(Enum):
    """Config server statuses."""

    # todo consider this status to be put in charm
    MONGOS_NOT_RUNNING = StatusObject(status=BlockedStatus("Internal mongos is not running."))
    NEED_SHARDS = StatusObject(status=BlockedStatus("Missing relation to shard(s)."))
    SYNCING_PASSWORDS = StatusObject(
        status=WaitingStatus("Waiting to sync passwords across the cluster...")
    )
    ACTIVE_IDLE = StatusObject(status=ActiveStatus())

    @staticmethod
    def adding_shard(shard: str) -> StatusBase:
        """Returns add shard status."""
        return StatusObject(
            status=MaintenanceStatus(f"Adding shard {shard} to config-server."), running="blocking"
        )

    @staticmethod
    def draining_shard(shard: str) -> StatusBase:
        """Returns draining shard status based on shard."""
        return StatusObject(status=MaintenanceStatus(f"Draining shard {shard}"), running="async")

    @staticmethod
    def unreachable_shards(unreachable_shards: list[str]) -> StatusBase:
        """Returns unreachable shard status based on list."""
        unreachable = ", ".join(unreachable_shards)
        return StatusObject(status=BlockedStatus(f"Shards: {unreachable} are unreachable."))

    @staticmethod
    def waiting_for_shard_upgrade(current_charms_version: str, local_identifier: str) -> StatusBase:
        """Returns waiting for shard upgrade status."""
        return StatusObject(
            status=WaitingStatus(
                f"Waiting for shards to upgrade/downgrade to revision {current_charms_version}{local_identifier}."
            )
        )


class ShardStatuses(Enum):
    """Shard statuses."""

    REQUIRES_TLS = StatusObject(status=BlockedStatus("Shard requires TLS to be enabled."))
    REQUIRES_NO_TLS = StatusObject(
        status=BlockedStatus("Shard has TLS enabled, but config-server does not.")
    )
    CA_MISMATCH = StatusObject(status=BlockedStatus("Shard CA and Config-Server CA don't match."))

    NEED_CONF_SERVER = StatusObject(status=BlockedStatus("Missing relation to config-server."))
    SHARD_DRAINED = StatusObject(
        status=ActiveStatus("Shard drained from cluster, ready for removal.")
    )
    WAITING_TO_REMOVE = StatusObject(
        status=WaitingStatus("Waiting for config-server to remove shard")
    )
    SYNCING_PASSWORDS = StatusObject(
        status=WaitingStatus("Waiting to sync passwords across the cluster...")
    )
    ADDING_TO_CLUSTER = StatusObject(status=MaintenanceStatus("Adding shard to config-server"))
    SHARD_NOT_AWARE = StatusObject(status=BlockedStatus("Shard is not yet shard aware."))
    ACTIVE_IDLE = StatusObject(status=ActiveStatus())

    # RUNNING status:
    DRAINING_SHARD = StatusObject(
        status=MaintenanceStatus("Draining shard from cluster..."), running="blocking"
    )
    FAILED_TO_DRAIN = StatusObject(
        status=BlockedStatus("Failed to drain shard from cluster"), running="blocking"
    )

    @staticmethod
    def shard_needs_upgrade(
        current_charms_version: str,
        local_identifier: str,
        config_server_revision: str,
        remote_local_identifier: str,
    ) -> StatusBase:
        """Returns needs shard upgrade status."""
        return StatusObject(
            status=BlockedStatus(
                f"Charm revision ({current_charms_version}{local_identifier}) is not up-to date with config-server ({config_server_revision}{remote_local_identifier})."
            )
        )

    @staticmethod
    def older_version_shard_needs_upgrade(
        current_charms_version: str,
        local_identifier: str,
    ) -> StatusBase:
        """Returns needs shard upgrade status."""
        return StatusObject(
            status=BlockedStatus(
                f"Charm revision ({current_charms_version}{local_identifier}) is not up-to date with config-server."
            )
        )


class MongodStatuses(Enum):
    """MongoD statuses."""

    WAITING_REPL_SET_INIT = StatusObject(
        status=WaitingStatus("Waiting for replica set initialisation...")
    )
    WAITING_RECONFIG = StatusObject(status=WaitingStatus("Waiting to reconfigure replica set..."))
    WAITING_ELECTION = StatusObject(status=WaitingStatus("Waiting for primary re-election..."))
    WAITING_RECONNECT = StatusObject(status=WaitingStatus("Waiting to reconnect to unit..."))
    MEMBER_BEING_ADDED = StatusObject(status=WaitingStatus("Member being added..."))
    MEMBER_REMOVING = StatusObject(status=WaitingStatus("Member is removing..."))
    MEMBER_SYNCING = StatusObject(status=WaitingStatus("Member is syncing..."))
    PRIMARY = StatusObject(status=ActiveStatus("Primary."))
    SECONDARY = StatusObject(status=ActiveStatus())

    ACTIVE_IDLE = StatusObject(status=ActiveStatus())

    MISSING_CREDENTIALS = StatusObject(status=WaitingStatus("Missing credentials for mongo"))

    @staticmethod
    def replset_status(status: str):
        """When we have an unexpected replica set status."""
        return StatusObject(status=BlockedStatus(status))


class UpgradeStatuses(Enum):
    """Upgrade statuses."""

    UNHEALTHY_UPGRADE = StatusObject(status=BlockedStatus("Unhealthy after refresh."))
    INCOMPATIBLE_UPGRADE = StatusObject(
        status=BlockedStatus(
            "Refresh incompatible. Rollback to previous revision with `juju refresh`"
        )
    )
    ACTIVE_IDLE = StatusObject(status=ActiveStatus())
    WAITING_POST_UPGRADE_STATUS = StatusObject(
        status=WaitingStatus("Waiting for post upgrade checks...")
    )
    REFRESH_IN_PROG = StatusObject(
        status=MaintenanceStatus("Refreshing. To rollback, `juju refresh` to the previous revision")
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
        return StatusObject(
            status=ActiveStatus(
                f"MongoDB {unit_workload_version} running; "
                f"Snap revision {unit_workload_container_version}{outdated_str}; "
                f"Charm revision {current_versions}"
            )
        )

    @staticmethod
    def k8s_active_upgrade(workload_version: str, charm_version: str, outdated=False) -> StatusBase:
        """Returns the active status for a k8s unit."""
        outdated_str = " (restart pending)" if outdated else ""
        return StatusObject(
            status=ActiveStatus(
                f"MongoDB {workload_version} running{outdated_str};  Charm revision {charm_version}"
            )
        )

    @staticmethod
    def refreshing_needs_resume(
        resume_string: str,
    ) -> StatusObject:
        """Returns refreshing status."""
        return StatusObject(
            status=BlockedStatus(
                f"Refreshing. {resume_string}To rollback, `juju refresh` to last revision"
            )
        )


class LdapStatuses(Enum):
    """Ldap Statuses."""

    INVALID_LDAP_USER_MAPPING = StatusObject(
        status=BlockedStatus("Invalid LdapUserToDnMapping, please update your config."),
    )
    INVALID_LDAP_QUERY_TEMPLATE = StatusObject(
        status=BlockedStatus("Invalid LDAP Query template, please update your config"),
    )
