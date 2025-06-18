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


class MongoDBStatuses(Enum):
    """MongoDB related statuses."""

    # STATE statuses:
    WAITING_FOR_MONGODB_START = StatusObject(status="waiting", message="Waiting to start mongod...")
    WAITING_FOR_EXPORTER_START = StatusObject(
        status="waiting", message="Waiting to start mongodb-exporter..."
    )
    SHARDING_ON_REPLICA = StatusObject(
        status="blocked", message="Sharding interface cannot be used by replicas."
    )
    UNSUPPORTED_MONGOS_REL = StatusObject(
        status="blocked",
        message="Relation to mongos not supported, config role must be config-server.",
    )
    INVALID_S3_INTEGRATION_STATUS = StatusObject(
        status="blocked",
        message="Relation to s3-integrator is not supported, config role must be config-server.",
    )

    INVALID_DB_REL_ON_SHARD = StatusObject(
        status="blocked", message="Sharding roles do not support database interface."
    )

    # RUNNING statuses:
    STARTING_MONGODB = StatusObject(
        status="maintenance", message="Starting MongoDB.", running="blocking"
    )


class MongosStatuses(Enum):
    """Mongos related statuses."""

    INVALID_EXPOSE_EXTERNAL = StatusObject(
        status="blocked", message="Config option for expose-external not valid."
    )
    CONNECTING_TO_CONFIG_SERVER = StatusObject(
        status="waiting", message="Connecting to config-server..."
    )
    WAITING_FOR_SECRETS = StatusObject(
        status="waiting", message="Waiting for secrets from config-server"
    )
    REQUIRES_TLS = StatusObject(status="blocked", message="mongos requires TLS to be enabled.")
    REQUIRES_NO_TLS = StatusObject(
        status="blocked", message="mongos has TLS enabled, but config-server does not."
    )
    CA_MISMATCH = StatusObject(
        status="blocked", message="mongos CA and Config-Server CA don't match."
    )
    MONGOS_NOT_STARTED = StatusObject(status="waiting", message="Waiting to start mongos...")

    # Running statuses:
    MISSING_CONF_SERVER_REL = StatusObject(
        status="blocked", message="Missing relation to config-server.", running="async"
    )
    STARTING_MONGOS = StatusObject(
        status="maintenance", message="Starting mongos.", running="blocking"
    )


class CharmStatuses(Enum):
    """Charm Statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    FAILED_SERVICES_START = StatusObject(status="blocked", message="Failed to start services.")
    MONGODB_NOT_INSTALLED = StatusObject(status="blocked", message="MongoDB not installed.")
    MONGOS_NOT_STARTED = StatusObject(status="waiting", message="Waiting to start mongos...")

    # RUNNING Statuses
    INSTALLING_MONGODB = StatusObject(
        status="maintenance", message="installing MongoDB", running="blocking"
    )
    DEPLOYED_WITHOUT_TRUST = StatusObject(
        status="blocked", message="Charm deployed without `trust`", running="async"
    )


class TLSStatuses(Enum):
    """TLS statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")

    # RUNNING statuses:
    DISABLING_TLS = StatusObject(
        status="maintenance", message="Disabling TLS...", running="blocking"
    )
    # Enabling TLS takes a while because we wait for multiple certs so it's
    # async to span over multiple events.
    ENABLING_TLS = StatusObject(status="maintenance", message="Enabling TLS...", running="blocking")


class BackupStatuses(Enum):
    """Backup manager related statuses."""

    # note unlike other daemons (exporter and mongod) this status belongs to the backup manager
    # since certain configurations are required for pbm to be active and running.
    WAITING_FOR_PBM_START = StatusObject(status="waiting", message="Waiting for pbm to start...")
    PBM_MISSING_CONFIGS = StatusObject(status="blocked", message="s3 configurations missing.")
    PBM_INCORRECT_CREDS = StatusObject(status="blocked", message="s3 credentials are incorrect.")
    PBM_INCOMPATIBLE_CONF = StatusObject(
        status="blocked", message="s3 configurations are incompatible."
    )
    UNKNOWN_PBM_ERROR = StatusObject(status="blocked", message="Unknown PBM error, check logs.")
    CANT_CONFIGURE = StatusObject(status="blocked", message="Couldn't configure s3 backup options.")
    ACTIVE_IDLE = StatusObject(status="active", message="")

    # Running status
    PBM_WAITING_TO_SYNC = StatusObject(
        status="waiting", message="Waiting to sync s3 configurations...", running="async"
    )

    @staticmethod
    def backup_running(backup_id: str) -> StatusObject:
        """Returns backup starting status based on id."""
        return StatusObject(
            status="maintenance",
            message=f"Backup started/running, backup id: '{backup_id}'",
            running="async",
        )

    @staticmethod
    def restore_running(backup_id: str) -> StatusObject:
        """Returns restore starting status based on id."""
        return StatusObject(
            status="maintenance",
            message=f"Restore started/running, backup id: '{backup_id}'",
            running="async",
        )


class ConfigServerStatuses(Enum):
    """Config server statuses."""

    # todo consider this status to be put in charm
    MONGOS_NOT_RUNNING = StatusObject(status="blocked", message="Internal mongos is not running.")
    MISSING_SHARDING_REL = StatusObject(status="blocked", message="Missing relation to shard(s).")
    SYNCING_PASSWORDS = StatusObject(
        status="waiting", message="Waiting to sync passwords across the cluster..."
    )
    ACTIVE_IDLE = StatusObject(status="active", message="")

    @staticmethod
    def adding_shard(shard: str) -> StatusObject:
        """Returns add shard status."""
        return StatusObject(
            status="maintenance",
            message=f"Adding shard {shard} to config-server.",
            running="blocking",
        )

    @staticmethod
    def draining_shard(shard: str) -> StatusObject:
        """Returns draining shard status based on shard."""
        return StatusObject(
            status="maintenance", message=f"Draining shard {shard}", running="async"
        )

    @staticmethod
    def unreachable_shards(unreachable_shards: list[str]) -> StatusObject:
        """Returns unreachable shard status based on list."""
        unreachable = ", ".join(unreachable_shards)
        return StatusObject(status="blocked", message=f"Shards: {unreachable} are unreachable.")

    @staticmethod
    def waiting_for_shard_upgrade(
        current_charms_version: str, local_identifier: str
    ) -> StatusObject:
        """Returns waiting for shard upgrade status."""
        return StatusObject(
            status="waiting",
            message=f"Waiting for shards to upgrade/downgrade to revision {current_charms_version}{local_identifier}.",
        )


class ShardStatuses(Enum):
    """Shard statuses."""

    REQUIRES_TLS = StatusObject(status="blocked", message="Shard requires TLS to be enabled.")
    REQUIRES_NO_TLS = StatusObject(
        status="blocked", message="Shard has TLS enabled, but config-server does not."
    )
    CA_MISMATCH = StatusObject(
        status="blocked", message="Shard CA and Config-Server CA don't match."
    )

    MISSING_CONF_SERVER_REL = StatusObject(
        status="blocked", message="Missing relation to config-server."
    )
    SHARD_DRAINED = StatusObject(
        status="active", message="Shard drained from cluster, ready for removal."
    )
    WAITING_TO_REMOVE = StatusObject(
        status="waiting", message="Waiting for config-server to remove shard", running="blocking"
    )
    SYNCING_PASSWORDS = StatusObject(
        status="waiting", message="Waiting to sync passwords across the cluster..."
    )
    ADDING_TO_CLUSTER = StatusObject(status="maintenance", message="Adding shard to config-server")
    SHARD_NOT_AWARE = StatusObject(status="blocked", message="Shard is not yet shard aware.")
    ACTIVE_IDLE = StatusObject(status="active", message="")

    # RUNNING status:
    DRAINING_SHARD = StatusObject(
        status="maintenance", message="Draining shard from cluster...", running="blocking"
    )
    FAILED_TO_DRAIN = StatusObject(
        status="blocked", message="Failed to drain shard from cluster", running="blocking"
    )

    @staticmethod
    def shard_needs_upgrade(
        current_charms_version: str,
        local_identifier: str,
        config_server_revision: str,
        remote_local_identifier: str,
    ) -> StatusObject:
        """Returns needs shard upgrade status."""
        return StatusObject(
            status="blocked",
            message=f"Charm revision ({current_charms_version}{local_identifier}) is not up-to date with config-server ({config_server_revision}{remote_local_identifier}).",
        )

    @staticmethod
    def older_version_shard_needs_upgrade(
        current_charms_version: str,
        local_identifier: str,
    ) -> StatusObject:
        """Returns needs shard upgrade status."""
        return StatusObject(
            status="blocked",
            message=f"Charm revision ({current_charms_version}{local_identifier}) is not up-to date with config-server.",
        )


class MongodStatuses(Enum):
    """MongoD statuses."""

    WAITING_REPL_SET_INIT = StatusObject(
        status="waiting", message="Waiting for replica set initialisation..."
    )
    WAITING_RECONFIG = StatusObject(
        status="waiting", message="Waiting to reconfigure replica set..."
    )
    WAITING_ELECTION = StatusObject(status="waiting", message="Waiting for primary re-election...")
    WAITING_RECONNECT = StatusObject(status="waiting", message="Waiting to reconnect to unit...")
    MEMBER_BEING_ADDED = StatusObject(status="waiting", message="Member being added...")
    MEMBER_REMOVING = StatusObject(status="waiting", message="Member is removing...")
    MEMBER_SYNCING = StatusObject(status="waiting", message="Member is syncing...")
    PRIMARY = StatusObject(status="active", message="Primary.")
    SECONDARY = StatusObject(status="active", message="")

    ACTIVE_IDLE = StatusObject(status="active", message="")

    MISSING_CREDENTIALS = StatusObject(status="waiting", message="Missing credentials for mongo")

    @staticmethod
    def replset_status(status: str):
        """When we have an unexpected replica set status."""
        return StatusObject(status="blocked", message=status)


class UpgradeStatuses(Enum):
    """Upgrade statuses."""

    UNHEALTHY_UPGRADE = StatusObject(
        status="blocked", message="Unhealthy after refresh.", approved_critical_component=True
    )
    INCOMPATIBLE_UPGRADE = StatusObject(
        status="blocked",
        message="Refresh incompatible. Rollback to previous revision with `juju refresh`",
        approved_critical_component=True,
    )
    ACTIVE_IDLE = StatusObject(status="active", message="")
    WAITING_POST_UPGRADE_STATUS = StatusObject(
        status="waiting", message="Waiting for post upgrade checks..."
    )
    REFRESH_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Refreshing. To rollback, `juju refresh` to the previous revision",
        approved_critical_component=True,
    )

    @staticmethod
    def vm_active_upgrade(
        unit_workload_version: str | None,
        unit_workload_container_version: str | None,
        current_versions: str,
        outdated: bool = False,
    ) -> StatusObject:
        """Returns the active status for a vm unit."""
        outdated_str = " (outdated)" if outdated else ""
        return StatusObject(
            status="active",
            message=f"MongoDB {unit_workload_version} running; "
            f"Snap revision {unit_workload_container_version}{outdated_str}; "
            f"Charm revision {current_versions}",
            approved_critical_component=True,
        )

    @staticmethod
    def k8s_active_upgrade(
        workload_version: str, charm_version: str, outdated=False
    ) -> StatusObject:
        """Returns the active status for a k8s unit."""
        outdated_str = " (restart pending)" if outdated else ""
        return StatusObject(
            status="active",
            message=f"MongoDB {workload_version} running{outdated_str};  Charm revision {charm_version}",
            approved_critical_component=True,
        )

    @staticmethod
    def refreshing_needs_resume(
        resume_string: str,
    ) -> StatusObject:
        """Returns refreshing status."""
        return StatusObject(
            status="blocked",
            message=f"Refreshing. {resume_string}To rollback, `juju refresh` to last revision",
            approved_critical_component=True,
        )


class LdapStatuses(Enum):
    """Ldap Statuses."""

    INVALID_LDAP_USER_MAPPING = StatusObject(
        status="blocked",
        message="Invalid LdapUserToDnMapping, please update your config.",
    )
    INVALID_LDAP_QUERY_TEMPLATE = StatusObject(
        status="blocked",
        message="Invalid LDAP Query template, please update your config",
    )
    CONFIGURING_LDAP = StatusObject(
        status="maintenance", message="Configuring LDAP", running="blocking"
    )
    INVALID_LDAP_REL_ON_SHARD = StatusObject(
        status="blocked",
        message="Cannot integrate LDAP with shard.",
    )
    TLS_REQUIRED = StatusObject(
        status="blocked",
        message="TLS is mandatory for LDAP transport.",
    )
    LDAP_REQUIRED = StatusObject(
        status="blocked",
        message="GLauth TLS is integrated but LDAP is not.",
    )
    LDAP_SERVERS_MISMATCH = StatusObject(
        status="blocked",
        message="mongos and config-server not integrated with the same ldap server.",
    )
    WAITING_FOR_DATA = StatusObject(
        status="waiting",
        message="Waiting for both LDAP data and Glauth certificates.",
    )
    WAITING_FOR_CERTS = StatusObject(
        status="waiting",
        message="Waiting for Glauth certificates.",
    )
    WAITING_FOR_LDAP_DATA = StatusObject(
        status="waiting",
        message="Missing LDAP data from Glauth.",
    )
    MISSING_BASE_DN = StatusObject(
        status="blocked",
        message="Missing base DN for LDAP.",
    )
    MISSING_CERT_CHAIN = StatusObject(
        status="blocked",
        message="Missing chain for LDAP.",
    )
    MISSING_LDAPS_URLS = StatusObject(
        status="blocked",
        message="Missing LDAPS URLs for LDAP.",
    )
    LDAPS_NOT_ENABLED = StatusObject(
        status="blocked",
        message="LDAPS not enabled on LDAP application.",
    )
    UNABLE_TO_BIND = StatusObject(
        status="blocked",
        message="Could not bind with ldap",
    )
    ACTIVE_IDLE = StatusObject(
        status="active",
        message="",
    )

    @staticmethod
    def on_error_status(err: Exception):
        """On error."""
        return StatusObject(status="blocked", message=f"{err}")
