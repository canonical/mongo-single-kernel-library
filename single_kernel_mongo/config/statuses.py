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
    WAITING_FOR_MONGODB_START = StatusObject(
        status="waiting",
        message="Waiting for mongod to start...",
        check="MongoDB process status check.",
    )
    WAITING_FOR_EXPORTER_START = StatusObject(
        status="waiting",
        message="Waiting for mongodb-exporter to start...",
        check="MongoDB Exporter status check.",
    )
    INVALID_SHARDING_REL = StatusObject(
        status="blocked",
        message="The sharding interface cannot be used by replica sets.",
        short_message="Invalid sharding relation.",
        check="Relation validation.",
        action="Remove the relation on the shards interface (config-server or sharding relation) from this application.",
    )
    INVALID_CFG_SRV_ON_SHARD_REL = StatusObject(
        status="blocked",
        message="The config-server interface cannot be used by shards.",
        short_message="Invalid config-server relation.",
        check="Relation validation.",
        action="Remove the relation on the config-server interface from this application.",
    )
    INVALID_SHARD_ON_CFG_SRV_REL = StatusObject(
        status="blocked",
        message="The sharding interface cannot be used by a config-server.",
        short_message="Invalid sharding relation.",
        check="Relation validation.",
        action="Remove the relation on the sharding interface from this application.",
    )
    INVALID_MONGOS_REL = StatusObject(
        status="blocked",
        message="The cluster relation can only be used by config servers.",
        short_message="Invalid cluster relation.",
        check="Relation validation.",
        action="Remove the cluster relation (config-server interface) from this application.",
    )
    INVALID_S3_REL = StatusObject(
        status="blocked",
        message="The s3-credentials relation can only be used by config servers or replica sets.",
        short_message="Invalid s3-credentials relation.",
        check="Relation validation.",
        action="Remove the s3-credentials relation (s3 interface) from this application.",
    )
    INVALID_DB_REL = StatusObject(
        status="blocked",
        message="The database relation cannot be used by sharding components (shards or config servers).",
        short_message="Invalid database relation.",
        check="Relation validation.",
        action="Remove the database relation (mongodb_client interface) from this application.",
    )

    # RUNNING statuses:
    STARTING_MONGODB = StatusObject(
        status="maintenance", message="Starting MongoDB.", running="blocking"
    )
    INVALID_ROLE = StatusObject(
        status="blocked",
        message="The role config option is invalid.",
        check="Config validation failed.",
        action="Set the role config to a valid value: `replication`, `shard` or `config-server`.",
        running="blocking",
    )


class MongosStatuses(Enum):
    """Mongos related statuses."""

    CONNECTING_TO_CONFIG_SERVER = StatusObject(
        status="waiting",
        message="Connecting to config-server...",
        check="mongos process status check.",
    )
    WAITING_FOR_SECRETS = StatusObject(
        status="waiting",
        message="Waiting for config-server secrets...",
        check="Cluster relation validation.",
    )
    WAITING_FOR_MONGOS_START = StatusObject(
        status="waiting",
        message="Waiting for mongos to start...",
        check="mongos process status check.",
    )
    INVALID_REL = StatusObject(
        status="blocked",
        message="The relation is invalid.",
        check="Mongos charm relation check",
        action="Remove the relation on mongos",
    )
    INVALID_EXPOSE_EXTERNAL = StatusObject(
        status="blocked",
        message="The expose-external config option is invalid. Valid options are `nodeport` and `none`.",
        short_message="Invalid expose-external config.",
        check="Config validation failed.",
        action="Set the expose-external config to a valid value: `nodeport` or `none`.",
    )
    MISSING_TLS_REL = StatusObject(
        status="blocked",
        message="TLS must be enabled in mongos, since it is enabled on the config-server in the cluster relation.",
        short_message="Missing certificates relation.",
        check="Relation validation failed.",
        action="Add the certificates relation (tls-certificates interface) to mongos.",
    )
    INVALID_TLS_REL = StatusObject(
        status="blocked",
        message="TLS must be disabled in mongos, since it is disabled on the config-server in the cluster relation.",
        short_message="Invalid certificates relation.",
        check="Relation validation failed.",
        action="Remove the certificates relation (tls-certificates interface) from this application.",
    )
    CA_MISMATCH = StatusObject(
        status="blocked",
        message="The mongos CA and Config-Server CA don't match.",
        short_message="CA mismatch.",
        check="Relation validation failed.",
        action="Verify the certificates relations. Use the same CA for all cluster components.",
    )

    # Running statuses:
    MISSING_CONF_SERVER_REL = StatusObject(
        status="blocked",
        message="The cluster relation with the config-server is missing.",
        short_message="Missing cluster relation.",
        check="Relation validation failed.",
        action="Add the cluster relation (config-server interface) to mongos.",
        running="async",
    )
    STARTING_MONGOS = StatusObject(
        status="maintenance", message="Starting mongos.", running="blocking"
    )


class CharmStatuses(Enum):
    """Charm Statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    FAILED_SERVICES_START = StatusObject(
        status="blocked",
        message="Failed to start services. Retrying...",
        action="Check logs for more information.",
    )
    MONGODB_NOT_INSTALLED = StatusObject(
        status="waiting", message="Waiting for MongoDB to be installed..."
    )

    # RUNNING Statuses
    INSTALLING_MONGODB = StatusObject(
        status="maintenance", message="Installing MongoDB...", running="blocking"
    )
    DEPLOYED_WITHOUT_TRUST = StatusObject(
        status="blocked",
        message="Charm deployed without `trust` option.",
        action="Run `juju trust --scope=cluster <application-name>`.",
        running="async",
    )


class TLSStatuses(Enum):
    """TLS statuses."""

    # RUNNING statuses:
    DISABLING_TLS = StatusObject(
        status="maintenance",
        message="Disabling TLS...",
        check="Certificates relation (tls-certificates interface) removed.",
        running="blocking",
    )
    # Enabling TLS takes a while because we wait for multiple certs so it's
    # async to span over multiple events.
    ENABLING_TLS = StatusObject(
        status="maintenance",
        message="Enabling TLS...",
        check="Certificates relation (tls-certificates interface) added.",
        running="async",
    )


class BackupStatuses(Enum):
    """Backup manager related statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    # note unlike other daemons (exporter and mongod) this status belongs to the backup manager
    # since certain configurations are required for pbm to be active and running.
    WAITING_FOR_PBM_START = StatusObject(status="waiting", message="Waiting for PBM to start...")
    PBM_MISSING_CONF = StatusObject(
        status="blocked",
        message="Missing configurations in the s3-credentials relation.",
        short_message="Missing S3 configurations.",
        action="Check the logs and verify the configuration in the s3-credentials relation (s3 interface).",
        check="S3 configuration validation failed.",
    )
    PBM_INCOMPATIBLE_CONF = StatusObject(
        status="blocked",
        message="Incompatible S3 config options.",
        action="Check the logs and verify the configuration in the s3-credentials relation (s3 interface).",
        check="S3 configuration validation failed.",
    )
    PBM_INCORRECT_CREDS = StatusObject(
        status="blocked",
        message="Incorrect S3 credentials.",
        action="Check the configuration in the s3-credentials relation (s3 interface).",
        check="S3 configuration validation failed.",
    )
    PBM_UNKNOWN_ERROR = StatusObject(
        status="blocked",
        message="Unknown PBM error, check logs.",
        action="Check the logs and verify the configuration in the s3-credentials relation (s3 interface).",
        check="PBM error found.",
    )
    CANT_CONFIGURE = StatusObject(
        status="blocked",
        message="Failed to configure S3 backup options.",
        short_message="Invalid S3 configuration.",
        action="Check the logs and verify the configuration in the s3-credentials relation (s3 interface).",
        check="S3 configuration validation failed.",
    )
    FAILED_TO_CREATE_BUCKET = StatusObject(
        status="blocked",
        message="Failed to create S3 bucket.",
        action="Check the logs and verify the configuration in the s3-credentials relation (s3 interface).",
        check="S3 bucket creation failed.",
    )

    # Running status
    PBM_WAITING_TO_SYNC = StatusObject(
        status="waiting", message="Waiting to sync S3 configurations...", running="async"
    )
    ACTION_RUNNING = StatusObject(
        status="waiting",
        message="Waiting for backup/restore to finish before removing the relation",
        running="blocking",
    )

    @staticmethod
    def backup_running(backup_id: str) -> StatusObject:
        """Returns backup starting status based on id."""
        return StatusObject(
            status="maintenance",
            message=f"Backup started/running, backup id: '{backup_id}'",
            short_message="Backing up...",
            running="async",
        )

    @staticmethod
    def restore_running(backup_id: str) -> StatusObject:
        """Returns restore starting status based on id."""
        return StatusObject(
            status="maintenance",
            message=f"Restore started/running, backup id: '{backup_id}'",
            short_message="Restoring...",
            running="async",
        )


class ConfigServerStatuses(Enum):
    """Config server statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    SYNCING_PASSWORDS = StatusObject(
        status="waiting",
        message="Waiting for passwords to be synced across the cluster...",
        short_message="Syncing passwords...",
    )
    # todo consider this status to be put in charm
    MONGOS_NOT_RUNNING = StatusObject(status="waiting", message="Internal mongos is not running...")
    MISSING_CONF_SERVER_REL = StatusObject(
        status="blocked",
        message="Missing relation to shard(s).",
        check="Relation validation failed.",
        action="Add the config-server relation to the config-server.",
    )

    @staticmethod
    def adding_shard(shard: str) -> StatusObject:
        """Returns add shard status."""
        return StatusObject(
            status="maintenance",
            message=f"Adding shard {shard} to config-server...",
            short_message="Adding shard to config-server...",
            running="blocking",
        )

    @staticmethod
    def draining_shard(shard: str) -> StatusObject:
        """Returns draining shard status based on shard."""
        return StatusObject(
            status="maintenance",
            message=f"Draining shard {shard}...",
            short_message="Draining shard...",
            running="async",
        )

    @staticmethod
    def unreachable_shards(unreachable_shards: list[str]) -> StatusObject:
        """Returns unreachable shard status based on list."""
        msg = (
            f"Shards: {unreachable_shards[0]} is unreachable."
            if len(unreachable_shards) == 1
            else f"Shards: {', '.join(unreachable_shards)} are unreachable."
        )
        return StatusObject(
            status="blocked",
            message=msg,
            short_message="Unreachable shards.",
            action="Check logs for more information.",
        )

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

    ACTIVE_IDLE = StatusObject(status="active", message="")
    SHARD_DRAINED = StatusObject(
        status="active",
        message="Shard drained from cluster, ready for removal.",
    )

    ADDING_TO_CLUSTER = StatusObject(
        status="maintenance",
        message="Adding shard to config-server...",
    )
    SYNCING_PASSWORDS = StatusObject(
        status="waiting",
        message="Waiting for passwords to be synced across the cluster...",
        short_message="Syncing passwords...",
    )
    SHARD_NOT_AWARE = StatusObject(
        status="waiting",
        message="Shard is not yet shard aware.",
    )
    REQUIRES_TLS = StatusObject(
        status="blocked",
        message="TLS must be enabled in shard, since it is enabled on the config-server in the cluster relation.",
        short_message="Shard requires TLS to be enabled.",
        check="Relation validation failed.",
        action="Align the TLS configuration in all the cluster components: add the certificates relation to the shard.",
    )
    REQUIRES_NO_TLS = StatusObject(
        status="blocked",
        message="TLS must be disabled in shard, since it is disabled on the config-server in the cluster relation.",
        short_message="Shard requires TLS to be disabled.",
        check="Relation validation failed.",
        action="Align the TLS configuration in all the cluster components: remove the certificates relation from the shard.",
    )
    CA_MISMATCH = StatusObject(
        status="blocked",
        message="Shard CA and config-server CA don't match.",
        short_message="CA mismatch.",
        check="TLS configuration validation failed.",
        action="Verify the certificates relations. Use the same CA for all the cluster components.",
    )
    MISSING_CONF_SERVER_REL = StatusObject(
        status="blocked",
        message="Missing relation to config-server.",
        check="Relation validation failed.",
        action="Add the sharding relation (shards interface) to the shard.",
    )

    # RUNNING status:
    DRAINING_SHARD = StatusObject(
        status="maintenance", message="Draining shard from cluster...", running="blocking"
    )
    FAILED_TO_DRAIN = StatusObject(
        status="blocked", message="Failed to drain shard from cluster.", running="blocking"
    )
    WAITING_TO_REMOVE = StatusObject(
        status="waiting",
        message="Waiting for config-server to remove shard...",
        running="blocking",
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
            short_message="Charm revision mismatch.",
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
            short_message="Charm revision mismatch.",
            message=f"Charm revision ({current_charms_version}{local_identifier}) is not up-to date with config-server.",
        )


class MongodStatuses(Enum):
    """MongoD statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    PRIMARY = StatusObject(status="active", message="Primary.")
    SECONDARY = StatusObject(status="active", message="")

    ADDING_MEMBER = StatusObject(status="maintenance", message="Adding member...")
    REMOVING_MEMBER = StatusObject(status="maintenance", message="Removing member...")
    SYNCING_MEMBER = StatusObject(status="maintenance", message="Syncing member...")
    NOT_READY = StatusObject(status="waiting", message="Mongod is not ready.")
    WAITING_REPL_SET_INIT = StatusObject(
        status="waiting", message="Waiting for replica set initialisation..."
    )
    WAITING_RECONFIG = StatusObject(
        status="waiting", message="Waiting for replica set reconfiguration..."
    )
    WAITING_ELECTION = StatusObject(status="waiting", message="Waiting for primary re-election...")
    WAITING_RECONNECTION = StatusObject(
        status="maintenance", message="Waiting for reconnection to mongo..."
    )
    WAITING_CREDENTIALS = StatusObject(status="waiting", message="Waiting for mongo credentials...")

    @staticmethod
    def replset_status(status: str):
        """When we have an unexpected replica set status."""
        return StatusObject(
            status="blocked",
            message=status,
            short_message="Unexpected error found in replica set.",
            action="Check logs for more information.",
        )


class UpgradeStatuses(Enum):
    """Upgrade statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    WAITING_POST_UPGRADE_STATUS = StatusObject(
        status="waiting", message="Waiting for post upgrade checks..."
    )
    UNHEALTHY_UPGRADE = StatusObject(
        status="blocked",
        message="Unhealthy after refresh. Rollback to previous revision with `juju refresh`.",
        approved_critical_component=True,
    )
    INCOMPATIBLE_UPGRADE = StatusObject(
        status="blocked",
        message="Refresh incompatible. Rollback to previous revision with `juju refresh`.",
        approved_critical_component=True,
    )
    REFRESH_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Refreshing...",
        action="To rollback, run `juju refresh` to the previous revision.",
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
            f"Charm revision {current_versions}.",
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
            message=f"MongoDB {workload_version} running{outdated_str};  Charm revision {charm_version}.",
            approved_critical_component=True,
        )

    @staticmethod
    def refreshing_needs_resume(
        resume_string: str,
    ) -> StatusObject:
        """Returns refreshing status."""
        return StatusObject(
            status="blocked",
            message=f"Refreshing. {resume_string}To rollback, `juju refresh` to last revision.",
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
