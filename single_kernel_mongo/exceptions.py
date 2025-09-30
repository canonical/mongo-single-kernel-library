#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""All general exceptions."""

from data_platform_helpers.advanced_statuses.models import StatusObject

from single_kernel_mongo.config.statuses import UpgradeStatuses


class InvalidCharmKindError(Exception):
    """Raised when calling a function on the wrong charm kind."""


class DeployedWithoutTrustError(Exception):
    """Deployed without `juju deploy --trust` or `juju trust`.

    Needed to access Kubernetes StatefulSet.
    """

    def __init__(self, *, app_name: str):
        super().__init__(
            f"Run `juju trust {app_name} --scope=cluster` and `juju resolve` for each unit (or remove & re-deploy {app_name} with `--trust`)"
        )


class WorkloadExecError(Exception):
    """Raised when a workload fails to exec a command."""

    def __init__(
        self,
        cmd: str | list[str],
        return_code: int,
        stdout: str | None,
        stderr: str | None,
    ):
        super().__init__(self)
        self.cmd = cmd
        self.return_code = return_code
        self.stdout = stdout or ""
        self.stderr = stderr or ""

    def __str__(self) -> str:
        """Repr of error."""
        return f"cmd failed ({self.return_code}) - cmd={self.cmd}, stdout={self.stdout}, stderr={self.stderr}"


class AmbiguousConfigError(Exception):
    """Raised when the config could correspond to a mongod config or mongos config."""


class WorkloadServiceError(Exception):
    """Raised when a service fail to start/stop/restart."""


class WorkloadNotReadyError(Exception):
    """Raised when a service is not ready yet."""


class ResyncError(Exception):
    """Raised when pbm is resyncing configurations and is not ready to be used."""


class SetPBMConfigError(Exception):
    """Raised when pbm cannot configure a given option."""


class PBMBusyError(Exception):
    """Raised when PBM is busy and cannot run another operation."""


class RestoreError(Exception):
    """Raised when restore backup operation is failed."""


class BackupError(Exception):
    """Raised when create backup operation is failed."""


class ListBackupError(Exception):
    """Raised when list backup operation is failed."""


class InvalidS3CredentialsError(Exception):
    """Raised when list backup operation is failed."""


class FailedToCreateS3BucketError(Exception):
    """Raised when list backup operation is failed."""


class FailedToFindNodePortError(Exception):
    """Raised when NodePort cannot be found, but is excepted to be present."""


class FailedToFindServiceError(Exception):
    """Raised when service cannot be found, but is excepted to be present."""


class FailedToGetHostsError(Exception):
    """Raised when we fail to get the host."""


class SecretAlreadyExistsError(Exception):
    """Raised when we try to push a secret that already exists."""


class SetPasswordError(Exception):
    """Raised when setting the password failed for a reason."""


class ShardingMigrationError(Exception):
    """Raised when there is an attempt to change the role of a sharding component."""


class ContainerNotReadyError(Exception):
    """Raised when the container is not ready."""


class UpgradeInProgressError(Exception):
    """Raised when an upgrade is in progress."""


class OpenPortFailedError(Exception):
    """Raised when we fail to open ports."""


class InvalidPBMStatusError(Exception):
    """Raised when pbm status does not allow the action to be executed."""


class InvalidArgumentForActionError(Exception):
    """Raised when arguments for an action are invalid."""


class UnknownCertificateExpiringError(Exception):
    """Raised when an unknown certificate is expiring."""


class UnknownCertificateAvailableError(Exception):
    """Raised when an unknown certificate is available."""


class DatabaseRequestedHasNotRunYetError(Exception):
    """Raised when the database event has not run yet."""


class ShardAuthError(Exception):
    """Raised when a shard doesn't have the same auth as the config server."""

    def __init__(self, shard: str):
        self.shard = shard


class RemoveLastShardError(Exception):
    """Raised when there is an attempt to remove the last shard in the cluster."""


class NotEnoughSpaceError(Exception):
    """Raised when there isn't enough space to movePrimary."""


class ShardNotInClusterError(Exception):
    """Raised when shard is not present in cluster, but it is expected to be."""


class ShardNotPlannedForRemovalError(Exception):
    """Raised when it is expected that a shard is planned for removal, but it is not."""


class NotDrainedError(Exception):
    """Raised when a shard is still being drained."""


class BalancerNotEnabledError(Exception):
    """Raised when balancer process is not enabled."""


class WaitingForSecretsError(Exception):
    """Raised when we are still waiting for secrets."""


class WaitingForCertificatesError(Exception):
    """Raised when we are waiting for certificates."""


class FailedToUpdateCredentialsError(Exception):
    """Raised when we failed to update credentials."""


class DeferrableFailedHookChecksError(Exception):
    """Raised when we failed to pass hook checks and we should defer."""


class NonDeferrableFailedHookChecksError(Exception):
    """Raised when we failed to pass hook checks and we should skip."""


class DeferrableError(Exception):
    """Raised for all deferrable errors."""


class MissingConfigServerError(Exception):
    """Raise when the mongos charm is missing config server integration."""


class EarlyRemovalOfConfigServerError(Exception):
    """Raised when we try to remove config server while it still has shards."""


class StatusError(Exception):
    """Exception with ops status."""

    def __init__(self, status: StatusObject) -> None:
        super().__init__(status.message)
        self.status = status


class PrecheckFailedError(StatusError):
    """App is not ready to upgrade."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(UpgradeStatuses.REFRESH_IN_PROGRESS.value)


class FailedToElectNewPrimaryError(Exception):
    """Raised when a new primary isn't elected after stepping down."""


class ClusterNotHealthyError(Exception):
    """Raised when the cluster is not healthy."""


class BalancerStillRunningError(Exception):
    """Raised when the balancer is still running after stopping it."""


class PeerRelationNotReadyError(Exception):
    """Upgrade peer relation not available (to this unit)."""


class FailedToMovePrimaryError(Exception):
    """Raised when attempt to move a primary fails."""


class ActionFailedError(Exception):
    """Raised when we failed an action."""


class UnhealthyUpgradeError(Exception):
    """Raised when the upgrade is unhealthy during an post upgrade check."""


class WaitingForLdapDataError(DeferrableError):
    """Raised when the charm hasn't received data from ldap yet."""


class InvalidLdapWithShardError(NonDeferrableFailedHookChecksError):
    """Raised when LDAP is integrated with a shard."""


class LDAPSNotEnabledError(Exception):
    """Raised when the charm hasn't received ldaps urls."""


class InvalidLdapUserToDnMappingError(Exception):
    """Raised when the LdapUserToDnMapping is invalid."""


class InvalidLdapQueryTemplateError(Exception):
    """Raised when the LdapQueryTemplate and LdapUserToDnMapping combination is invalid."""


class WaitingForLeaderError(Exception):
    """Raised when we haven't elected a leader yet but we need it."""


class MissingCredentialsError(Exception):
    """Raised when we haven't received credentials yet."""


class InvalidLdapHashError(DeferrableError):
    """Raised when the hash shared by config server is invalid."""


class InvalidConfigRoleError(Exception):
    """Raised when the role is invalid."""
