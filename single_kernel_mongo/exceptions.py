#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""All general exceptions."""


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


class WorkloadServiceError(Exception):
    """Raised when a service fail to start/stop/restart."""


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


class FailedToFindNodePortError(Exception):
    """Raised when NodePort cannot be found, but is excepted to be present."""


class FailedToFindServiceError(Exception):
    """Raised when service cannot be found, but is excepted to be present."""


class FailedToGetHostsError(Exception):
    """Raised when we fail to get the host."""


class SecretAlreadyExistsError(Exception):
    """Raised when we try to push a secret that already exists."""
