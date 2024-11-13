#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""All general exceptions."""


class WorkloadExecError(Exception):
    """Raised when a workload fails to exec a command."""

    def __init__(self, message: str):
        super().__init__(self)
        self.message = message


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