#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Backup state."""


class BackupState:
    """The stored state for the TLS relation."""

    @property
    def pbm_uri(self) -> str:
        """Is TLS enabled."""
        return ""
