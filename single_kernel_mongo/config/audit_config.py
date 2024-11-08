#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The audit log configuration values."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AuditLog:
    """Audit log related configuration."""

    format: str = "JSON"
    destination: str = "file"
