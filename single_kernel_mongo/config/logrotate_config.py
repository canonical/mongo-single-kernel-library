#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Logrotate parameters."""

from dataclasses import dataclass
from importlib import resources as impresources
from importlib.abc import Traversable
from pathlib import Path

from single_kernel_mongo import templates

TEMPLATE_DIRECTORY = impresources.files(templates)


@dataclass(frozen=True)
class LogRotateConfig:
    """The logrotate parameters and useful static configuration."""

    max_log_size: str = "50M"
    max_rotations_to_keep: int = 10
    log_rotate_template: Traversable = TEMPLATE_DIRECTORY / "logrotate.j2"
    rendered_template: Path = Path("/etc/logrotate.d/mongodb")
    log_status_dir: Path = Path("/var/lib/logrotate")
