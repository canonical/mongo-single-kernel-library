#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The different config models."""

from dataclasses import dataclass
from importlib import resources as impresources
from importlib.abc import Traversable
from pathlib import Path

from single_kernel_mongo import templates
from single_kernel_mongo.config.literals import RoleEnum, Substrates

TEMPLATE_DIRECTORY = impresources.files(templates)


@dataclass(frozen=True)
class LogRotateConfig:
    """The logrotate parameters and useful static configuration."""

    max_log_size: str = "50M"
    max_rotations_to_keep: int = 10
    log_rotate_template: Traversable = TEMPLATE_DIRECTORY / "logrotate.j2"
    rendered_template: Path = Path("/etc/logrotate.d/mongodb")
    log_status_dir: Path = Path("/var/lib/logrotate")


@dataclass(frozen=True)
class AuditLogConfig:
    """Audit log related configuration."""

    format: str = "JSON"
    destination: str = "file"


@dataclass(frozen=True)
class Role:
    """Defines a role for the charm."""

    name: RoleEnum
    substrate: Substrates
    paths: dict[str, str]


SNAP_NAME = "charmed-mongodb"

VM_PATH = {
    "mongod": {
        "ENVIRONMENT": "/etc/environment",
        "CONF": f"/var/snap/{SNAP_NAME}/current/etc/mongod",
        "DATA": f"/var/snap/{SNAP_NAME}/common/var/lib/mongodb",
        "LOGS": f"/var/snap/{SNAP_NAME}/common/var/log/mongodb",
        "ETC": f"/var/snap/{SNAP_NAME}/current/etc",
        "VAR": f"/var/snap/{SNAP_NAME}/common/var",
        "BIN": "/snap/bin",
        "SHELL": "/snap/bin/charmed-mongodb.mongosh",
        "LICENSES": f"/snap/{SNAP_NAME}/current/licenses",
    }
}
K8S_PATH = {
    "mongod": {
        "ENVIRONMENT": "/etc/environment",
        "CONF": "/etc/mongod",
        "DATA": "/var/lib/mongodb",
        "LOGS": "var/log/mongodb",
        "ETC": "/etc",
        "VAR": "/var/",
        "BIN": "/usr/bin/",
        "SHELL": "/usr/bin/mongosh",
        "LICENSES": "/licenses",
    }
}

VM_MONGOD = Role(name=RoleEnum.MONGOD, substrate=Substrates.VM, paths=VM_PATH["mongod"])
K8S_MONGOD = Role(name=RoleEnum.MONGOD, substrate=Substrates.K8S, paths=K8S_PATH["mongod"])
VM_MONGOS = Role(name=RoleEnum.MONGOS, substrate=Substrates.VM, paths=VM_PATH["mongod"])
K8S_MONGOS = Role(name=RoleEnum.MONGOS, substrate=Substrates.K8S, paths=K8S_PATH["mongod"])

ROLES = {
    "vm": {"mongod": VM_MONGOD, "mongos": VM_MONGOS},
    "k8s": {"mongod": K8S_MONGOD, "mongos": K8S_MONGOS},
}
