#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The different configuration models.

This file should contain the models that are used for the charm configuration.
The models specify the dataclasses and roles used to configure and fully specify a charm.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from importlib import resources as impresources
from importlib.abc import Traversable
from pathlib import Path

from single_kernel_mongo import observability_rules, templates
from single_kernel_mongo.config.literals import CharmKind, Substrates

TEMPLATE_DIRECTORY = impresources.files(templates)
OBSERVABILITY_DIRECTORY = impresources.files(observability_rules)


@dataclass(frozen=True)
class LogRotateConfig:
    """The logrotate parameters and useful static configuration."""

    max_log_size: str = "200M"
    max_rotations_to_keep: int = 25
    log_rotate_template: Traversable = TEMPLATE_DIRECTORY / "logrotate.j2"
    rendered_template: Path = Path("/etc/logrotate.d/mongodb")
    log_status_dir: Path = Path("/var/lib/logrotate")


@dataclass(frozen=True)
class ObservabilityConfig:
    """The config for the observability stack."""

    mongodb_exporter_port: int = 9216
    metrics_endpoints: list[dict[str, str]] = field(
        default_factory=lambda: [{"path": "/metrics", "port": "9216"}]
    )
    metrics_rules_dir: Traversable = OBSERVABILITY_DIRECTORY / "vm_prometheus_alert_rules"
    logs_rules_dir: Traversable = OBSERVABILITY_DIRECTORY / "loki"
    k8s_prometheus: Traversable = OBSERVABILITY_DIRECTORY / "k8s_prometheus_alert_rules"
    grafana_dashboards: Traversable = OBSERVABILITY_DIRECTORY / "grafana_dashboards"
    log_slots: list[str] = field(default_factory=lambda: ["charmed-mongodb:logs"])


OBSERVABILITY_CONFIG = ObservabilityConfig()


@dataclass(frozen=True)
class LdapConfig:
    """The config for the ldap library."""

    ldap_conf_template: Traversable = TEMPLATE_DIRECTORY / "ldap.conf.j2"


LDAP_CONFIG = LdapConfig()


@dataclass(frozen=True)
class OverrideFile:
    """Dataclass for the systemd override."""

    override_template: Path = Path(f"{TEMPLATE_DIRECTORY}") / "override.conf"
    override_path: Path = Path("override.conf")


OVERRIDE_FILES = OverrideFile()


@dataclass(frozen=True)
class AuditLogConfig:
    """Audit log related configuration."""

    format: str = "JSON"
    destination: str = "file"


@dataclass(frozen=True)
class CharmSpec:
    """Defines a role for the charm."""

    name: CharmKind
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
        "LOGS": "/var/log/mongodb",
        "ETC": "/etc",
        "VAR": "/var/",
        "BIN": "/usr/bin/",
        "SHELL": "/usr/bin/mongosh",
        "LICENSES": "/licenses",
    }
}

VM_MONGOD = CharmSpec(name=CharmKind.MONGOD, substrate=Substrates.VM, paths=VM_PATH["mongod"])
K8S_MONGOD = CharmSpec(name=CharmKind.MONGOD, substrate=Substrates.K8S, paths=K8S_PATH["mongod"])
VM_MONGOS = CharmSpec(name=CharmKind.MONGOS, substrate=Substrates.VM, paths=VM_PATH["mongod"])
K8S_MONGOS = CharmSpec(name=CharmKind.MONGOS, substrate=Substrates.K8S, paths=K8S_PATH["mongod"])

ROLES = {
    "vm": {"mongod": VM_MONGOD, "mongos": VM_MONGOS},
    "k8s": {"mongod": K8S_MONGOD, "mongos": K8S_MONGOS},
}


class LdapState(Enum):
    """Ldap State that can be mapped to a status."""

    EMPTY = auto()
    WRONG_ROLE = auto()
    MISSING_CERT_REL = auto()
    MISSING_LDAP_REL = auto()
    LDAP_SERVERS_MISMATCH = auto()
    WAITING_FOR_DATA = auto()
    WAITING_FOR_CERTS = auto()
    WAITING_FOR_LDAP_DATA = auto()
    MISSING_BASE_DN = auto()
    MISSING_CERT_CHAIN = auto()
    MISSING_LDAPS_URLS = auto()
    UNABLE_TO_BIND = auto()
    ACTIVE = auto()


class BackupState(Enum):
    """Backup state that can be mapped to a status."""

    EMPTY = auto()
    MISSING_CONFIG = auto()
    WAITING_PBM_START = auto()
    INCORRECT_CREDS = auto()
    INCOMPATIBLE_CONF = auto()
    UNKNOWN_ERROR = auto()
    BACKUP_RUNNING = auto()
    RESTORE_RUNNING = auto()
    WAITING_TO_SYNC = auto()
    FAILED_TO_CREATE_BUCKET = auto()
    CANT_CONFIGURE = auto()
    ACTIVE = auto()
