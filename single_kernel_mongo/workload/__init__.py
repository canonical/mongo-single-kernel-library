# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The different workloads and their code for mongo charms."""

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.core.k8s_workload import KubernetesWorkload
from single_kernel_mongo.core.vm_workload import VMWorkload
from single_kernel_mongo.workload.backup_workload import PBMWorkload
from single_kernel_mongo.workload.log_rotate_workload import LogRotateWorkload
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload
from single_kernel_mongo.workload.mongos_workload import MongosWorkload
from single_kernel_mongo.workload.monitor_workload import MongoDBExporterWorkload


class VMMongoDBWorkload(MongoDBWorkload, VMWorkload):
    """VM MongoDB Workload implementation."""

    ...


class VMMongosWorkload(MongosWorkload, VMWorkload):
    """VM Mongos Workload implementation."""

    ...


class VMPBMWorkload(PBMWorkload, VMWorkload):
    """VM PBM Workload implementation."""

    ...


class VMLogRotateDBWorkload(LogRotateWorkload, VMWorkload):
    """VM logrotate Workload implementation."""

    ...


class VMMongoDBExporterWorkload(MongoDBExporterWorkload, VMWorkload):
    """VM mongodb exporter Workload implementation."""

    ...


class KubernetesMongoDBWorkload(MongoDBWorkload, KubernetesWorkload):
    """Kubernetes MongoDB Workload implementation."""

    ...


class KubernetesMongosWorkload(MongosWorkload, KubernetesWorkload):
    """Kubernetes Mongos Workload implementation."""

    ...


class KubernetesPBMWorkload(PBMWorkload, KubernetesWorkload):
    """Kubernetes PBM Workload implementation."""

    ...


class KubernetesLogRotateDBWorkload(LogRotateWorkload, KubernetesWorkload):
    """Kubernetes logrotate Workload implementation."""

    ...


class KubernetesMongoDBExporterWorkload(MongoDBExporterWorkload, KubernetesWorkload):
    """Kubernetes mongodb exporter Workload implementation."""

    ...


def get_mongodb_workload_for_substrate(substrate: Substrates) -> type[MongoDBWorkload]:
    """Return substrate appropriate workload."""
    if substrate == Substrates.K8S:
        return KubernetesMongoDBWorkload
    return VMMongoDBWorkload


def get_mongos_workload_for_substrate(substrate: Substrates) -> type[MongosWorkload]:
    """Return substrate appropriate workload."""
    if substrate == Substrates.K8S:
        return KubernetesMongosWorkload
    return VMMongosWorkload


def get_pbm_workload_for_substrate(substrate: Substrates) -> type[PBMWorkload]:
    """Return substrate appropriate workload."""
    if substrate == Substrates.K8S:
        return KubernetesPBMWorkload
    return VMPBMWorkload


def get_logrotate_workload_for_substrate(substrate: Substrates) -> type[LogRotateWorkload]:
    """Return substrate appropriate workload."""
    if substrate == Substrates.K8S:
        return KubernetesLogRotateDBWorkload
    return VMLogRotateDBWorkload


def get_mongodb_exporter_workload_for_substrate(
    substrate: Substrates,
) -> type[MongoDBExporterWorkload]:
    """Return substrate appropriate workload."""
    if substrate == Substrates.K8S:
        return KubernetesMongoDBExporterWorkload
    return VMMongoDBExporterWorkload
