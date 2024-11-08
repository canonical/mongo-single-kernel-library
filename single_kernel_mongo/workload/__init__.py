# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The different workloads and their code for mongo charms."""

from single_kernel_mongo.core.k8s_worload import KubernetesWorkload
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
