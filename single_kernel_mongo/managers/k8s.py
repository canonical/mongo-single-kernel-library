#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling k8s resources."""

import json
import logging
import math
import time
from functools import cache

from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.models.core_v1 import ServicePort, ServiceSpec
from lightkube.models.meta_v1 import ObjectMeta, OwnerReference
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.resources.core_v1 import Node, Pod, Service

from single_kernel_mongo.exceptions import (
    DeployedWithoutTrustError,
    FailedToFindNodePortError,
    FailedToFindServiceError,
)

# default logging from lightkube httpx requests is very noisy
logging.getLogger("lightkube").disabled = True
logging.getLogger("lightkube.core.client").disabled = True
logging.getLogger("httpx").disabled = True
logging.getLogger("httpcore").disabled = True

logger = logging.getLogger()


class K8sManager:
    """Manager for handling k8s resources for mongo charms."""

    def __init__(self, pod_name: str, namespace: str):
        self.pod_name: str = pod_name
        self.app_name: str = "-".join(pod_name.split("-")[:-1])
        self.namespace: str = namespace

    def __eq__(self, other: object) -> bool:
        """__eq__ dunder.

        Allows to get cache hit on calls on the same method from different instances of K8sManager
        as `self` is passed to methods.
        """
        return isinstance(other, K8sManager) and self.__dict__ == other.__dict__

    def __hash__(self) -> int:
        """__hash__ dunder.

        For dict like caching.
        """
        return hash(json.dumps(self.__dict__, sort_keys=True))

    @property
    def client(self) -> Client:
        """The Lightkube client."""
        return Client(  # pyright: ignore[reportArgumentType]
            field_manager=self.pod_name,
            namespace=self.namespace,
        )

    # BEGIN: getters
    def get_ttl_hash(self, seconds=120) -> int:
        """Gets a unique time hash for the cache, expiring after 2 minutes.

        We enforce a cache miss by using a ghost argument which changes every 2
        minutes to all getters.
        """
        return math.floor(time.time() / seconds)

    def get_pod(self, pod_name: str = "") -> Pod:
        """Gets the pod via k8s API."""
        return self._get_pod(pod_name, self.get_ttl_hash())

    def get_node(self, pod_name: str) -> Node:
        """Gets the node the port is running on."""
        return self._get_node(pod_name, self.get_ttl_hash())

    def get_node_ip(self, pod_name: str) -> str:
        """Gets the IP Address of the Node via the K8s API."""
        return self._get_node_ip(pod_name, self.get_ttl_hash())

    def get_service(self, service_name: str) -> Service | None:
        """Gets the Service via the K8s API."""
        return self._get_service(service_name, self.get_ttl_hash())

    def get_partition(self) -> int:
        """Gets the stateful set rolling partition."""
        return self._get_partition(self.get_ttl_hash())

    def get_revision(self) -> str:
        """Gets the stateful set revision."""
        return self._get_revision(self.get_ttl_hash())

    def list_revisions(self) -> dict[str, str]:
        """Returns a mapping of {unit name: Kubernetes controller revision hash.

        This is used for kubernetes upgrades to get the version of each container.
        """
        return self._list_revisions(self.get_ttl_hash())

    def get_unit_service_name(self, pod_name: str = "") -> str:
        """Returns the service name for the current unit."""
        pod_name = pod_name or self.pod_name
        return f"{pod_name}-external"

    # END: getters

    # BEGIN: helpers

    def on_deployed_without_trust(self) -> None:
        """Blocks the application and returns a specific error message."""
        logger.error("Kubernetes application needs `juju trust`")
        raise DeployedWithoutTrustError(app_name=self.app_name)

    def build_node_port_services(self, port: str) -> Service:
        """Builds a ClusterIP service for initial client connection."""
        pod = self.get_pod(pod_name=self.pod_name)
        if not pod.metadata or not pod.apiVersion or not pod.kind or not pod.metadata.uid:
            raise Exception(f"Could not find metadata for {pod}")

        return Service(
            metadata=ObjectMeta(
                name=self.get_unit_service_name(self.pod_name),
                namespace=self.namespace,
                # When we scale-down K8s will keep the Services for the deleted units around,
                # unless the Services' owner is also deleted.
                ownerReferences=[
                    OwnerReference(
                        apiVersion=pod.apiVersion,
                        kind=pod.kind,
                        name=self.pod_name,
                        uid=pod.metadata.uid,
                        blockOwnerDeletion=False,
                    )
                ],
            ),
            spec=ServiceSpec(
                externalTrafficPolicy="Local",
                type="NodePort",
                selector={
                    "statefulset.kubernetes.io/pod-name": self.pod_name,
                },
                ports=[
                    ServicePort(
                        protocol="TCP",
                        port=int(port),
                        targetPort=int(port),
                        name=f"{self.pod_name}-port",
                    )
                ],
            ),
        )

    def apply_service(self, service: Service) -> None:
        """Applies the given service."""
        try:
            self.client.apply(service)
        except ApiError as e:
            if e.status.code == 403:
                self.on_deployed_without_trust()
                return
            if (
                e.status.code == 422
                and isinstance(e.status.message, str)
                and "port is already allocated" in e.status.message
            ):
                logger.error(e.status.message)
                return
            raise

    def delete_service(self) -> None:
        """Deletes the service if it exists."""
        try:
            service_name = self.get_unit_service_name(self.pod_name)
            service = self.get_service(service_name=service_name)
        except ApiError as e:
            if e.status.code == 404:
                logger.debug(f"Could not find {service_name} to delete.")
                return
            raise

        if not service:
            raise Exception(f"No service {service_name}.")
        if not service.metadata:
            raise Exception(f"No metadata for {service_name}")
        if not service.metadata.name:
            raise Exception(f"No name in service metadata for {service_name}.")

        try:
            self.client.delete(Service, name=service.metadata.name)
        except ApiError as e:
            if e.status.code == 403:
                self.on_deployed_without_trust()
                return
            raise

    def set_partition(self, value: int) -> None:
        """Sets the partition value."""
        try:
            self.client.patch(
                res=StatefulSet,
                name=self.app_name,
                obj={"spec": {"updateStrategy": {"rollingUpdate": {"partition": value}}}},
            )
            self._get_partition.cache_clear()  # Clean the cache.
        except ApiError as e:
            if e.status.code == 403:
                self.on_deployed_without_trust()
                return
            raise

    def get_node_port(self, port_to_match: int) -> int:
        """Return node port for the provided port to match."""
        service_name = self.get_unit_service_name(self.pod_name)
        service = self.get_service(service_name=service_name)

        if not service or not service.spec or not service.spec.type == "NodePort":
            raise FailedToFindServiceError(f"No service found for port on {self.pod_name}")

        for svc_port in service.spec.ports or []:
            if svc_port.port == port_to_match:
                return svc_port.nodePort  # type: ignore[return-value]

        raise FailedToFindNodePortError(
            f"Unable to find NodePort for {port_to_match} for the {service} service"
        )

    # END: helpers

    # BEGIN: Private methods
    @cache
    def _get_pod(self, pod_name: str = "", *_) -> Pod:
        # Allows us to get pods from other peer units
        pod_name = pod_name or self.pod_name

        return self.client.get(
            res=Pod,
            name=pod_name,
        )

    @cache
    def _get_node(self, pod_name: str, *_) -> Node:
        pod = self.get_pod(pod_name)
        if not pod.spec or not pod.spec.nodeName:
            raise Exception("Could not find podSpec or nodeName")

        return self.client.get(
            Node,
            name=pod.spec.nodeName,
        )

    @cache
    def _get_node_ip(self, pod_name: str, *_) -> str:
        # all these redundant checks are because Lightkube's typing is awful
        node = self.get_node(pod_name)
        if not node.status or not node.status.addresses:
            raise Exception(f"No status found for {node}")

        for addresses in node.status.addresses:
            if addresses.type in ["ExternalIP", "InternalIP", "Hostname"]:
                return addresses.address

        return ""

    @cache
    def _get_service(self, service_name: str, *_) -> Service | None:
        return self.client.get(
            res=Service,
            name=service_name,
        )

    @cache
    def _get_partition(self, *_) -> int:
        partition = self.client.get(res=StatefulSet, name=self.app_name)
        if (
            not partition.spec
            or not partition.spec.updateStrategy
            or not partition.spec.updateStrategy.rollingUpdate
            or partition.spec.updateStrategy.rollingUpdate.partition
            is None  # partition == 0 is valid so we check for None explicitly.
        ):
            raise Exception("Incomplete stateful set.")
        return partition.spec.updateStrategy.rollingUpdate.partition

    @cache
    def _get_revision(self, *_) -> str:
        stateful_set = self.client.get(res=StatefulSet, name=self.app_name)
        if not stateful_set.status or not stateful_set.status.updateRevision:
            raise Exception("Incomplete stateful set")
        return stateful_set.status.updateRevision

    @cache
    def _list_revisions(self, *_) -> dict[str, str]:
        pods = self.client.list(res=Pod, labels={"app.kubernetes.io/name": self.app_name})

        def get_unit_name(pod_name: str) -> str:
            *app_name, unit_number = pod_name.split("-")
            return f'{"-".join(app_name)}/{unit_number}'

        # We can type ignore here
        return {
            get_unit_name(pod.metadata.name): pod.metadata.labels["controller-revision-hash"]  # type: ignore
            for pod in pods
        }
