#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Operator for Mongos Related Charms."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, final
from urllib.parse import quote

from lightkube.core.exceptions import ApiError
from ops.framework import Object
from ops.model import Relation, Unit
from pymongo.errors import PyMongoError
from typing_extensions import override

from single_kernel_mongo.config.literals import KindEnum, MongoPorts, Substrates
from single_kernel_mongo.config.models import ROLES
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import ExposeExternal
from single_kernel_mongo.events.database import DatabaseEventsHandler
from single_kernel_mongo.events.tls import TLSEventsHandler
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    DeferrableError,
    MissingConfigServerError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.managers.config import MongosConfigManager
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.managers.mongo import MongoManager
from single_kernel_mongo.managers.tls import TLSManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.workload import (
    get_mongos_workload_for_substrate,
)
from single_kernel_mongo.workload.mongos_workload import MongosWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm  # pragma: nocover
logger = logging.getLogger(__name__)


@final
class MongosOperator(OperatorProtocol, Object):
    """Operator for Mongos Related Charms."""

    name = KindEnum.MONGOS
    workload: MongosWorkload

    def __init__(self, charm: AbstractMongoCharm):
        super(OperatorProtocol, self).__init__(charm, self.name)
        self.charm = charm
        self.substrate: Substrates = self.charm.substrate
        self.role = ROLES[self.substrate][self.name]
        self.state = CharmState(
            self.charm,
            self.substrate,
            self.role,
        )

        container = (
            self.charm.unit.get_container(CONTAINER) if self.substrate == Substrates.K8S else None
        )

        self.workload = get_mongos_workload_for_substrate(self.substrate)(
            role=self.role, container=container
        )
        self.mongos_config_manager = MongosConfigManager(
            self.config,
            self.workload,
            self.state,
        )
        self.mongo_manager = MongoManager(
            self,
            self.workload,
            self.state,
            self.substrate,
        )
        self.tls_manager = TLSManager(
            self,
            self.workload,
            self.state,
            self.substrate,
        )
        pod_name = self.model.unit.name.replace("/", "-")
        self.k8s = K8sManager(pod_name, self.model.name)

        self.tls_events = TLSEventsHandler(self)
        self.client_events = DatabaseEventsHandler(self, RelationNames.MONGOS_PROXY)

    @property
    def config(self):
        """Returns the actual config."""
        return self.charm.parsed_config

    @override
    def on_install(self) -> None:
        if not self.workload.workload_present:
            raise ContainerNotReadyError
        self.charm.unit.set_workload_version(self.workload.get_version())
        self.mongos_config_manager.set_environment()

    @override
    def on_start(self) -> None:
        if not self.workload.workload_present:
            logger.debug("mongos installation is not ready yet.")
            raise ContainerNotReadyError
        self.handle_licenses()
        # start hooks are fired before relation hooks and `mongos` requires a config-server in
        # order to start. Wait to receive config-server info from the relation event before
        # starting `mongos` daemon
        self.charm.status_manager.to_blocked("Missing relation to config-server.")

    @override
    def on_secret_changed(self, secret_label: str, secret_id: str) -> None:
        # Nothing happens in this handler for mongos operators
        pass

    @override
    def on_config_changed(self) -> None:
        if self.substrate == Substrates.K8S:
            if self.config.expose_external == ExposeExternal.UNKNOWN:
                logger.error(
                    "External configuration: %s for expose-external is not valid, should be one of: %s",
                    self.charm.config["expose-external"],
                    "['nodeport', 'none']",
                )
                self.charm.status_manager.to_blocked("Config option for expose-external not valid.")
            # TODO: Updated external service

            self.tls_manager.update_tls_sans()
            # TODO: Updated client related hosts
            self.share_connection_info()

    @override
    def on_storage_attached(self) -> None:
        # Nothing happens in this handler for mongos operators
        pass

    @override
    def on_storage_detaching(self) -> None:
        # Nothing happens in this handler for mongos operators
        pass

    @override
    def on_leader_elected(self) -> None:
        # Just forward the call, this is for simplicity and typing.
        self.share_connection_info()

    @override
    def on_update_status(self) -> None:
        if self.substrate == Substrates.K8S:
            if self.config.expose_external == ExposeExternal.UNKNOWN:
                logger.error(
                    "External configuration: %s for expose-external is not valid, should be one of: %s",
                    self.charm.config["expose-external"],
                    "['nodeport', 'none']",
                )
                self.charm.status_manager.to_blocked("Config option for expose-external not valid.")
                return
        if not self.state.mongos_cluster_relation:
            logger.info(
                "Missing integration to config-server. mongos cannot run unless connected to config-server."
            )
            self.charm.status_manager.to_blocked("Missing relation to config-server.")
            return

        # TODO : Check TLS status

        if not self.is_mongos_running():
            logger.info("mongos has not started yet")
            self.charm.status_manager.to_waiting("Waiting for mongos to start.")
            return

        if self.substrate == Substrates.K8S:
            self.tls_manager.update_tls_sans()

        self.charm.status_manager.to_active("")

    @override
    def on_relation_joined(self) -> None:
        self.share_connection_info()

    @override
    def on_relation_changed(self) -> None:
        self.share_connection_info()

    @override
    def on_relation_departed(self, departing_unit: Unit | None) -> None:
        self.share_connection_info()

    @override
    def on_stop(self) -> None:
        pass

    @override
    def start_charm_services(self) -> None:
        self.workload.start()

    @override
    def stop_charm_services(self) -> None:
        self.workload.stop()

    @override
    def restart_charm_services(self) -> None:
        self.workload.stop()
        if not self.state.cluster.config_server_uri:
            logger.error("Cannot start mongos without a config server db")
            raise MissingConfigServerError()

        self.mongos_config_manager.set_environment()
        self.workload.start()

    @override
    def is_relation_feasible(self, name: str) -> bool:
        if name != RelationNames.MONGOS_PROXY:
            return False
        return True

    def share_connection_info(self):
        """Shares the connection information of clients."""
        if not self.state.db_initialised:
            return
        if not self.charm.unit.is_leader():
            return
        try:
            self._share_configuration()
        except PyMongoError as e:
            raise DeferrableError(f"updating app relation data because of {e}")
        except ApiError as e:  # Raised for k8s
            if e.status.code == 404:
                raise DeferrableError(
                    "updating app relation data since service not found for more or one units"
                )
            raise

    def _share_configuration(self):
        """Actually shares the configuration according to the substrate."""
        match self.substrate:
            case Substrates.VM:
                if not self.state.mongos_config.password or not self.state.mongos_config.username:
                    return
                for relation in self.state.client_relations:
                    self.mongo_manager.update_app_relation_data_for_config(
                        relation, self.state.mongos_config
                    )
            case Substrates.K8S:
                for relation in self.state.client_relations:
                    self.mongo_manager.update_app_relation_data(relation)

    def share_credentials(self, relation: Relation):
        """Shares credentials to the client."""
        data_interface = DatabaseProviderData(self.model, relation.name)
        if not self.charm.unit.is_leader():
            return
        new_database_name = data_interface.fetch_relation_field(relation.id, "database")
        new_extra_user_roles: set[str] = set(
            json.loads(
                data_interface.fetch_relation_field(
                    relation.id,
                    "extra-user-roles",
                )
                or "[]"
            )
        )
        external_connectivity = json.loads(
            data_interface.fetch_relation_field(relation.id, "external-node-conectivity") or "false"
        )

        if new_database_name and new_database_name != self.state.app_peer_data.database:
            self.state.app_peer_data.database = new_database_name
            if self.state.mongos_cluster_relation:
                self.state.cluster.database = new_database_name

        if new_extra_user_roles != self.state.app_peer_data.extra_user_roles:
            self.state.app_peer_data.extra_user_roles = new_extra_user_roles
            if self.state.mongos_cluster_relation:
                self.state.cluster.extra_user_roles = new_extra_user_roles

        self.state.app_peer_data.external_connectivity = external_connectivity

        if external_connectivity:
            self.charm.unit.open_port("tcp", MongoPorts.MONGOS_PORT)

    # BEGIN: Helpers
    def update_external_services(self):
        """Updates the external service if necessary."""
        if self.substrate == Substrates.K8S:
            if self.config.expose_external == ExposeExternal.NODEPORT:
                service = self.k8s.build_node_port_services(str(MongoPorts.MONGOS_PORT))
                self.k8s.apply_service(service)
            else:
                self.k8s.delete_service()
            self.state.app_peer_data.expose_external = self.config.expose_external

    def is_mongos_running(self) -> bool:
        """Is the mongos service running ?"""
        # Useless to even try to connect if we haven't started the service.
        if not self.workload.active():
            return False

        if self.substrate == Substrates.VM:
            if self.state.app_peer_data.external_connectivity:
                uri = self.state.unit_peer_data.host + f":{MongoPorts.MONGOS_PORT}"
            else:
                uri = quote(f"{self.workload.paths.socket_path}", safe="")
        else:
            uri = self.state.unit_peer_data.host + f":{MongoPorts.MONGOS_PORT}"

        return self.mongo_manager.mongod_ready(uri=uri)

    # END: Helpers
