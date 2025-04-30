#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Operator for Mongos Related Charms."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, final

from lightkube.core.exceptions import ApiError
from ops.framework import Object
from ops.model import BlockedStatus, Relation, StatusBase, Unit, WaitingStatus
from pymongo.errors import PyMongoError
from typing_extensions import override

from single_kernel_mongo.config.literals import (
    INCOMPATIBLE_UPGRADE,
    UNHEALTHY_UPGRADE,
    CharmKind,
    MongoPorts,
    Substrates,
    UnitState,
)
from single_kernel_mongo.config.models import ROLES
from single_kernel_mongo.config.relations import ExternalRequirerRelations, RelationNames
from single_kernel_mongo.core.kubernetes_upgrades import KubernetesUpgrade
from single_kernel_mongo.core.machine_upgrades import MachineUpgrade
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import ExposeExternal, MongosCharmConfig
from single_kernel_mongo.events.cluster import ClusterMongosEventHandler
from single_kernel_mongo.events.database import DatabaseEventsHandler
from single_kernel_mongo.events.ldap import LDAPEventHandler
from single_kernel_mongo.events.tls import TLSEventsHandler
from single_kernel_mongo.events.upgrades import UpgradeEventHandler
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    DeferrableError,
    MissingConfigServerError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.managers.cluster import ClusterRequirer
from single_kernel_mongo.managers.config import MongosConfigManager
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.managers.ldap import LDAPManager
from single_kernel_mongo.managers.mongo import MongoManager
from single_kernel_mongo.managers.tls import TLSManager
from single_kernel_mongo.managers.upgrade import MongosUpgradeManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.helpers import unit_number
from single_kernel_mongo.workload import (
    get_mongos_workload_for_substrate,
)
from single_kernel_mongo.workload.mongos_workload import MongosWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm  # pragma: nocover

logger = logging.getLogger(__name__)

INVALID_EXTERNAL_CONFIG = "Config option for expose-external not valid."


@final
class MongosOperator(OperatorProtocol, Object):
    """Operator for Mongos Related Charms."""

    name = CharmKind.MONGOS
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
            self.charm.unit.get_container(self.name) if self.substrate == Substrates.K8S else None
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
        self.cluster_manager = ClusterRequirer(
            self, self.workload, self.state, self.substrate, RelationNames.CLUSTER
        )
        upgrade_backend = MachineUpgrade if self.substrate == Substrates.VM else KubernetesUpgrade
        self.upgrade_manager = MongosUpgradeManager(
            self, upgrade_backend, key=RelationNames.UPGRADE_VERSION.value
        )

        # LDAP Manager, which covers both send-ca-cert interface and ldap interface.
        self.ldap_manager = LDAPManager(
            self,
            self.state,
            self.substrate,
            ExternalRequirerRelations.LDAP,
            ExternalRequirerRelations.LDAP_CERT,
        )

        pod_name = self.model.unit.name.replace("/", "-")
        self.k8s = K8sManager(pod_name, self.model.name)

        self.tls_events = TLSEventsHandler(self)
        self.client_events = DatabaseEventsHandler(self, RelationNames.MONGOS_PROXY)
        self.cluster_event_handlers = ClusterMongosEventHandler(self)
        self.upgrade_events = UpgradeEventHandler(self)
        self.ldap_events = LDAPEventHandler(self)

    @property
    def config(self) -> MongosCharmConfig:
        """Returns the actual config."""
        return self.charm.parsed_config

    @override
    def on_install(self) -> None:
        """Handles the install event.

        We ensure the workload (container or snap) is present before setting
        the version and  setting the environment.
        """
        if not self.workload.workload_present:
            raise ContainerNotReadyError
        self.charm.unit.set_workload_version(self.workload.get_version())

    def _configure_workloads(self) -> None:
        self.tls_manager.push_tls_files_to_workload()
        self.ldap_manager.save_certificates(self.state.ldap.chain)
        self.handle_licenses()
        self.set_permissions()

        self.mongos_config_manager.set_environment()

    @override
    def on_start(self) -> None:
        """For this case, we don't start any service.

        Mongos charms need to be integrated to its config server before
        starting the service since it needs the config server URL to do so.
        """
        if not self.workload.workload_present:
            logger.debug("mongos installation is not ready yet.")
            raise ContainerNotReadyError

        self._configure_workloads()

        if self.substrate == Substrates.K8S:
            self.upgrade_manager._reconcile_upgrade()

        # start hooks are fired before relation hooks and `mongos` requires a config-server in
        # order to start. Wait to receive config-server info from the relation event before
        # starting `mongos` daemon
        if not self.state.mongos_cluster_relation:
            self.charm.status_manager.to_blocked("Missing relation to config-server.")

    @override
    def on_secret_changed(self, secret_label: str, secret_id: str) -> None:
        """Nothing happens in this handler for mongos operators."""
        pass

    @override
    def on_config_changed(self) -> None:
        """Handle configurations for expose-external.

        It is necessary to check that the option is valid, and if it has
        changed we must update external services, update TLS certificates and
        share connection information with client. This is because when we
        change our connectivity we update the IP address of mongos.
        """
        if self.substrate == Substrates.K8S:
            if self.config.expose_external == ExposeExternal.UNKNOWN:
                logger.error(
                    "External configuration: %s for expose-external is not valid, should be one of: %s",
                    self.charm.config["expose-external"],
                    "['nodeport', 'none']",
                )
                self.charm.status_manager.to_blocked(INVALID_EXTERNAL_CONFIG)
                return
            self.charm.status_manager.clear_status(BlockedStatus(INVALID_EXTERNAL_CONFIG))
            self.update_k8s_external_services()

            self.tls_manager.update_tls_sans()
            self.share_connection_info()

    @override
    def on_storage_attached(self) -> None:
        """Nothing happens in this handler for mongos operators."""
        pass

    @override
    def on_storage_detaching(self) -> None:
        """Nothing happens in this handler for mongos operators."""
        pass

    @override
    def on_leader_elected(self) -> None:
        """Just forward the call, this is for simplicity and typing.

        Leader elected events indicate that a unit may have been removed or
        lost connectivity. In these cases the hosts can be updated and we must
        share the most up to date information with the hosts.
        """
        self.share_connection_info()

    @override
    def on_update_status(self) -> None:
        """Many things happening here.

        First, as always we ensure the expose external value is valid.
        Then we ensure the integration to config server before doing anything else.
        We proceed to update client connections if needed and renew certificates as well if needed.
        """
        if self.substrate == Substrates.K8S:
            if self.config.expose_external == ExposeExternal.UNKNOWN:
                logger.error(
                    "External configuration: %s for expose-external is not valid, should be one of: %s",
                    self.charm.config["expose-external"],
                    "['nodeport', 'none']",
                )
                self.charm.status_manager.to_blocked("Config option for expose-external not valid.")
                return

        if self.get_sanity_check_status() is None:
            # In case any information was changed, we proceed to update the
            # connection information on the client databag.
            self.share_connection_info()

        # in K8s mongos charms which are exposed externally it is possible for
        # the node port to change. This can invalidate our current
        # certificates. when this happens we do not receive any notifications
        # from Juju so we must monitor it and request TLS integration to update
        # our SANS as necessary.
        # The connection info will be updated when we receive the new certificates.
        if self.substrate == Substrates.K8S:
            self.tls_manager.update_tls_sans()
            self.upgrade_manager._reconcile_upgrade()

        if self.charm.unit.status in (UNHEALTHY_UPGRADE, INCOMPATIBLE_UPGRADE):
            return

        self.charm.status_manager.process_and_share_statuses()

    @override
    def on_relation_joined(self) -> None:
        """Any relation event will just share the connection with the client."""
        self.share_connection_info()

    @override
    def on_relation_changed(self) -> None:
        """Any relation event will just share the connection with the client."""
        self.share_connection_info()

    @override
    def on_relation_departed(self, departing_unit: Unit | None) -> None:
        """Any relation event will just share the connection with the client."""
        self.share_connection_info()

    @override
    def on_stop(self) -> None:
        if self.substrate == Substrates.VM:
            return

        # Raise partition to prevent other units from restarting if an upgrade is in progress.
        # If an upgrade is not in progress, the leader unit will reset the partition to 0.
        current_unit_number = unit_number(self.state.unit_upgrade_peer_data)
        if self.state.k8s_manager.get_partition() < current_unit_number:
            self.state.k8s_manager.set_partition(value=current_unit_number)
            logger.debug(f"Partition set to {current_unit_number} during stop event")

        if not self.upgrade_manager._upgrade:
            logger.debug("Upgrade Peer relation missing during stop event")
            return

        # We update the state to set up the unit as restarting
        self.upgrade_manager._upgrade.unit_state = UnitState.RESTARTING

    @override
    def start_charm_services(self) -> None:
        """Start the charm services."""
        self.mongos_config_manager.set_environment()
        self.workload.start()

    @override
    def stop_charm_services(self) -> None:
        """Star the charm services."""
        self.workload.stop()

    @override
    def restart_charm_services(self, force: bool = False) -> None:
        """Restarts the charm with the new configuration."""
        if not self.state.cluster.config_server_uri:
            logger.error("Cannot start mongos without a config server db")
            raise MissingConfigServerError()

        self.mongos_config_manager.configure_and_restart(force=force)

    @override
    def is_relation_feasible(self, name: str) -> bool:
        """Checks if the relation is feasible.

        In the mongos case, we only allow the mongos proxy client relation.
        """
        return name == RelationNames.MONGOS_PROXY

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

    def remove_connection_info(self) -> None:
        """Deletes the information from the client databag."""
        for relation in self.state.client_relations:
            data_interface = DatabaseProviderData(
                self.model,
                relation.name,
            )
            data_interface.delete_relation_data(
                relation.id, fields=["username", "password", "uris"]
            )

    def _share_configuration(self):
        """Actually shares the configuration according to the substrate."""
        match self.substrate:
            case Substrates.VM:
                # We can't build the config if those are missing so we get it beforehand.
                username, password = self.state.get_user_credentials()
                if not username or not password:
                    return
                # We'll always have only one client relation as VM because
                # we're a subordinate charm, so this loop will run at most once.
                # For consistency however it's easier to "just" loop on the
                # `client_relations` method.
                for relation in self.state.client_relations:
                    self.mongo_manager.update_app_relation_data_for_config(
                        relation, self.state.mongos_config
                    )
            case Substrates.K8S:
                for relation in self.state.client_relations:
                    self.mongo_manager.update_app_relation_data(relation)

    def update_proxy_connection(self, relation: Relation):
        """Shares credentials to the client and opens the port if necessary."""
        data_interface = DatabaseProviderData(self.model, relation.name)
        if not self.charm.unit.is_leader():
            return
        new_database_name = data_interface.fetch_relation_field(relation.id, "database")
        new_extra_user_roles: set[str] = set(
            (
                data_interface.fetch_relation_field(
                    relation.id,
                    "extra-user-roles",
                )
                or "default"
            ).split(",")
        )
        external_connectivity = json.loads(
            data_interface.fetch_relation_field(relation.id, "external-node-connectivity")
            or "false"
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
    def update_k8s_external_services(self):
        """Updates the kubernetes external service if necessary.

        This function changes the kubernetes deployment so it's expected to do
        nothing on VM charms.
        """
        if self.substrate == Substrates.VM:
            # Nothing to do if we're a VM charm.
            return
        match self.config.expose_external:
            case ExposeExternal.NODEPORT:
                service = self.k8s.build_node_port_services(f"{MongoPorts.MONGOS_PORT}")
                self.k8s.apply_service(service)
            case ExposeExternal.NONE:
                self.k8s.delete_service()
            case ExposeExternal.UNKNOWN:
                return
        if not self.charm.unit.is_leader():
            return
        self.state.app_peer_data.expose_external = self.config.expose_external

    def update_keyfile(self, keyfile_content: str) -> bool:
        """Updates the keyfile in the app databag and on the workload."""
        current_key_file_lines = self.workload.read(self.workload.paths.keyfile)

        # Keyfile is either empty or one line long.
        current_key_file = current_key_file_lines[0] if current_key_file_lines else None

        if not keyfile_content or current_key_file == keyfile_content:
            return False

        self.workload.write(self.workload.paths.keyfile, keyfile_content)
        if self.charm.unit.is_leader():
            self.state.set_keyfile(keyfile_content)
        return True

    def update_config_server_db(self, config_server_db_uri: str) -> bool:
        """Updates the config server db uri if necessary."""
        if self.workload.config_server_db == config_server_db_uri:
            return False

        self.mongos_config_manager.set_environment()
        return True

    def is_mongos_running(self) -> bool:
        """Is the mongos service running ?"""
        # Useless to even try to connect if we haven't started the service.
        if not self.workload.active():
            return False

        if self.substrate == Substrates.VM:
            if self.state.app_peer_data.external_connectivity:
                host = self.state.unit_peer_data.internal_address + f":{MongoPorts.MONGOS_PORT}"
            else:
                host = self.state.formatted_socket_path
        else:
            host = self.state.unit_peer_data.internal_address + f":{MongoPorts.MONGOS_PORT}"

        uri = f"mongodb://{host}"

        return self.mongo_manager.mongod_ready(uri=uri)

    def get_sanity_check_status(self) -> StatusBase | None:
        """Retrieve statuses that directly relate to states of mongos.

        Those status would prevent other more advanced mongos statuses from
        being checked.
        """
        if not self.state.mongos_cluster_relation:
            logger.info(
                "Missing integration to config-server. mongos cannot run unless connected to config-server."
            )
            return BlockedStatus("Missing relation to config-server.")

        if status := self.cluster_manager.get_tls_statuses():
            logger.info(f"Invalid TLS integration: {status.message}")
            return status

        if not self.is_mongos_running():
            logger.info("mongos has not started yet")
            return WaitingStatus("Waiting for mongos to start.")

        return None

    # END: Helpers
