#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The substrate agnostic Upgrades manager.

In this class, we manage upgrades and their lifecycle.
"""

from __future__ import annotations

import copy
import logging
import secrets
import string
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Generic, TypeVar

import poetry.core.constraints.version as poetry_version
from data_platform_helpers.advanced_statuses.models import StatusObject, StatusObjectList
from data_platform_helpers.advanced_statuses.protocol import ManagerStatusProtocol
from data_platform_helpers.advanced_statuses.types import Scope
from ops import Object
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError
from tenacity import RetryError, Retrying, retry, stop_after_attempt, wait_fixed

from single_kernel_mongo.config.literals import (
    FEATURE_VERSION_6,
    SNAP,
    CharmKind,
    Substrates,
    UnitState,
)
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import UpgradeStatuses
from single_kernel_mongo.core.operator import MainWorkloadType, OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    BalancerStillRunningError,
    ClusterNotHealthyError,
    FailedToElectNewPrimaryError,
    FailedToMovePrimaryError,
    PeerRelationNotReadyError,
    PrecheckFailedError,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.helpers import mongodb_only
from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongo_connection import MongoConnection
from single_kernel_mongo.utils.mongodb_users import OperatorUser

if TYPE_CHECKING:
    from single_kernel_mongo.core.kubernetes_upgrades import KubernetesUpgrade
    from single_kernel_mongo.core.machine_upgrades import MachineUpgrade
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator
    from single_kernel_mongo.managers.mongos_operator import MongosOperator

T = TypeVar("T", covariant=True, bound=OperatorProtocol)

logger = logging.getLogger(__name__)

WRITE_KEY = "write_value"
SHARD_NAME_INDEX = "_id"


class UpgradeActions(str, Enum):
    """All upgrade actions."""

    RESUME_ACTION_NAME = "resume-refresh"
    PRECHECK_ACTION_NAME = "pre-refresh-check"
    FORCE_REFRESH_START = "force-refresh-start"


# BEGIN: Useful classes
class AbstractUpgrade(ABC):
    """In-place upgrades abstract class (typing).

    Based off specification: DA058 - In-Place Upgrades - Kubernetes v2
    (https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
    """

    def __init__(
        self,
        dependent: OperatorProtocol,
        workload: MainWorkloadType,
        state: CharmState,
        substrate: Substrates,
    ) -> None:
        self.charm = dependent.charm
        self.dependent = dependent
        self.workload = workload
        self.state = state
        self.substrate = substrate
        self.relation_name = RelationNames.UPGRADE_VERSION.value

        if not self.state.upgrade_relation:
            raise PeerRelationNotReadyError

        self.app_name = self.charm.app.name
        self.unit_name = self.charm.unit.name
        self._current_versions = {
            "charm": self.workload.get_charm_revision(),
            "workload": self.workload.get_version(),
        }

    @property
    def unit_state(self) -> UnitState | None:
        """Unit upgrade state."""
        return self.state.unit_upgrade_peer_data.unit_state

    @unit_state.setter
    def unit_state(self, value: UnitState) -> None:
        self.state.unit_upgrade_peer_data.unit_state = value

    @property
    def is_compatible(self) -> bool:
        """Whether upgrade is supported from previous versions."""
        if not (previous_version_strs := self.state.app_upgrade_peer_data.versions):
            logger.debug("`versions` missing from peer relation")
            return False

        # TODO charm versioning: remove `.split("+")` (which removes git hash before comparing)
        previous_version_strs["charm"] = previous_version_strs["charm"].split("+")[0]
        previous_versions: dict[str, poetry_version.Version] = {
            key: poetry_version.Version.parse(value) for key, value in previous_version_strs.items()
        }
        current_version_strs = copy.copy(self._current_versions)
        current_version_strs["charm"] = current_version_strs["charm"].split("+")[0]
        current_versions = {
            key: poetry_version.Version.parse(value) for key, value in current_version_strs.items()
        }
        try:
            # TODO Future PR: change this > sign to support downgrades
            if (
                previous_versions["charm"] > current_versions["charm"]
                or previous_versions["charm"].major != current_versions["charm"].major
            ):
                logger.debug(
                    f'{previous_versions["charm"]=} incompatible with {current_versions["charm"]=}'
                )
                return False
            if (
                previous_versions["workload"] > current_versions["workload"]
                or previous_versions["workload"].major != current_versions["workload"].major
            ):
                logger.debug(
                    f'{previous_versions["workload"]=} incompatible with {current_versions["workload"]=}'
                )
                return False
            logger.debug(
                f"Versions before refresh compatible with versions after refresh {previous_version_strs=} {self._current_versions=}"
            )
            return True
        except KeyError as exception:
            logger.debug(f"Version missing from {previous_versions=}", exc_info=exception)
            return False

    @abstractmethod
    def _get_unit_healthy_status(self) -> StatusObject:
        """Status shown during upgrade if unit is healthy."""
        raise NotImplementedError()

    def get_upgrade_unit_status(self) -> StatusObject | None:
        """Unit upgrade status."""
        if self.state.upgrade_in_progress:
            if not self.is_compatible:
                return UpgradeStatuses.INCOMPATIBLE_UPGRADE.value
            return self._get_unit_healthy_status()
        return None

    @property
    def app_status(self) -> StatusObject | None:
        """App upgrade status."""
        if not self.state.upgrade_in_progress:
            return None
        if self.dependent.name == CharmKind.MONGOD and not self.upgrade_resumed:
            # User confirmation needed to resume upgrade (i.e. upgrade second unit)
            # Statuses over 120 characters are truncated in `juju status` as of juju 3.1.6 and
            # 2.9.45
            resume_string = ""
            if len(self.state.units_upgrade_peer_data) > 1:
                resume_string = f"Verify highest unit is healthy & run `{UpgradeActions.RESUME_ACTION_NAME.value}` action. "
            return UpgradeStatuses.refreshing_needs_resume(resume_string)
        return UpgradeStatuses.REFRESH_IN_PROGRESS.value

    def set_versions_in_app_databag(self) -> None:
        """Save current versions in app databag.

        Used after next upgrade to check compatibility (i.e. whether that upgrade should be
        allowed).
        """
        assert not self.state.upgrade_in_progress
        logger.debug(f"Setting {self._current_versions=} in upgrade peer relation app databag")
        self.state.app_upgrade_peer_data.versions = self._current_versions
        logger.debug(f"Set {self._current_versions=} in upgrade peer relation app databag")

    @property
    @abstractmethod
    def upgrade_resumed(self) -> bool:
        """Whether user has resumed upgrade with Juju action."""
        raise NotImplementedError()

    @abstractmethod
    def reconcile_partition(self, *, from_event: bool = False, force: bool = False) -> str | None:
        """If ready, allow next unit to upgrade."""
        raise NotImplementedError()

    def pre_upgrade_check(self) -> None:
        """Check if this app is ready to upgrade.

        Runs before any units are upgraded

        Does *not* run during rollback

        On machines, this runs before any units are upgraded (after `juju refresh`)
        On machines & Kubernetes, this also runs during pre-upgrade-check action

        Can run on leader or non-leader unit

        Raises:
            PrecheckFailed: App is not ready to upgrade

        TODO Kubernetes: Run (some) checks after `juju refresh` (in case user forgets to run
        pre-upgrade-check action). Note: 1 unit will upgrade before we can run checks (checks may
        need to be modified).
        See https://chat.canonical.com/canonical/pl/cmf6uhm1rp8b7k8gkjkdsj4mya
        """
        logger.debug("Running pre-refresh checks")

        if self.dependent.name == CharmKind.MONGOS:
            if not self.state.db_initialised:
                return
            if not self.dependent.upgrade_manager.is_mongos_able_to_read_write():
                raise PrecheckFailedError("mongos is not able to read/write")
            return

        # TODO: if shard is getting upgraded but BOTH have same revision, then fail
        # https://warthogs.atlassian.net/browse/DPE-6397
        try:
            self.dependent.upgrade_manager.wait_for_cluster_healthy()
        except RetryError:
            logger.error("Cluster is not healthy")
            raise PrecheckFailedError("Cluster is not healthy")

        # On VM charms we can choose the order to upgrade, but not on K8s. In order to keep the
        # two charms in sync we decided to have the VM charm have the same upgrade order as the K8s
        # charm (i.e. highest to lowest.) Hence, we move the primary to the last unit to upgrade.
        # This prevents the primary from jumping around from unit to unit during the upgrade
        # procedure.
        try:
            self.dependent.upgrade_manager.move_primary_to_last_upgrade_unit()
        except FailedToMovePrimaryError:
            logger.error("Cluster failed to move primary before re-election.")
            raise PrecheckFailedError("Primary switchover failed")

        if not self.dependent.upgrade_manager.is_cluster_able_to_read_write():
            logger.error("Cluster cannot read/write to replicas")
            raise PrecheckFailedError("Cluster is not healthy")

        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            if not self.dependent.upgrade_manager.are_pre_upgrade_operations_config_server_successful():
                raise PrecheckFailedError("Pre-refresh operations on config-server failed.")

        self.add_status_data_for_legacy_upgrades()

    def add_status_data_for_legacy_upgrades(self):
        """Add dummy data for legacy upgrades.

        Upgrades supported on revision 212 and lower require status information from shards.
        however in upgrades on later reisions this information was determined not necessary and
        obsolete. It is true that this information is *not* needed for earlier revisions to
        facilitate earlier revisions we populate this data with ActiveStatus.
        """
        if not self.state.is_role(MongoDBRoles.SHARD):
            return

        if not self.state.shard_relation:
            return

        self.state.unit_shard_state.status_ready_for_upgrade = True


# END: Useful classes


class GenericMongoDBUpgradeManager(ManagerStatusProtocol, Generic[T], Object, ABC):
    """Substrate agnostif, abstract handler for upgrade events."""

    def __init__(
        self,
        dependent: T,
        upgrade_backend: type[KubernetesUpgrade | MachineUpgrade],
        *args,
        **kwargs,
    ):
        self.name = "upgrade"
        super(Generic, self).__init__(dependent, *args, **kwargs)  # type: ignore[arg-type]
        self.dependent = dependent
        self.substrate = self.dependent.substrate
        self.upgrade_backend = upgrade_backend
        self.charm = dependent.charm
        self.state = dependent.state

    @property
    def _upgrade(self) -> KubernetesUpgrade | MachineUpgrade | None:
        """Gets the correct upgrade backend if it exists."""
        try:
            return self.upgrade_backend(
                self.dependent,
                self.dependent.workload,
                self.state,
                self.dependent.substrate,
            )
        except PeerRelationNotReadyError:
            return None

    def _set_upgrade_status(self) -> None:
        """Sets the upgrade status in the unit and app status."""
        assert self._upgrade
        if self.charm.unit.is_leader():
            status_object = self._upgrade.app_status or UpgradeStatuses.ACTIVE_IDLE.value
            self.state.statuses.add(status_object, scope="app", component=self.name)
        # Set/clear upgrade unit status if no other unit status - upgrade status for units should
        # have the lowest priority.
        statuses: StatusObjectList = self.state.statuses.get(scope="unit", component=self.name)
        if (
            not statuses.root
            or UpgradeStatuses.WAITING_POST_UPGRADE_STATUS in statuses
            or statuses[0] == UpgradeStatuses.ACTIVE_IDLE  # Works because the list is sorted
            or any("is not up-to date with" in status.message for status in statuses)
        ):
            self.state.statuses.set(
                self._upgrade.get_upgrade_unit_status() or UpgradeStatuses.ACTIVE_IDLE.value,
                scope="unit",
                component=self.name,
            )

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Gets statuses for upgrades statelessly."""
        if not self._upgrade:
            return []

        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        match scope:
            case "unit":
                return [
                    self._upgrade.get_upgrade_unit_status() or UpgradeStatuses.ACTIVE_IDLE.value
                ]
            case "app":
                return [self._upgrade.app_status or UpgradeStatuses.ACTIVE_IDLE.value]
            case _:
                raise ValueError(f"Invalid scope {scope}")

    def store_initial_revisions(self) -> None:
        """Handle peer relation created event."""
        assert self._upgrade
        if self.substrate == Substrates.VM:
            self.state.unit_workload_container_version = SNAP.revision
            logger.debug(f"Saved {SNAP.revision=} in unit databag after first install")
        if self.dependent.name == CharmKind.MONGOD:
            self.state.unit_upgrade_peer_data.current_revision = (
                self.dependent.cross_app_version_checker.version  # type: ignore
            )
        if self.charm.unit.is_leader():
            if not self.state.upgrade_in_progress:
                # Save versions on initial start
                self._upgrade.set_versions_in_app_databag()

    @abstractmethod
    def run_post_app_upgrade_task(self) -> None:
        """Runs the post upgrade check to verify that the deployment is healthy."""
        raise NotImplementedError()

    def run_post_cluster_upgrade_task(self) -> None:
        """Runs the post upgrade check to verify that the deployment is healthy."""
        raise NotImplementedError()

    @abstractmethod
    def run_post_upgrade_checks(self, finished_whole_cluster: bool = False) -> None:
        """Runs post-upgrade checks for after an application upgrade."""
        raise NotImplementedError()

    def _reconcile_upgrade(self, during_upgrade: bool = False) -> None:
        """Handle upgrade events."""
        if not self._upgrade:
            logger.debug("Peer relation not available")
            return
        if not self.state.app_upgrade_peer_data.versions:
            logger.debug("Peer relation not ready")
            return
        if self.charm.unit.is_leader() and not self.state.upgrade_in_progress:
            # Run before checking `self._upgrade.is_compatible` in case incompatible upgrade was
            # forced & completed on all units.
            self._upgrade.set_versions_in_app_databag()

        if self.substrate == Substrates.VM and not self._upgrade.is_compatible:
            self._set_upgrade_status()
            return

        if self._upgrade.unit_state is UnitState.OUTDATED:
            self._on_vm_outdated()  # type: ignore
            return

        if self._upgrade.unit_state is UnitState.RESTARTING:  # Kubernetes only
            if not self._upgrade.is_compatible:
                logger.info(
                    f"Refresh incompatible. If you accept potential *data loss* and *downtime*, you can continue with `{UpgradeActions.RESUME_ACTION_NAME.value} force=true`"
                )
                self.state.statuses.add(
                    UpgradeStatuses.INCOMPATIBLE_UPGRADE.value,
                    scope="unit",
                    component=self.name,
                )
                return

        if self.dependent.substrate == Substrates.K8S:
            self._on_kubernetes_always(during_upgrade)  # type: ignore
        self._set_upgrade_status()

    def _on_kubernetes_always(self, during_upgrade: bool) -> None:
        """Always run this as part of kubernetes reconcile_upgade call."""
        if not self._upgrade:
            logger.debug("Peer relation not available")
            return
        if (
            not during_upgrade
            and self.state.db_initialised
            and self.dependent.mongo_manager.mongod_ready()
        ):
            self._upgrade.unit_state = UnitState.HEALTHY
        if self.charm.unit.is_leader():
            self._upgrade.reconcile_partition()
        self._set_upgrade_status()

    def _on_vm_outdated(self) -> None:
        """This is run on VMs if the current unit is outdated."""
        try:
            # This is the case only for VM which is OK
            authorized = self._upgrade.authorized  # type: ignore
        except PrecheckFailedError as exception:
            self._set_upgrade_status()
            self.state.statuses.add(exception.status, scope="unit", component=self.name)
            logger.debug(f"Set unit status to {exception.status}")
            logger.error(exception.status.message)
            return
        if authorized:
            self._set_upgrade_status()
            # We can type ignore because this branch is VM only
            self._upgrade.upgrade_unit(dependent=self.dependent)  # type: ignore
            # Refresh status after upgrade
        else:
            logger.debug("Waiting to upgrade")
        self._set_upgrade_status()

    # BEGIN: Helpers
    @mongodb_only
    def move_primary_to_last_upgrade_unit(self) -> None:
        """Moves the primary to last unit that gets upgraded (the unit with the lowest id).

        Raises FailedToMovePrimaryError
        """
        # no need to move primary in the scenario of one unit
        if len(self.state.units_upgrade_peer_data) < 2:
            return

        with MongoConnection(self.state.mongo_config) as mongod:
            unit_with_lowest_id = self.state.units_upgrade_peer_data[-1].unit
            unit_host = self.state.peer_unit_data(unit_with_lowest_id).internal_address
            if mongod.primary() == unit_host:
                logger.debug(
                    "Not moving Primary before refresh, primary is already on the last unit to refresh."
                )
                return

            logger.debug("Moving primary to unit: %s", unit_with_lowest_id)
            mongod.move_primary(new_primary_ip=unit_host)

    @mongodb_only
    def wait_for_cluster_healthy(
        self: GenericMongoDBUpgradeManager[MongoDBOperator],
    ) -> None:
        """Waits until the cluster is healthy after upgrading.

        After a unit restarts it can take some time for the cluster to settle.

        Raises:
            ClusterNotHealthyError.
        """
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(1)):
            with attempt:
                if not self.is_cluster_healthy():
                    raise ClusterNotHealthyError()

    @mongodb_only
    def is_cluster_healthy(self: GenericMongoDBUpgradeManager[MongoDBOperator]) -> bool:
        """Returns True if all nodes in the cluster/replica set are healthy."""
        # TODO: check mongos
        if not self.dependent.mongo_manager.mongod_ready():
            logger.error("Cannot proceed with refresh. Service mongod is not running")
            return False

        if self.state.is_sharding_component and not self.state.has_sharding_integration:
            return True

        try:
            return self.are_nodes_healthy()
        except (PyMongoError, OperationFailure, ServerSelectionTimeoutError) as e:
            logger.error(
                "Cannot proceed with refresh. Failed to check cluster health, error: %s",
                e,
            )
            return False

    @mongodb_only
    def are_nodes_healthy(self) -> bool:
        """Returns true if all nodes in the MongoDB deployment are healthy."""
        if self.state.is_role(MongoDBRoles.REPLICATION):
            return self.are_replica_set_nodes_healthy(self.state.mongo_config)

        mongos_config = self.get_cluster_mongos()
        if not self.are_shards_healthy(mongos_config):
            logger.debug(
                "One or more individual shards are not healthy - do not proceed with refresh."
            )
            return False

        if not self.are_replicas_in_sharded_cluster_healthy(mongos_config):
            logger.debug("One or more nodes are not healthy - do not proceed with refresh.")
            return False

        return True

    def are_replicas_in_sharded_cluster_healthy(self, mongos_config: MongoConfiguration) -> bool:
        """Returns True if all replicas in the sharded cluster are healthy."""
        # dictionary of all replica sets in the sharded cluster
        for mongodb_config in self.get_all_replica_set_configs_in_cluster():
            if not self.are_replica_set_nodes_healthy(mongodb_config):
                logger.debug(f"Replica set: {mongodb_config.replset} contains unhealthy nodes.")
                return False

        return True

    def are_shards_healthy(self, mongos_config: MongoConfiguration) -> bool:
        """Returns True if all shards in the cluster are healthy."""
        with MongoConnection(mongos_config) as mongos:
            if mongos.is_any_shard_draining():
                logger.debug("Cluster is draining a shard, do not proceed with refresh.")
                return False

            if not mongos.are_all_shards_aware():
                logger.debug("Not all shards are shard aware, do not proceed with refresh.")
                return False

            # Config-Server has access to all the related shard applications.
            if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
                relation_shards = {
                    relation.app.name for relation in self.state.config_server_relation
                }
                cluster_shards = mongos.get_shard_members()
                if len(relation_shards - cluster_shards):
                    logger.debug(
                        "Not all shards have been added/drained, do not proceed with refresh."
                    )
                    return False

        return True

    def get_all_replica_set_configs_in_cluster(self) -> list[MongoConfiguration]:
        """Returns a list of all the mongodb_configurations for each application in the cluster."""
        mongos_config = self.get_cluster_mongos()
        mongodb_configurations = []
        if self.state.is_role(MongoDBRoles.SHARD):
            # the hosts of the integrated mongos application are also the config-server hosts
            config_server_hosts = self.state.app_peer_data.mongos_hosts
            mongodb_configurations = [
                self.state.mongodb_config_for_user(
                    OperatorUser,
                    hosts=set(config_server_hosts),
                    replset=self.state.config_server_name,
                )
            ]
        elif self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            mongodb_configurations = [self.state.mongo_config]

        with MongoConnection(mongos_config) as mongos:
            sc_status = mongos.client.admin.command("listShards")
            for shard in sc_status["shards"]:
                mongodb_configurations.append(self.get_mongodb_config_from_shard_entry(shard))

        return mongodb_configurations

    def are_replica_set_nodes_healthy(self, mongodb_config: MongoConfiguration) -> bool:
        """Returns true if all nodes in the MongoDB replica set are healthy."""
        with MongoConnection(mongodb_config) as mongod:
            rs_status = mongod.get_replset_status()
            rs_status = mongod.client.admin.command("replSetGetStatus")
            return not mongod.is_any_sync(rs_status)

    def is_cluster_able_to_read_write(
        self: GenericMongoDBUpgradeManager[MongoDBOperator],
    ) -> bool:
        """Returns True if read and write is feasible for cluster."""
        try:
            if self.state.is_role(MongoDBRoles.REPLICATION):
                return self.is_replica_set_able_read_write()
            return self.is_sharded_cluster_able_to_read_write()
        except (ServerSelectionTimeoutError, OperationFailure):
            logger.warning("Impossible to select server, will try again later")
            return False

    def is_mongos_able_to_read_write(
        self: GenericMongoDBUpgradeManager[MongosOperator],
    ) -> bool:
        """Returns True if read and write is feasible from mongos."""
        _, collection_name, write_value = self.get_random_write_and_collection()
        config = self.state.mongos_config
        self.add_write_to_sharded_cluster(config, config.database, collection_name, write_value)

        write_replicated = self.confirm_excepted_write_cluster(
            config,
            collection_name,
            write_value,
        )
        self.clear_tmp_collection(config, collection_name)

        if not write_replicated:
            logger.debug("Test read/write to cluster failed.")
            return False

        return True

    @retry(
        stop=stop_after_attempt(10),
        wait=wait_fixed(1),
        reraise=True,
    )
    def confirm_excepted_write_cluster(
        self: GenericMongoDBUpgradeManager[MongosOperator],
        config: MongoConfiguration,
        collection_name: str,
        expected_write_value: str,
    ) -> bool:
        """Returns True if the replica contains the expected write in the provided collection."""
        with MongoConnection(config) as mongos:
            db = mongos.client[config.database]
            test_collection = db[collection_name]
            query = test_collection.find({}, {WRITE_KEY: 1})
            if query[0][WRITE_KEY] != expected_write_value:
                return False

        return True

    def is_sharded_cluster_able_to_read_write(
        self: GenericMongoDBUpgradeManager[MongoDBOperator],
    ) -> bool:
        """Returns True if possible to write all cluster shards and read from all replicas."""
        mongos_config = self.get_cluster_mongos()
        with MongoConnection(mongos_config) as mongos:
            sc_status = mongos.client.admin.command("listShards")
            for shard in sc_status["shards"]:
                # force a write to a specific shard to ensure the primary on that shard can
                # receive writes
                db_name, collection_name, write_value = self.get_random_write_and_collection()
                self.add_write_to_sharded_cluster(
                    mongos_config, db_name, collection_name, write_value
                )
                mongos.client.admin.command("movePrimary", db_name, to=shard[SHARD_NAME_INDEX])

                write_replicated = self.is_write_on_secondaries(
                    self.get_mongodb_config_from_shard_entry(shard),
                    collection_name,
                    write_value,
                    db_name,
                )

                self.clear_db_collection(mongos_config, db_name)
                if not write_replicated:
                    logger.debug(f"Test read/write to shard {shard['_id']} failed.")
                    return False

        return True

    def get_mongodb_config_from_shard_entry(self, shard_entry: dict) -> MongoConfiguration:
        """Returns a replica set MongoConfiguration based on a shard entry from ListShards."""
        # field hosts is of the form shard01/host1:27018,host2:27018,host3:27018
        shard_hosts = shard_entry["host"].split("/")[1]
        parsed_ips = {host.split(":")[0] for host in shard_hosts.split(",")}
        return self.state.mongodb_config_for_user(
            OperatorUser, parsed_ips, replset=shard_entry[SHARD_NAME_INDEX]
        )

    def get_cluster_mongos(self) -> MongoConfiguration:
        """Return a mongos configuration for the sharded cluster."""
        return (
            self.state.mongos_config
            if self.state.is_role(MongoDBRoles.CONFIG_SERVER)
            else self.state.mongos_config_for_user(
                OperatorUser, hosts=set(self.state.shard_state.mongos_hosts)
            )
        )

    def is_replica_set_able_read_write(self) -> bool:
        """Returns True if is possible to write to primary and read from replicas."""
        _, collection_name, write_value = self.get_random_write_and_collection()
        mongodb_config = self.state.mongo_config
        self.add_write_to_replica_set(mongodb_config, collection_name, write_value)
        write_replicated = self.is_write_on_secondaries(
            mongodb_config, collection_name, write_value
        )
        self.clear_tmp_collection(mongodb_config, collection_name)
        return write_replicated

    def clear_db_collection(self, mongos_config: MongoConfiguration, db_name: str) -> None:
        """Clears the temporary collection."""
        with MongoConnection(mongos_config) as mongos:
            mongos.client.drop_database(db_name)

    def clear_tmp_collection(self, mongo_config: MongoConfiguration, collection_name: str) -> None:
        """Clears the temporary collection."""
        with MongoConnection(mongo_config) as mongo:
            db = mongo.client[mongo_config.database]
            db.drop_collection(collection_name)

    @retry(
        stop=stop_after_attempt(10),
        wait=wait_fixed(1),
        reraise=True,
    )
    def confirm_excepted_write_on_replica(
        self,
        host: str,
        db_name: str,
        collection: str,
        expected_write_value: str,
        secondary_config: MongoConfiguration,
    ) -> None:
        """Returns True if the replica contains the expected write in the provided collection."""
        secondary_config.hosts = {host}
        with MongoConnection(secondary_config, direct=True) as direct_seconary:
            db = direct_seconary.client[db_name]
            test_collection = db[collection]
            query = test_collection.find({}, {WRITE_KEY: 1})
            if query[0][WRITE_KEY] != expected_write_value:
                raise ClusterNotHealthyError

    def get_random_write_and_collection(self) -> tuple[str, str, str]:
        """Returns a tuple for a random collection name and a unique write to add to it."""
        choices = string.ascii_letters + string.digits
        collection_name = "collection_" + "".join([secrets.choice(choices) for _ in range(32)])
        write_value = "unique_write_" + "".join([secrets.choice(choices) for _ in range(16)])
        db_name = "db_name_" + "".join([secrets.choice(choices) for _ in range(32)])
        return (db_name, collection_name, write_value)

    def add_write_to_sharded_cluster(
        self, mongos_config: MongoConfiguration, db_name, collection_name, write_value
    ) -> None:
        """Adds a the provided write to the provided database with the provided collection."""
        with MongoConnection(mongos_config) as mongod:
            db = mongod.client[db_name]
            test_collection = db[collection_name]
            write = {WRITE_KEY: write_value}
            test_collection.insert_one(write)

    def add_write_to_replica_set(
        self, mongodb_config: MongoConfiguration, collection_name, write_value
    ) -> None:
        """Adds a the provided write to the admin database with the provided collection."""
        with MongoConnection(mongodb_config) as mongod:
            db = mongod.client["admin"]
            test_collection = db[collection_name]
            write = {WRITE_KEY: write_value}
            test_collection.insert_one(write)

    def is_write_on_secondaries(
        self,
        mongodb_config: MongoConfiguration,
        collection_name,
        expected_write_value,
        db_name: str = "admin",
    ) -> bool:
        """Returns true if the expected write."""
        for replica_ip in mongodb_config.hosts:
            try:
                self.confirm_excepted_write_on_replica(
                    replica_ip,
                    db_name,
                    collection_name,
                    expected_write_value,
                    mongodb_config,
                )
            except ClusterNotHealthyError:
                # do not return False immediately - as it is
                logger.debug("Secondary with IP %s, does not contain the expected write.")
                return False

        return True

    def step_down_primary_and_wait_reelection(self) -> None:
        """Steps down the current primary and waits for a new one to be elected."""
        if len(self.state.internal_hosts) < 2:
            logger.warning(
                "No secondaries to become primary - upgrading primary without electing a new one, expect downtime."
            )
            return

        old_primary = self.dependent.primary_unit_name  # type: ignore
        with MongoConnection(self.state.mongo_config) as mongod:
            mongod.step_down_primary()

        for attempt in Retrying(stop=stop_after_attempt(30), wait=wait_fixed(1), reraise=True):
            with attempt:
                new_primary = self.dependent.primary_unit_name  # type: ignore
                if new_primary == old_primary:
                    raise FailedToElectNewPrimaryError()

    def are_pre_upgrade_operations_config_server_successful(self) -> bool:
        """Runs pre-upgrade operations for config-server and returns True if successful."""
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return False

        if not self.is_feature_compatibility_version(FEATURE_VERSION_6):
            logger.debug(
                "Not all replicas have the expected feature compatibility: %s",
                FEATURE_VERSION_6,
            )
            return False

        self.set_mongos_feature_compatibilty_version(FEATURE_VERSION_6)

        # pre-upgrade sequence runs twice. Once when the user runs the pre-upgrade action and
        # again automatically on refresh (just in case the user forgot to). Disabling the balancer
        # can negatively impact the cluster, so we only disable it once the upgrade sequence has
        # begun.
        if self._upgrade and self.state.upgrade_in_progress:
            try:
                self.turn_off_and_wait_for_balancer()
            except BalancerStillRunningError:
                logger.debug("Balancer is still running. Please try the pre-refresh check later.")
                return False

        return True

    def is_feature_compatibility_version(self, expected_feature_version: str) -> bool:
        """Returns True if all nodes in the sharded cluster have the expected_feature_version.

        Note it is NOT sufficient to check only mongos or the individual shards. It is necessary to
        check each node according to MongoDB upgrade docs.
        """
        for replica_set_config in self.get_all_replica_set_configs_in_cluster():
            for single_host in replica_set_config.hosts:
                single_replica_config = self.state.mongodb_config_for_user(
                    OperatorUser,
                    hosts={single_host},
                    replset=replica_set_config.replset,
                    standalone=True,
                )
                with MongoConnection(single_replica_config) as mongod:
                    version = mongod.client.admin.command(
                        {"getParameter": 1, "featureCompatibilityVersion": 1}
                    )
                    if (
                        version["featureCompatibilityVersion"]["version"]
                        != expected_feature_version
                    ):
                        return False

        return True

    def set_mongos_feature_compatibilty_version(self, feature_version: str) -> None:
        """Sets the mongos feature compatibility version."""
        with MongoConnection(self.state.mongos_config) as mongos:
            mongos.client.admin.command("setFeatureCompatibilityVersion", feature_version)

    @retry(
        stop=stop_after_attempt(10),
        wait=wait_fixed(1),
        reraise=True,
    )
    def turn_off_and_wait_for_balancer(self) -> None:
        """Sends the stop command to the balancer and wait for it to stop running."""
        with MongoConnection(self.state.mongos_config) as mongos:
            mongos.client.admin.command("balancerStop")
            balancer_state = mongos.client.admin.command("balancerStatus")
            if balancer_state["mode"] != "off":
                raise BalancerStillRunningError("balancer is still Running.")

    # END: helpers
