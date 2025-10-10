"""Common code for upgrades."""

import abc
import dataclasses
import logging
import secrets
import string

import charm_ as charm_api
import charm_refresh
import poetry.core.constraints.version as poetry_version
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError
from tenacity import RetryError, Retrying, retry, stop_after_attempt, wait_fixed
from typing_extensions import override

from single_kernel_mongo.config.literals import CharmKind
from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    BalancerStillRunningError,
    ClusterNotHealthyError,
    FailedToMovePrimaryError,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongo_connection import MongoConnection
from single_kernel_mongo.utils.mongodb_users import OperatorUser

logger = logging.getLogger()


WRITE_KEY = "write_value"
SHARD_NAME_INDEX = "_id"


@dataclasses.dataclass(eq=False)
class MongoDBRefresh(charm_refresh.CharmSpecificCommon, abc.ABC):
    """Common code for MongoDB Refreshes."""

    dependent: OperatorProtocol
    state: CharmState

    @classmethod
    @override
    def is_compatible(
        cls,
        *,
        old_charm_version: charm_refresh.CharmVersion,
        new_charm_version: charm_refresh.CharmVersion,
        old_workload_version: str,
        new_workload_version: str,
    ) -> bool:
        # Check charm version compatibility
        if not super().is_compatible(
            old_charm_version=old_charm_version,
            new_charm_version=new_charm_version,
            old_workload_version=old_workload_version,
            new_workload_version=new_workload_version,
        ):
            return False
        return cls.is_workload_compatible(
            old_workload_version=old_workload_version, new_workload_version=new_workload_version
        )

    @staticmethod
    def is_workload_compatible(
        old_workload_version: str,
        new_workload_version: str,
    ) -> bool:
        """Check if the workload versions are compatible.

        This method is called on the new charm code version. This means that it is responsible for
        determining which versions the charm code supports refreshing from - not refreshing to.
        """
        try:
            old_version = poetry_version.Version.parse(old_workload_version)
            new_version = poetry_version.Version.parse(new_workload_version)
        except ValueError:
            # Not enough values to unpack or cannot convert
            logger.error(
                "Unable to parse workload versions."
                f"Got {old_workload_version} to {new_workload_version}"
            )
            return False

        if old_version.major != new_version.major:
            logger.info(
                "Refreshing to a different major version workload is not supported. "
                f"Got {old_version.major} to {new_version.major}"
            )
            return False

        if old_version > new_version:
            logger.info(
                "Refreshing to an older minor version workload is not supported. "
                f"Got {old_version} to {new_version}"
            )
            return False

        return True

    def _mongodb_checks(self) -> None:
        """MongoDB specific checks."""
        try:
            self.wait_for_cluster_healthy()
        except RetryError as e:
            logger.error(
                "Cannot proceed with refresh. Failed to check cluster health, error: %s", e
            )
            raise charm_refresh.PrecheckFailed("Cluster is not healthy")

        try:
            self.move_primary_to_last_upgrade_unit()
        except FailedToMovePrimaryError:
            logger.error("Cluster failed to move primary before re-election.")
            raise charm_refresh.PrecheckFailed("Primary switchover failed")

        if not self.is_cluster_able_to_read_write():
            logger.error("Cluster cannot read/write to replicas")
            raise charm_refresh.PrecheckFailed("Cluster is not able to read/write to replicas")

        fcv = self.state.app_peer_data.feature_compatibility_version
        if not self.is_feature_compatibility_version(fcv):
            logger.info(
                "Not all replicas have the expected feature compatibility: %s",
                fcv,
            )
            raise charm_refresh.PrecheckFailed(f"Not all replicas have the expected FCV {fcv}.")

    def run_pre_refresh_checks_after_1_unit_refreshed(self):
        """Implement pre-refresh checks."""
        if not self.state.db_initialised:
            return

        if self.dependent.name == CharmKind.MONGOS:
            if not self.is_mongos_able_to_read_write():
                raise charm_refresh.PrecheckFailed("mongos is not able to read/write")
            return

        backup_state = self.dependent.backup_manager.backup_state()

        if backup_state == BackupState.BACKUP_RUNNING:
            raise charm_refresh.PrecheckFailed("Backup in progress.")
        if backup_state == BackupState.RESTORE_RUNNING:
            raise charm_refresh.PrecheckFailed("Restore in progress.")

        self._mongodb_checks()

        if not self.are_pre_upgrade_operations_config_server_successful():
            raise charm_refresh.PrecheckFailed("Failed to disabled balancer.")

    def run_pre_refresh_checks_before_any_units_refreshed(self):
        """Runs before the upgrade."""
        if not self.state.db_initialised:
            return
        if self.dependent.name == CharmKind.MONGOD:
            if not self.dependent.mongo_manager.mongod_ready():
                logger.error("Cannot proceed with refresh. Service mongod is not running.")
                raise charm_refresh.PrecheckFailed("mongod is not running")
        self.run_pre_refresh_checks_after_1_unit_refreshed()

    def wait_for_cluster_healthy(self) -> None:
        """Waits until the cluster is healthy after upgrading.

        After a unit restarts it can take some time for the cluster to settle.

        Raises:
            ClusterNotHealthyError.
        """
        for attempt in Retrying(stop=stop_after_attempt(10), wait=wait_fixed(1)):
            with attempt:
                if not self.is_cluster_healthy():
                    raise ClusterNotHealthyError()

    def is_cluster_healthy(self) -> bool:
        """Returns True if all nodes in the replica set / cluster are healthy."""
        try:
            return self.are_nodes_healthy()
        except (PyMongoError, OperationFailure, ServerSelectionTimeoutError) as e:
            logger.error(
                "Cannot proceed with refresh. Failed to check cluster health, error: %s",
                e,
            )
            return False

    def are_nodes_healthy(self) -> bool:
        """Returns true if all nodes in the MongoDB deployment are healthy."""
        if self.state.is_sharding_component and not self.state.has_sharding_integration:
            return True
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

    def are_replica_set_nodes_healthy(self, mongodb_config: MongoConfiguration) -> bool:
        """Returns true if all nodes in the MongoDB replica set are healthy."""
        with MongoConnection(mongodb_config) as mongod:
            rs_status = mongod.get_replset_status()
            rs_status = mongod.client.admin.command("replSetGetStatus")
            return not mongod.is_any_sync(rs_status)

    def get_cluster_mongos(self) -> MongoConfiguration:
        """Return a mongos configuration for the sharded cluster."""
        return (
            self.state.mongos_config
            if self.state.is_role(MongoDBRoles.CONFIG_SERVER)
            else self.state.mongos_config_for_user(
                OperatorUser, hosts=set(self.state.shard_state.mongos_hosts)
            )
        )

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

    def are_replicas_in_sharded_cluster_healthy(self, mongos_config: MongoConfiguration) -> bool:
        """Returns True if all replicas in the sharded cluster are healthy."""
        # dictionary of all replica sets in the sharded cluster
        for mongodb_config in self.get_all_replica_set_configs_in_cluster(mongos_config):
            if not self.are_replica_set_nodes_healthy(mongodb_config):
                logger.debug(f"Replica set: {mongodb_config.replset} contains unhealthy nodes.")
                return False

        return True

    def get_all_replica_set_configs_in_cluster(
        self, mongos_config: MongoConfiguration
    ) -> list[MongoConfiguration]:
        """Returns a list of all the mongodb_configurations for each application in the cluster."""
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

    def get_mongodb_config_from_shard_entry(self, shard_entry: dict) -> MongoConfiguration:
        """Returns a replica set MongoConfiguration based on a shard entry from ListShards."""
        # field hosts is of the form shard01/host1:27018,host2:27018,host3:27018
        shard_hosts = shard_entry["host"].split("/")[1]
        parsed_ips = {host.split(":")[0] for host in shard_hosts.split(",")}
        return self.state.mongodb_config_for_user(
            OperatorUser, parsed_ips, replset=shard_entry[SHARD_NAME_INDEX]
        )

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

    def get_primary_for_database(
        self, config: MongoConfiguration, shard_name: str, db_name: str
    ) -> bool:
        """Gets the primary for a database to ensure that it was correctly moved."""
        with MongoConnection(config) as mongos:
            db = mongos.client["config"]
            collection = db["databases"]
            result = collection.find_one({"_id": db_name})
            if not result:
                return False
            if result.get("primary", "") != shard_name:
                return False
        return True

    @retry(
        stop=stop_after_attempt(10),
        wait=wait_fixed(1),
        reraise=True,
    )
    def confirm_expected_write_cluster(
        self,
        config: MongoConfiguration,
        collection_name: str,
        expected_write_value: str,
        db_name: str | None = None,
    ) -> bool:
        """Returns True if the replica contains the expected write in the provided collection."""
        database = db_name or config.database
        with MongoConnection(config) as mongos:
            db = mongos.client[database]
            test_collection = db[collection_name]
            query = test_collection.find({}, {WRITE_KEY: 1})
            if query[0][WRITE_KEY] != expected_write_value:
                return False

        return True

    def add_write_to_replica_set(
        self, mongodb_config: MongoConfiguration, collection_name, write_value
    ) -> None:
        """Adds a the provided write to the admin database with the provided collection."""
        with MongoConnection(mongodb_config) as mongod:
            db = mongod.client["admin"]
            test_collection = db[collection_name]
            write = {WRITE_KEY: write_value}
            test_collection.insert_one(write)

    def confirm_expected_write_on_replica(
        self,
        host: str,
        db_name: str,
        collection: str,
        expected_write_value: str,
        secondary_config: MongoConfiguration,
    ):
        """Returns True if the replica contains the expected write in the provided collection."""
        secondary_config.hosts = {host}
        with MongoConnection(secondary_config, direct=True) as direct_secondary:
            db = direct_secondary.client[db_name]
            test_collection = db[collection]
            query = test_collection.find({}, {WRITE_KEY: 1})
            if query[0][WRITE_KEY] != expected_write_value:
                raise ClusterNotHealthyError

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
                self.confirm_expected_write_on_replica(
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

    def clear_tmp_collection(self, mongo_config: MongoConfiguration, collection_name: str) -> None:
        """Clears the temporary collection."""
        with MongoConnection(mongo_config) as mongo:
            db = mongo.client[mongo_config.database]
            db.drop_collection(collection_name)

    def clear_db_collection(self, mongos_config: MongoConfiguration, db_name: str) -> None:
        """Clears the temporary collection."""
        with MongoConnection(mongos_config) as mongos:
            mongos.client.drop_database(db_name)

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

    def is_mongos_able_to_read_write(self) -> bool:
        """Returns True if read and write is feasible from mongos."""
        _, collection_name, write_value = self.get_random_write_and_collection()
        config = self.state.mongos_config
        self.add_write_to_sharded_cluster(config, config.database, collection_name, write_value)

        write_replicated = self.confirm_expected_write_cluster(
            config,
            collection_name,
            write_value,
        )
        self.clear_tmp_collection(config, collection_name)

        if not write_replicated:
            logger.debug("Test read/write to cluster failed.")
            return False

        return True

    def move_primary_to_last_upgrade_unit(self) -> None:
        """Moves the primary to last unit that gets upgraded (the unit with the lowest id).

        Raises FailedToMovePrimaryError
        """
        # no need to move primary in the scenario of one unit
        if len(self.state.units) < 2:
            return

        with MongoConnection(self.state.mongo_config) as mongod:
            unit_with_lowest_id = self.state.reverse_order_peer_units[-1]
            unit_host = self.state.peer_unit_data(unit_with_lowest_id).internal_address
            if mongod.primary() == unit_host:
                logger.debug(
                    "Not moving Primary before refresh, primary is already on the last unit to refresh."
                )
                return

            logger.debug("Moving primary to unit: %s", unit_with_lowest_id)
            mongod.move_primary(new_primary_ip=unit_host)

    def is_sharded_cluster_able_to_read_write(self) -> bool:
        """Returns True if possible to write all cluster shards and read from all replicas."""
        mongos_config = self.get_cluster_mongos()
        with MongoConnection(mongos_config) as mongos:
            sc_status = mongos.client.admin.command("listShards")
            for shard in sc_status["shards"]:
                shard_name = shard[SHARD_NAME_INDEX]
                # force a write to a specific shard to ensure the primary on that shard can
                # receive writes
                db_name, collection_name, write_value = self.get_random_write_and_collection()
                self.add_write_to_sharded_cluster(
                    mongos_config, db_name, collection_name, write_value
                )

                # Can't move if there's not at least 2 shards
                if len(sc_status["shards"]) > 1:
                    mongos.client.admin.command("movePrimary", db_name, to=shard_name)

                has_correct_primary = self.get_primary_for_database(
                    mongos_config, shard_name, db_name
                )

                write_replicated = self.confirm_expected_write_cluster(
                    mongos_config,
                    collection_name,
                    write_value,
                    db_name=db_name,
                )

                self.clear_db_collection(mongos_config, db_name)
                if not (write_replicated and has_correct_primary):
                    logger.debug(f"Test read/write to shard {shard_name} failed.")
                    return False

        return True

    def is_cluster_able_to_read_write(self) -> bool:
        """Returns True if read and write is feasible for cluster."""
        try:
            if self.state.is_role(MongoDBRoles.REPLICATION):
                return self.is_replica_set_able_read_write()
            return self.is_sharded_cluster_able_to_read_write()
        except (ServerSelectionTimeoutError, OperationFailure):
            logger.warning("Impossible to select server, will try again later")
            return False

    def are_pre_upgrade_operations_config_server_successful(self) -> bool:
        """Runs pre-upgrade operations for config-server and returns True if successful."""
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return True

        if (
            isinstance(charm_api.event, charm_api.ActionEvent)
            and charm_api.event.action == "pre-refresh-check"
        ):
            return True

        try:
            self.turn_off_and_wait_for_balancer()
        except BalancerStillRunningError:
            logger.info("Balancer is still running. Please try the pre-refresh check later.")
            return False

        return True

    def is_feature_compatibility_version(self, expected_feature_version: str) -> bool:
        """Returns True if all nodes in the cluster have the expected FCV.

        Args:
            expected_feature_version: The version all nodes should have.
        """
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return self._is_mongos_feature_compatibility_version(expected_feature_version)
        return self._is_rs_feature_compatibility_version(expected_feature_version)

    def _is_mongos_feature_compatibility_version(self, expected_feature_version: str) -> bool:
        """Returns True if all nodes in the sharded cluster have the expected_feature_version.

        Note it is NOT sufficient to check only mongos or the individual shards. It is necessary to
        check each node according to MongoDB upgrade docs.
        """
        mongos_config = self.get_cluster_mongos()
        for replica_set_config in self.get_all_replica_set_configs_in_cluster(mongos_config):
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

    def _is_rs_feature_compatibility_version(self, expected_feature_version: str) -> bool:
        """Returns True if all nodes in the sharded cluster have the expected_feature_version.

        Note it is NOT sufficient to check only mongos or the individual shards. It is necessary to
        check each node according to MongoDB upgrade docs.
        """
        config = self.state.mongo_config
        for host in config.hosts:
            single_unit_config = self.state.mongodb_config_for_user(
                OperatorUser, hosts={host}, replset=config.replset, standalone=True
            )
            with MongoConnection(single_unit_config) as mongod:
                version = mongod.client.admin.command(
                    {"getParameter": 1, "featureCompatibilityVersion": 1}
                )
                if version["featureCompatibilityVersion"]["version"] != expected_feature_version:
                    return False
        return True

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
