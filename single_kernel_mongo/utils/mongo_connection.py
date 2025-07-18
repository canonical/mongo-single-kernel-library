# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Definition of MongoDB Connections."""

import logging
import re
from typing import Any

from bson import json_util
from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError
from tenacity import (
    RetryError,
    Retrying,
    before_log,
    retry,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
)

from single_kernel_mongo.config.literals import MongoPorts
from single_kernel_mongo.exceptions import (
    BalancerNotEnabledError,
    FailedToMovePrimaryError,
    NotDrainedError,
    NotEnoughSpaceError,
    ShardNotInClusterError,
    ShardNotPlannedForRemovalError,
)
from single_kernel_mongo.utils.helpers import hostname_from_hostport, hostname_from_shardname
from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongo_error_codes import MongoErrorCodes
from single_kernel_mongo.utils.mongodb_users import DBPrivilege, SystemDBS

logger = logging.getLogger(__name__)

SHARD_AWARE_STATE = 1


class NotReadyError(PyMongoError):
    """Raised when mongo is not ready."""

    ...


class MongoConnection:
    """In this class we create connection object to Mongo[s/db].

    This class is meant for agnostic functions in mongos and mongodb.

    Real connection is created on the first call to Mongo[s/db].
    Delayed connectivity allows to firstly check database readiness
    and reuse the same connection for an actual query later in the code.

    Connection is automatically closed when object destroyed.
    Automatic close allows to have more clean code.

    Note that connection when used may lead to the following pymongo errors: ConfigurationError,
    ConfigurationError, OperationFailure. It is suggested that the following pattern be adopted
    when using MongoDBConnection:

    with MongoMongos(MongoConfig) as mongo:
        try:
            mongo.<some operation from this class>
        except ConfigurationError, OperationFailure:
            <error handling as needed>
    """

    def __init__(self, config: MongoConfiguration, uri: str | None = None, direct: bool = False):
        """A MongoDB client interface.

        Args:
            config: MongoDB Configuration object.
            uri: allow using custom MongoDB URI, needed for replSet init.
            direct: force a direct connection to a specific host, avoiding
                    reading replica set configuration and reconnection.
        """
        self.config = config

        if uri is None:
            uri = config.uri

        self.client: MongoClient = MongoClient(
            uri,
            directConnection=direct,
            connect=False,
            serverSelectionTimeoutMS=1000,
            connectTimeoutMS=2000,
        )

    def __enter__(self):
        """Return a reference to the new connection."""
        return self

    def __exit__(self, *args, **kwargs):
        """Disconnect from MongoDB client."""
        self.client.close()

    @property
    def is_ready(self) -> bool:
        """Is the MongoDB server ready for services requests.

        Returns:
            True if services is ready False otherwise. Retries over a period of 60 seconds times to
            allow server time to start up.
        """
        try:
            for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3)):
                with attempt:
                    # The ping command is cheap and does not require auth.
                    self.client.admin.command("ping")
        except RetryError:
            return False

        return True

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(5),
        reraise=True,
        before=before_log(logger, logging.DEBUG),
    )
    def init_replset(self, host: str) -> None:
        """Create replica set config the first time.

        Raises:
            ConfigurationError, ConfigurationError, OperationFailure
        """
        config = {"_id": self.config.replset, "members": [{"_id": 0, "host": host}]}
        try:
            self.client.admin.command("replSetInitiate", config)
        except OperationFailure as e:
            if e.code not in (
                MongoErrorCodes.UNAUTHORIZED,
                MongoErrorCodes.ALREADY_INITIALIZED,
            ):
                # Unauthorized error can be raised only if initial user were
                #     created the step after this.
                # AlreadyInitialized error can be raised only if this step
                #     finished.
                logger.error("Cannot initialize replica set. error=%r", e)
                raise e

    def create_user(self, username: str, password: str, roles: list[DBPrivilege]):
        """Create user.

        Grant read and write privileges for specified database.
        """
        try:
            self.client.admin.command(
                "createUser",
                value=username,
                pwd=password,
                roles=roles,
                mechanisms=["SCRAM-SHA-256"],
            )
        except OperationFailure as e:
            if e.code == MongoErrorCodes.USER_ALREADY_EXISTS:
                logger.info("Role already exists")
                return
            logger.error("Cannot add user. error=%r", e)
            raise

    def update_user(self, config: MongoConfiguration):
        """Update grants on database."""
        self.client.admin.command(
            "updateUser",
            value=config.username,
            roles=config.supported_roles,
        )

    def set_user_password(self, username: str, password: str):
        """Update the password."""
        self.client.admin.command(
            "updateUser",
            value=username,
            pwd=password,
        )

    def drop_user(self, username: str):
        """Drop user."""
        self.client.admin.command("dropUser", username)

    def create_role(self, role_name: str, privileges: dict, roles: list | None = None) -> None:
        """Creates a new role.

        Args:
            role_name: name of the role to be added.
            privileges: privileges to be associated with the role.
            roles: List of roles from which this role inherits privileges.
        """
        if roles is None:
            roles = []
        try:
            self.client.admin.command("createRole", role_name, privileges=[privileges], roles=roles)
        except OperationFailure as e:
            if e.code == MongoErrorCodes.ROLE_ALREADY_EXISTS:
                logger.info("Role already exists")
                return
            logger.error("Cannot add role. error=%r", e)
            raise

    def set_replicaset_election_priority(
        self, priority: int | float, ignore_member: str | None = None
    ) -> None:
        """Set the election priority for the entire replica set."""
        rs_config = self.client.admin.command("replSetGetConfig")
        rs_config = rs_config["config"]
        rs_config["version"] += 1

        # keep track of the original configuration before setting the priority, reconfiguring the
        # replica set can result in primary re-election, which would would like to avoid when
        # possible.
        original_rs_config = rs_config

        for member in rs_config["members"]:
            if member["host"] == ignore_member:
                continue

            member["priority"] = priority

        if original_rs_config == rs_config:
            return

        logger.debug("rs_config: %r", rs_config)
        self.client.admin.command("replSetReconfig", rs_config)

    def get_replset_members(self) -> set[str]:
        """Get a replica set members.

        Returns:
            A set of the replica set members as reported by mongod.

        Raises:
            ConfigurationError, ConfigurationError, OperationFailure
        """
        rs_status = self.client.admin.command("replSetGetStatus")
        curr_members = [hostname_from_hostport(member["name"]) for member in rs_status["members"]]
        return set(curr_members)

    def get_replset_status(self) -> dict:
        """Get a replica set status as a dict.

        Returns:
            A set of the replica set members along with their status.

        Raises:
            ConfigurationError, ConfigurationError, OperationFailure
        """
        rs_status = self.client.admin.command("replSetGetStatus")
        rs_status_parsed = {}
        for member in rs_status["members"]:
            member_name = hostname_from_hostport(member["name"])
            rs_status_parsed[member_name] = member["stateStr"]

        return rs_status_parsed

    @retry(
        stop=stop_after_attempt(20),
        wait=wait_fixed(3),
        reraise=True,
        before=before_log(logger, logging.DEBUG),
    )
    def remove_replset_member(self, hostname: str) -> None:
        """Remove member from replica set config inside MongoDB.

        Raises:
            ConfigurationError, ConfigurationError, OperationFailure, NotReadyError
        """
        rs_config = self.client.admin.command("replSetGetConfig")
        rs_status = self.client.admin.command("replSetGetStatus")

        # When we remove member, to avoid issues when majority members is removed, we need to
        # remove next member only when MongoDB forget the previous removed member.
        if self.is_any_removing(rs_status):
            # removing from replicaset is fast operation, lets @retry(3 times with a 5sec timeout)
            # before giving up.
            raise NotReadyError

        # avoid downtime we need to reelect new primary if removable member is the primary.
        if self.primary(rs_status) == hostname:
            logger.debug("Stepping down from primary.")
            self.client.admin.command("replSetStepDown", {"stepDownSecs": "60"})

        rs_config["config"]["version"] += 1
        rs_config["config"]["members"] = [
            member
            for member in rs_config["config"]["members"]
            if hostname != hostname_from_hostport(member["host"])
        ]
        logger.debug("rs_config: %r", json_util.dumps(rs_config["config"]))
        self.client.admin.command("replSetReconfig", rs_config["config"])

    def add_replset_member(self, hostname: str) -> None:
        """Adds a member to replicaset config inside MongoDB.

        Raises:
            ConfigurationError, ConfigurationError, OperationFailure, NotReadyError
        """
        rs_config = self.client.admin.command("replSetGetConfig")
        rs_status = self.client.admin.command("replSetGetStatus")

        # When we add a new member, MongoDB transfer data from existing member to new.
        # Such operation reduce performance of the cluster. To avoid huge performance
        # degradation, before adding new members, it is needed to check that all other
        # members finished init sync.
        if self.is_any_sync(rs_status):
            raise NotReadyError

        # Avoid reusing IDs, according to the doc
        # https://www.mongodb.com/docs/manual/reference/replica-configuration/
        max_id = max([int(member["_id"]) for member in rs_config["config"]["members"]])

        new_member = {"_id": max_id + 1, "host": hostname}

        rs_config["config"]["version"] += 1
        rs_config["config"]["members"].append(new_member)
        logger.debug("rs_config: %r", rs_config["config"])
        self.client.admin.command("replSetReconfig", rs_config["config"])

    def get_databases(self) -> set[str]:
        """Return list of all non-default databases."""
        databases: list[str] = self.client.list_database_names()
        return {db for db in databases if db not in SystemDBS}

    def drop_database(self, database: str):
        """Drop a non-default database."""
        if database in SystemDBS:
            logger.info(f"Not dropping system DB {database}.")
            return
        self.client.drop_database(database)

    def get_users(self) -> set[str]:
        """Add a new member to replica set config inside MongoDB."""
        users_info = self.client.admin.command("usersInfo")
        return {
            user_obj["user"]
            for user_obj in users_info["users"]
            if re.match(r"^relation-\d+$", user_obj["user"])
        }

    def user_exists(self, username: str) -> bool:
        """Checks if a specific user exists."""
        assert re.match(r"^relation-\d+$", username)  # Ensure we get only relation users.
        users_info = self.client.admin.command({"usersInfo": username})
        return users_info["users"] != []

    def primary(self, status: dict[str, Any] | None = None) -> str:
        """Returns the primary replica host."""
        status = status or self.client.admin.command("replSetGetStatus")

        for member in status["members"]:
            # check replica's current state
            if member["stateStr"] == "PRIMARY":
                return hostname_from_hostport(member["name"])

        raise Exception("No primary found.")

    @staticmethod
    def is_any_sync(rs_status: dict[str, Any]) -> bool:
        """Returns true if any replica set members are syncing data.

        Checks if any members in replica set are syncing data. Note it is recommended to run only
        one sync in the cluster to not have huge performance degradation.

        Args:
            rs_status: current state of replica set as reported by mongod.
        """
        return any(
            member["stateStr"] in ["STARTUP", "STARTUP2", "ROLLBACK", "RECOVERING"]
            for member in rs_status["members"]
        )

    @staticmethod
    def is_any_removing(rs_status: dict[str, Any]) -> bool:
        """Returns true if any replica set member is removing itself.

        Args:
            rs_status: current state of replica set as reported by mongod.
        """
        return any(
            member.get("stateStr", "") == "REMOVED" for member in rs_status.get("members", [])
        )

    def get_shard_members(self) -> set[str]:
        """Gets shard members.

        Returns:
            A set of the shard members as reported by mongos.

        Raises:
            ConfigurationError, OperationFailure
        """
        shard_list = self.client.admin.command("listShards")
        return {hostname_from_shardname(member["host"]) for member in shard_list["shards"]}

    def add_shard(
        self, shard_name: str, shard_hosts: list[str], shard_port=MongoPorts.MONGODB_PORT
    ):
        """Adds shard to the cluster.

        Raises:
            ConfigurationError, OperationFailure
        """
        shard_hosts = [f"{host}:{shard_port}" for host in shard_hosts]
        if shard_name in self.get_shard_members():
            logger.info("Skipping adding shard %s, shard is already in cluster", shard_name)
            return

        logger.info("Adding shard %s", shard_name)
        # We can use only one host of the shard and we don't know which ones
        # are added yet to the replica set so we loop over it.
        for shard_host in shard_hosts:
            try:
                shard_url = f"{shard_name}/{shard_host}"
                self.client.admin.command("addShard", shard_url)
                return
            except OperationFailure as err:
                # This means that the shard host is not yet in the shard replica set.
                # Other errors should be raised as they indicate something else.
                if err.code == MongoErrorCodes.OPERATION_FAILED:
                    continue
                raise

    def pre_remove_shard_checks(self, shard_name: str) -> None:
        """Performs a series of checks for removing a shard from the cluster.

        Raises:
            ConfigurationError, OperationFailure, NotReadyError, ShardNotInClusterError,
            BalencerNotEnabledError
        """
        if shard_name not in self.get_shard_members():
            logger.info("Shard to remove is not in cluster.")
            raise ShardNotInClusterError(f"Shard {shard_name} could not be removed")

        # It is necessary to call removeShard multiple times on a shard to guarantee removal.
        # Allow re-removal of shards that are currently draining.
        if self.is_any_shard_draining(ignore_shard=shard_name):
            cannot_remove_shard = (
                f"cannot remove shard {shard_name} from cluster, another shard is draining"
            )
            logger.error(cannot_remove_shard)
            raise NotReadyError(cannot_remove_shard)

        # check if enabled sh.getBalancerState()
        balancer_state = self.client.admin.command("balancerStatus")
        if balancer_state["mode"] != "off":
            logger.info("Balancer is enabled, ready to remove shard.")
            return

        # starting the balancer doesn't guarantee that is is running, wait until it starts up.
        logger.info("Balancer process is not running, enabling it.")
        self.start_and_wait_for_balancer()

    def is_any_shard_draining(self, ignore_shard: str = "") -> bool:
        """Returns true if any shard members is draining.

        Checks if any members in sharded cluster are draining data.

        Args:
            sc_status: current state of shard cluster status as reported by mongos.
            ignore_shard: shard to ignore
        """
        sc_status = self.client.admin.command("listShards")
        return any(
            # check draining status of all shards except the one to be ignored.
            shard.get("draining", False) if shard["_id"] != ignore_shard else False
            for shard in sc_status["shards"]
        )

    def start_and_wait_for_balancer(self) -> None:
        """Turns on the balancer and waits for it to be running.

        Starting the balancer doesn't guarantee that is is running, wait until it starts up.

        Raises:
            BalancerNotEnabledError, ConfigurationError, OperationFailure
        """
        self.client.admin.command("balancerStart")
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3), reraise=True):
            with attempt:
                balancer_state = self.client.admin.command("balancerStatus")
                if balancer_state["mode"] == "off":
                    raise BalancerNotEnabledError("balancer is not enabled.")

    def remove_shard(self, shard_name: str) -> None:
        """Removes shard from the cluster.

        Raises:
            ConfigurationError, OperationFailure, NotReadyError, NotEnoughSpaceError,
            ShardNotInClusterError, BalencerNotEnabledError
        """
        # remove shard, process removal status, & check if fully removed
        logger.info("Attempting to remove shard %s", shard_name)
        removal_info = self.client.admin.command("removeShard", shard_name)
        remaining_chunks = self._retrieve_remaining_chunks(removal_info)
        self._log_removal_info(removal_info, shard_name, remaining_chunks)
        if remaining_chunks:
            logger.info("Waiting for all chunks to be drained from %s.", shard_name)
            raise NotDrainedError

    def move_primary_after_draining_shard(self, shard_name: str) -> None:
        """Move primary after the shard was drained and removed from the cluster."""
        # MongoDB docs says to movePrimary only after all chunks have been drained from the shard.
        logger.info("All chunks drained from shard: %s", shard_name)
        if databases_using_shard_as_primary := self.get_databases_for_shard(shard_name):
            logger.info(
                "These databases: %s use Shard %s is a primary shard, moving primary.",
                ", ".join(databases_using_shard_as_primary),
                shard_name,
            )
            self._move_primary(databases_using_shard_as_primary, old_primary=shard_name)

            # MongoDB docs says to re-run removeShard after running movePrimary
            logger.info("removing shard: %s, after moving primary", shard_name)
            removal_info = self.client.admin.command("removeShard", shard_name)
            remaining_chunks = self._retrieve_remaining_chunks(removal_info)
            self._log_removal_info(removal_info, shard_name, remaining_chunks)

        if shard_name in self.get_shard_members():
            logger.info("Shard %s is still present in sharded cluster.", shard_name)
            raise NotDrainedError()

    def _log_removal_info(self, removal_info, shard_name, remaining_chunks) -> None:
        """Logs removal information for a shard removal."""
        dbs_to_move = (
            removal_info["dbsToMove"]
            if "dbsToMove" in removal_info and removal_info["dbsToMove"] != []
            else ["None"]
        )
        logger.info(
            "Shard %s is draining status is: %s. Remaining chunks: %s. DBs to move: %s.",
            shard_name,
            removal_info["state"],
            str(remaining_chunks),
            ",".join(dbs_to_move),
        )

    def _retrieve_remaining_chunks(self, removal_info: dict[str, Any]) -> int:
        """Parses the remaining chunks to remove from removeShard command."""
        # when chunks have finished draining, remaining chunks is still in the removal info, but
        # marked as 0. If "remaining" is not present, in removal_info then the shard is not yet
        # draining
        if "remaining" not in removal_info:
            raise NotDrainedError

        return removal_info["remaining"]["chunks"] if "remaining" in removal_info else 0

    def get_databases_for_shard(self, primary_shard: str) -> list[str] | None:
        """Returns a list of databases using the given shard as a primary shard.

        In Sharded MongoDB clusters, mongos selects the primary shard when creating a new database
        by picking the shard in the cluster that has the least amount of data. This means that:
        1. There can be multiple primary shards in a cluster.
        2. Until there is data written to the cluster there is effectively no primary shard.
        """
        config_db = self.client["config"]
        if "databases" not in config_db.list_collection_names():
            logger.info("No data written to sharded cluster yet.")
            return None

        databases_collection = config_db["databases"]
        if databases_collection is None:
            return None

        return databases_collection.distinct("_id", {"primary": primary_shard})

    def _move_primary(self, databases_to_move: list[str], old_primary: str) -> None:
        """Moves all the provided databases to a new primary.

        Raises:
            NotEnoughSpaceError, ConfigurationError, OperationFailure
        """
        for database_name in databases_to_move:
            # we try to find the shard that has the most available space and if
            # it's still to small, we raise an error so the user can act
            # accordingly.
            db_size = self.get_db_size_on_primary_shard(database_name, old_primary)
            new_shard, avail_space = self.get_shard_with_most_available_space(
                shard_to_ignore=old_primary
            )
            if db_size > avail_space:
                no_space_on_new_primary = (
                    f"Cannot move primary for database: {database_name}, new shard: {new_shard}",
                    f"does not have enough space. {db_size} > {avail_space}",
                )
                logger.error(no_space_on_new_primary)
                raise NotEnoughSpaceError(no_space_on_new_primary)

            # From MongoDB Docs: After starting movePrimary, do not perform any read or write
            # operations against any unsharded collection in that database until the command
            # completes.
            logger.warning(
                "Moving primary on %s database to new primary: %s. Do NOT write to %s database.",
                database_name,
                new_shard,
                database_name,
            )
            # This command does not return until MongoDB completes moving all data. This can take
            # a long time.
            self.client.admin.command("movePrimary", database_name, to=new_shard)
            logger.info(
                "Successfully moved primary on %s database to new primary: %s",
                database_name,
                new_shard,
            )

    def step_down_primary(self) -> None:
        """Steps down the current primary, forcing a re-election."""
        self.client.admin.command("replSetStepDown", {"stepDownSecs": "60"})

    def move_primary(self, new_primary_ip: str) -> None:
        """Forcibly moves the primary to the new primary provided.

        Args:
            new_primary_ip: ip address of the unit chosen to be the new primary.
        """
        # Do not move a priary unless the cluster is in sync
        rs_status = self.client.admin.command("replSetGetStatus")
        if self.is_any_sync(rs_status):
            # it can take a while, we should defer
            raise NotReadyError

        is_move_successful = True
        self.set_replicaset_election_priority(priority=0.5, ignore_member=new_primary_ip)
        try:
            for attempt in Retrying(stop=stop_after_delay(180), wait=wait_fixed(3)):
                with attempt:
                    self.step_down_primary()
                    if self.primary() != new_primary_ip:
                        raise FailedToMovePrimaryError
        except RetryError:
            # catch all possible exceptions when failing to step down primary. We do this in order
            # to ensure that we reset the replica set election priority.
            is_move_successful = False

        # reset all replicas to the same priority
        self.set_replicaset_election_priority(priority=1)

        if not is_move_successful:
            raise FailedToMovePrimaryError

    def get_db_size_on_primary_shard(self, database_name: str, primary_shard: str) -> int:
        """Returns the size of a DB on a given shard in bytes.

        We need to find the amount of storage used because we cannot move
        primary to a shard that doesn't have enough available space.
        """
        database = self.client[database_name]
        db_stats = database.command("dbStats")

        # sharded databases are spread across multiple shards, find the amount of storage used on
        # the primary shard
        for shard_name, shard_storage_info in db_stats["raw"].items():
            # shard names are of the format `shard-one/10.61.64.212:27017`
            shard_name = shard_name.split("/")[0]
            if shard_name != primary_shard:
                continue

            return shard_storage_info["storageSize"]

        return 0

    def get_shard_with_most_available_space(self, shard_to_ignore: str) -> tuple[str, int]:
        """Returns the shard in the cluster with the most available space and the space in bytes.

        Algorithm used was similar to that used in mongo in `selectShardForNewDatabase`:
        https://github.com/mongodb/mongo/blob/6/0/src/mongo/db/s/config/sharding_catalog_manager_database_operations.cpp#L68-L91
        """
        candidate_shard: str = ""
        candidate_free_space = -1
        available_storage = self.client.admin.command("dbStats", freeStorage=1)

        for shard_name, shard_storage_info in available_storage["raw"].items():
            # shard names are of the format `shard-one/10.61.64.212:27017`
            shard_name = shard_name.split("/")[0]
            if shard_name == shard_to_ignore:
                continue

            current_free_space = shard_storage_info["freeStorageSize"]
            if current_free_space > candidate_free_space:
                candidate_shard = shard_name
                candidate_free_space = current_free_space

        return (candidate_shard, candidate_free_space)

    def get_draining_shards(self, shard_name: str) -> list[str]:
        """Returns a list of the shards currently draining."""
        sc_status = self.client.admin.command("listShards")
        draining_shards = []
        for shard in sc_status["shards"]:
            if shard["_id"] == shard_name and "draining" not in shard:
                raise ShardNotPlannedForRemovalError

            if shard.get("draining", False):
                draining_shards.append(shard["_id"])

        return draining_shards

    def is_shard_aware(self, shard_name: str) -> bool:
        """Returns True if the shard is in the AWARE state."""
        sc_status = self.client.admin.command("listShards")
        for shard in sc_status["shards"]:
            if shard["_id"] == shard_name:
                return shard["state"] == SHARD_AWARE_STATE

        return False

    def are_all_shards_aware(self) -> bool:
        """Returns True if all shards already in the cluster are shard aware."""
        sc_status = self.client.admin.command("listShards")
        return all(shard["state"] == SHARD_AWARE_STATE for shard in sc_status["shards"])
