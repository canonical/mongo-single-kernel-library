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

from single_kernel_mongo.utils.helpers import hostname_from_hostport
from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongodb_users import DBPrivilege, SystemDBS

logger = logging.getLogger(__name__)


class NotReadyError(PyMongoError):
    """Raised when mongo is not ready."""

    ...


class MongoConnection:
    """In this class we create connection object to Mongo[s/db].

    This class is meant for agnositc functions in mongos and mongodb.

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
    def init_replset(self) -> None:
        """Create replica set config the first time.

        Raises:
            ConfigurationError, ConfigurationError, OperationFailure
        """
        config = {
            "_id": self.config.replset,
            "members": [{"_id": i, "host": h} for i, h in enumerate(self.config.hosts)],
        }
        try:
            self.client.admin.command("replSetInitiate", config)
        except OperationFailure as e:
            if e.code not in (13, 23):  # Unauthorized, AlreadyInitialized
                # Unauthorized error can be raised only if initial user were
                #     created the step after this.
                # AlreadyInitialized error can be raised only if this step
                #     finished.
                logger.error("Cannot initialize replica set. error=%r", e)
                raise e
        pass

    def create_user(self, config: MongoConfiguration, roles: list[DBPrivilege] | None = None):
        """Create user.

        Grant read and write privileges for specified database.
        """
        self.client.admin.command(
            "createUser",
            value=config.username,
            pwd=config.password,
            roles=roles or config.supported_roles,
            mechanisms=["SCRAM-SHA-256"],
        )

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

    def create_role(self, role_name: str, privileges: dict, roles: dict = {}):
        """Creates a new role.

        Args:
            role_name: name of the role to be added.
            privileges: privileges to be associated with the role.
            roles: List of roles from which this role inherits privileges.
        """
        try:
            self.client.admin.command("createRole", role_name, privileges=[privileges], roles=roles)
        except OperationFailure as e:
            if e.code == 51002:
                logger.info("Role already exists")
                return
            logger.error("Cannot add role. error=%r", e)
            raise

    def set_replicaset_election_priority(
        self, priority: int, ignore_member: str | None = None
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
        if any(member.get("stateStr", "") == "REMOVED" for member in rs_status.get("members", [])):
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
