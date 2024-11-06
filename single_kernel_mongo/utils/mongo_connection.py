# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Definition of MongoDB Connections."""


import logging

from pymongo import MongoClient
from pymongo.errors import OperationFailure
from tenacity import RetryError, Retrying, stop_after_delay, wait_fixed

from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongodb_users import SYSTEM_DBS

logger = logging.getLogger(__name__)


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

    def __init__(
        self, config: MongoConfiguration, uri: str | None = None, direct: bool = False
    ):
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

    def create_user(self, config: MongoConfiguration):
        """Create user.

        Grant read and write privileges for specified database.
        """
        self.client.admin.command(
            "createUser",
            config.username,
            pwd=config.password,
            roles=config.supported_roles,
            mechanisms=["SCRAM-SHA-256"],
        )

    def update_user(self, config: MongoConfiguration):
        """Update grants on database."""
        self.client.admin.command(
            "updateUser",
            config.username,
            roles=config.supported_roles,
        )

    def set_user_password(self, username: str, password: str):
        """Update the password."""
        self.client.admin.command(
            "updateUser",
            username,
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
            self.client.admin.command(
                "createRole", role_name, privileges=[privileges], roles=roles
            )
        except OperationFailure as e:
            if e.code == 51002:
                logger.info("Role already exists")
                return
            logger.error("Cannot add role. error=%r", e)
            raise

    def get_databases(self) -> set[str]:
        """Return list of all non-default databases."""
        databases: list[str] = self.client.list_database_names()
        return {db for db in databases if db not in SYSTEM_DBS}

    def drop_database(self, database: str):
        """Drop a non-default database."""
        if database in SYSTEM_DBS:
            logger.info(f"Not dropping system DB {database}.")
            return
        self.client.drop_database(database)
