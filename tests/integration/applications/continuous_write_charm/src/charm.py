#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Application charm that connects to database charms.

This charm is meant to be used only for testing
high availability of the MongoDB charm.
"""

import json
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote_plus, urlencode

from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires, DatabaseCreatedEvent
from ops.charm import ActionEvent, CharmBase
from ops.main import main
from ops.model import ActiveStatus, Relation, WaitingStatus
from pymongo import MongoClient
from pymongo.uri_parser import parse_uri
from tenacity import RetryError, Retrying, stop_after_delay, wait_fixed

logger = logging.getLogger(__name__)

DATABASE_NAME = "continuous_writes_database"
COLLECTION_NAME = "continuous_writes_collection"
REPLICATION_COLL_NAME = "test_ubuntu_collection"
PEER = "application-peers"
PROC_PID_KEY = "proc-pid"
LAST_WRITTEN_FILE = "last_written_value"
N_READ_FILE = "n_read_value"

CA_PATH = Path("/tmp/ca.crt")


class ContinuousWritesApplication(CharmBase):
    """Application charm that continuously writes to MongoDB."""

    def __init__(self, *args):
        super().__init__(*args)

        # Charm events
        self.framework.observe(self.on.start, self._on_start)

        self.framework.observe(
            self.on.clear_continuous_writes_action, self._on_clear_continuous_writes_action
        )
        self.framework.observe(
            self.on.start_continuous_writes_action, self._on_start_continuous_writes_action
        )
        self.framework.observe(
            self.on.stop_continuous_writes_action, self._on_stop_continuous_writes_action
        )

        self.framework.observe(
            self.on.start_continuous_reads_action, self._on_start_continuous_reads_action
        )
        self.framework.observe(
            self.on.stop_continuous_reads_action, self._on_stop_continuous_reads_action
        )

        # Database related events
        self.database = DatabaseRequires(self, "mongodb", self.database_name)
        # Database related events
        self.mongos_database = DatabaseRequires(self, "mongos", self.database_name, external_node_connectivity=True)

        self.framework.observe(self.database.on.database_created, self._on_database_created)
        self.framework.observe(self.mongos_database.on.database_created, self._on_database_created)

        if (data:= list(self.database.fetch_relation_data().values())):
            if (tls_ca := data[0].get("tls-ca")):
                CA_PATH.write_text(tls_ca)
                return

        if (data:= list(self.mongos_database.fetch_relation_data().values())):
            if (tls_ca := data[0].get("tls-ca")):
                CA_PATH.write_text(tls_ca)
                return

        if tls_ca := self.model.config.get("tls-ca", None):
            CA_PATH.write_text(tls_ca)
            return

    # ==============
    # Properties
    # ==============

    @property
    def database_name(self) -> str:
        return self.model.config.get("database-name", DATABASE_NAME)

    @property
    def _peers(self) -> Relation | None:
        """Retrieve the peer relation (`ops.model.Relation`)."""
        return self.model.get_relation(PEER)

    @property
    def app_peer_data(self) -> dict:
        """Application peer relation data object."""
        if self._peers is None:
            return {}

        return self._peers.data[self.app]

    @property
    def _database_config(self) -> dict[str, str]:
        """Returns the database config to use to connect to the MongoDB cluster."""
        # In some tests we want to write directly to mongos, but the config-server does not
        # support integrations to client applications, so the data to connect is set via config.
        if not self.database.relations and not self.mongos_database.relations:
            uri = self.model.config.get("mongos-uri", "")
            if self.model.config.get("tls-ca"):
                uri = self._build_tls_uri(uri)

            return {"uris": uri}

        if self.database.relations:
            data =list(self.database.fetch_relation_data().values())[0]
        elif self.mongos_database.relations:
            data =list(self.mongos_database.fetch_relation_data().values())[0]
        else:
            return {}

        username, password, endpoints, replset, uris, tls = (
            data.get("username"),
            data.get("password"),
            data.get("endpoints"),
            data.get("replset"),
            data.get("uris"),
            data.get("tls")
        )

        if None in [username, password, endpoints, uris]:
            return {}

        if tls:
            uris = self._build_tls_uri(uris)

        return {
            "user": username,
            "password": password,
            "endpoints": endpoints,
            "replset": replset or "",
            "uris": uris,
        }

    # ==============
    # Helpers
    # ==============

    def _build_tls_uri(self, uris: str) -> str:
            parsed_uri = parse_uri(uris)
            params = parsed_uri["options"]
            params["tls"] = "true"
            params["tlsCaFile"] = f"{CA_PATH}"
            hosts = ",".join(f"{host}:{port}" for host, port in parsed_uri["nodelist"])
            return (
                    f"mongodb://{quote_plus(parsed_uri['username'])}:"
                        f"{quote_plus(parsed_uri['password'])}@"
                        f"{hosts}/{quote_plus(parsed_uri['database'])}?"
                        f"{urlencode(params)}"
                )

    def _start_continuous_writes(
        self, starting_number: int, db_name: str, collection_name: str
    ) -> None:
        """Start continuous writes to the MongoDB cluster."""
        if not self._database_config:
            logger.warning("No database configured.")
            return

        logger.info(f"Running start continuous write with {db_name=} and {collection_name=}")
        self._stop_continuous_writes(db_name, collection_name)

        uris: str = self._database_config.get("uris", "")
        # Run continuous writes in the background
        proc = subprocess.Popen(
            [
                sys.executable,
                "src/continuous_writes.py",
                uris,
                str(starting_number),
                db_name,
                collection_name,
            ]
        )

        # Store the continuous writes process id in stored state to be able to stop it later
        self.app_peer_data[self.proc_id_key(db_name, collection_name)] = str(proc.pid)

    def _stop_continuous_writes(self, db_name: str, collection_name: str) -> int | None:
        """Stop continuous writes to the MongoDB cluster and return the last written value."""
        if not self._database_config:
            logger.warning("No database configured.")
            return None

        if not self.app_peer_data.get(self.proc_id_key(db_name, collection_name)):
            return None

        # Send a SIGTERM to the process and wait for the process to exit
        try:
            os.kill(
                int(self.app_peer_data[self.proc_id_key(db_name, collection_name)]), signal.SIGTERM
            )
        except ProcessLookupError:
            logger.info(
                f"Process {self.proc_id_key(db_name, collection_name)} was killed already (or never existed)"
            )
            return -1
        finally:
            del self.app_peer_data[self.proc_id_key(db_name, collection_name)]

        # read the last written_value
        try:
            for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
                with attempt, open(self.last_written_filename(db_name, collection_name)) as fd:
                    last_written_value = int(fd.read())
                    os.remove(self.last_written_filename(db_name, collection_name))
                    logger.info(f"Stopped writing at {last_written_value=}")
                    return last_written_value
        except RetryError as e:
            logger.exception("Unable to query the database", exc_info=e)
            return -1

    def _start_continuous_reads(
        self, db_name: str, collection_name: str
    ) -> None:
        """Start continuous writes to the MongoDB cluster."""
        if not self._database_config:
            logger.warning("No database configured.")
            return

        logger.info(f"Running start continuous reads with {db_name=} and {collection_name=}")
        self._stop_continuous_reads(db_name, collection_name)

        uris: str = self._database_config.get("uris", "")
        # Run continuous writes in the background
        proc = subprocess.Popen(
            [
                sys.executable,
                "src/continuous_reads.py",
                uris,
                db_name,
                collection_name,
            ]
        )

        # Store the continuous writes process id in stored state to be able to stop it later
        self.app_peer_data[self.read_proc_id_key(db_name, collection_name)] = str(proc.pid)

    def _stop_continuous_reads(self, db_name: str, collection_name: str) -> tuple[int | None, list[str]]:
        """Stop continuous reads to the MongoDB cluster and return the number of successful reads."""
        if not self._database_config:
            logger.warning("No database configured.")
            return None, []

        if not self.app_peer_data.get(self.read_proc_id_key(db_name, collection_name)):
            return None, []

        # Send a SIGTERM to the process and wait for the process to exit
        try:
            os.kill(
                int(self.app_peer_data[self.read_proc_id_key(db_name, collection_name)]), signal.SIGTERM
            )
        except ProcessLookupError:
            logger.info(
                f"Process {self.read_proc_id_key(db_name, collection_name)} was killed already (or never existed)"
            )

        del self.app_peer_data[self.read_proc_id_key(db_name, collection_name)]

        # read the last written_value
        try:
            for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
                with attempt, open(self.n_read_filename(db_name, collection_name)) as fd:
                    data = json.load(fd)
                    number_of_reads = int(data.get("reads", -1))
                    failed_reads = data.get("failed_reads", [])
                    os.remove(self.n_read_filename(db_name, collection_name))
                    logger.info(f"Read {number_of_reads} times // Failed {len(failed_reads)}.")
                    return number_of_reads, failed_reads
        except RetryError as e:
            logger.exception("Unable to query the database", exc_info=e)
            return -1, []

    def proc_id_key(self, db_name: str, collection_name: str) -> str:
        """Returns a process id key for the continuous writes process to a given db and coll."""
        return f"{PROC_PID_KEY}-{db_name}-{collection_name}"

    def read_proc_id_key(self, db_name: str, collection_name: str) -> str:
        """Returns a process id key for the continuous reads process to a given db and coll."""
        return f"read-{PROC_PID_KEY}-{db_name}-{collection_name}"

    def last_written_filename(self, db_name: str, collection_name: str) -> str:
        """Returns the filename for the written data for a given db and coll."""
        return f"{LAST_WRITTEN_FILE}-{db_name}-{collection_name}"

    def n_read_filename(self, db_name: str, collection_name: str) -> str:
        """Returns the filename for the read data for a given db and coll."""
        return f"{N_READ_FILE}-{db_name}-{collection_name}.json"

    # ==============
    # Handlers
    # ==============

    def _on_start(self, _) -> None:
        """Handle the start event."""
        self.unit.status = WaitingStatus()

    def _on_clear_continuous_writes_action(self, event) -> None:
        """Handle the clear continuous writes action event."""
        if not self._database_config:
            logger.warning("No database configured.")
            return

        db_name = event.params.get("db-name") or DATABASE_NAME
        collection_name = event.params.get("collection-name") or COLLECTION_NAME

        self._stop_continuous_writes(db_name, collection_name)

        client = MongoClient(self._database_config["uris"])
        db = client[db_name]

        # collection for continuous writes
        test_collection = db[collection_name]
        test_collection.drop()

        # collection for replication tests
        test_collection = db[REPLICATION_COLL_NAME]
        test_collection.drop()

        client.close()

    def _on_start_continuous_writes_action(self, event) -> None:
        """Handle the start continuous writes action event."""
        if not self._database_config:
            return

        db_name = event.params.get("db-name") or self.database_name
        collection_name = event.params.get("collection-name") or COLLECTION_NAME
        self._start_continuous_writes(1, db_name, collection_name)

    def _on_stop_continuous_writes_action(self, event: ActionEvent) -> None:
        """Handle the stop continuous writes action event."""
        if not self._database_config:
            return event.set_results({"writes": -1})

        db_name = event.params.get("db-name") or DATABASE_NAME
        collection_name = event.params.get("collection-name") or COLLECTION_NAME
        writes = self._stop_continuous_writes(db_name, collection_name)
        event.set_results({"writes": writes or -1})
        return None

    def _on_start_continuous_reads_action(self, event) -> None:
        """Handle the start continuous reads action event."""
        if not self._database_config:
            return

        db_name = event.params.get("db-name") or self.database_name
        collection_name = event.params.get("collection-name") or COLLECTION_NAME
        self._start_continuous_reads(db_name, collection_name)

    def _on_stop_continuous_reads_action(self, event: ActionEvent) -> None:
        """Handle the stop continuous reads action event."""
        if not self._database_config:
            return event.set_results({"reads": -1})

        db_name = event.params.get("db-name") or self.database_name
        collection_name = event.params.get("collection-name") or COLLECTION_NAME
        reads, failed_reads = self._stop_continuous_reads(db_name, collection_name)
        event.set_results({"reads": reads or -1, "failed_reads": failed_reads})
        return None

    def _on_database_created(self, event: DatabaseCreatedEvent) -> None:
        """Handle the database created event."""
        if event.tls == "True":
            CA_PATH.write_text(event.tls_ca)

        self.unit.status = ActiveStatus()

if __name__ == "__main__":
    main(ContinuousWritesApplication)
