# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""This file is meant to run in the background continuously reading data from MongoDB."""

import json
import random
import signal
import sys

import math
from pymongo import MongoClient

DEFAULT_DB_NAME = "continuous_writes_database"
DEFAULT_COLL_NAME = "continuous_writes_collection"

run = True


def sigterm_handler(_signo, _stack_frame):
    global run
    run = False

def n_read_filename(db_name: str, coll_name: str) -> str:
    return f"n_read_value-{db_name}-{coll_name}.json"

def _client(connection_string: str) -> MongoClient[dict[str, int]]:
    """Returns a Mongo Client."""
    return MongoClient(
            connection_string,
            socketTimeoutMS=5000,
            document_class=dict
        )

def continous_reads(
    connection_string: str,
    db_name: str,
    coll_name: str,
):
    failed_reads = []
    reads = 0
    client = _client(connection_string=connection_string)
    should_get_new_client = False
    while run:
        if should_get_new_client:
            try:
                client = _client(connection_string=connection_string)
                should_get_new_client = False
            except Exception:
                continue
        db = client[db_name]
        test_collection = db[coll_name]
        try:
            if (rand:= random.random()) < 0.3:
                # run some basic sampling
                test_collection.aggregate([{"$sample": {"size": 10}}, {"$sort": {"number": 1}}])
            elif rand < 0.6:
                n_docs = test_collection.count_documents({})
                # get one single sample
                test_collection.aggregate([{"$skip": math.floor(n_docs * random.random())}, {"$limit": 1}])
            else:
                n_docs = test_collection.count_documents({})
                test_collection.find({"number": {"$lte": math.floor(n_docs /2)}})
        except Exception as err:
            failed_reads.append(str(err))
            with open("error.log", mode="a") as fd:
                fd.write(f"{err}\n")
            should_get_new_client = True
            client.close()
            continue

        reads += 1

    with open(n_read_filename(db_name, coll_name), "w") as fd:
        json.dump({"reads": reads, "failed_reads": failed_reads}, fd)


def main():
    connection_string = sys.argv[1]
    db_name = DEFAULT_DB_NAME if len(sys.argv) < 3 else sys.argv[2]
    coll_name = DEFAULT_COLL_NAME if len(sys.argv) < 4 else sys.argv[3]
    continous_reads(connection_string, db_name, coll_name)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, sigterm_handler)
    main()
