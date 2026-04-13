# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""This file is meant to run in the background continuously reading data from MongoDB."""

import json
import random
import signal
import sys

import math
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from pymongo.write_concern import WriteConcern

DEFAULT_DB_NAME = "continuous_writes_database"
DEFAULT_COLL_NAME = "continuous_writes_collection"

run = True


def sigterm_handler(_signo, _stack_frame):
    global run
    run = False

def n_read_filename(db_name: str, coll_name: str) -> str:
    return f"n_read_value-{db_name}-{coll_name}.json"


def continous_reads(
    connection_string: str,
    db_name: str,
    coll_name: str,
):
    failed_reads = []
    reads = 0
    while run:
        client = MongoClient(
            connection_string,
            socketTimeoutMS=5000,
        )
        db = client[db_name]
        test_collection = db[coll_name]
        try:
            if (rand:= random.random()) < 0.3:
                # run some basic sampling
                test_collection.aggregate([{"$sample": {"size": 10}}, {"$sort": {"number": 1}}])
            elif rand < 0.6:
                n_docs = test_collection.count_documents()
                # get one single sample
                test_collection.aggregate([{"$skip": math.floor(n_docs * random.random())}, {"$limit": 1}])
            else:
                n_docs = test_collection.count_documents()
                test_collection.find({"number": {"$lte": math.floor(n_docs /2)}})
        except PyMongoError as err:
            failed_reads.append(str(err))
            continue
        finally:
            client.close()

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
