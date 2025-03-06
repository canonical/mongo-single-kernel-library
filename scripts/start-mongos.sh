#!/bin/bash

# This starts mongos with the provided arguments
exec /usr/bin/mongos --config /etc/mongod/mongos.conf ${MONGOS_ARGS}
