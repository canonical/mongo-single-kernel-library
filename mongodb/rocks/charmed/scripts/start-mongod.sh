#!/bin/bash

# This starts mongod with the args from the environment
exec /usr/bin/mongod --config /etc/mongod/mongod.conf ${MONGOD_ARGS}
