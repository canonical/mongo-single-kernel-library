#!/bin/bash

# This starts mongod with the args from the environment
exec /usr/bin/mongod ${MONGOD_ARGS}
