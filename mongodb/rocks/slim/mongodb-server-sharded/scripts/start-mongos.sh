#!/bin/bash

# Start mongos
#
# Extra arguments can be supplied through the MONGOS_ARGS environment variable,
# for example:
#   docker run -e MONGOS_ARGS="--configdb configrs/configsvr:27019 --bind_ip_all" ...
set -euo pipefail

source /bin/keyfile-common.sh

# Auto-generate an internal-authentication keyfile on first start, unless one is
# already present (e.g. bind-mounted from the host). Restarts reuse it.
if [ ! -e "${KEYFILE}" ]; then
  generate_keyfile
fi

exec /usr/bin/mongos --config /etc/mongod/mongos.conf ${MONGOS_ARGS:-} "$@"
