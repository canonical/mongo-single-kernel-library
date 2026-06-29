#!/bin/bash

ulimit -SHf unlimited
ulimit -SHt unlimited
ulimit -SHv unlimited
ulimit -SHm unlimited
ulimit -Sl unlimited
ulimit -SHn 64000
ulimit -SHu 64000

SNAP_ARGS="$(snapctl get mongod-args)"

if [[ -n "${SNAP_ARGS}" ]]; then
    MONGOD_ARGS="${SNAP_ARGS}"
fi
# For security measures, daemons should not be run as sudo. Execute mongod as the non-sudo user: snap-daemon.
exec $SNAP/usr/bin/setpriv --clear-groups --reuid snap_daemon \
  --regid snap_daemon -- $SNAP/usr/bin/mongod --config ${SNAP_DATA}/etc/mongod/mongod.conf ${MONGOD_ARGS} "$@"
