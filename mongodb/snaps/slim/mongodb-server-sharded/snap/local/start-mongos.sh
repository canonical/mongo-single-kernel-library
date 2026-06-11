#!/bin/bash

ulimit -SHf unlimited
ulimit -SHt unlimited
ulimit -SHv unlimited
ulimit -SHm unlimited
ulimit -Sl unlimited
ulimit -SHn 64000
ulimit -SHu 64000

SNAP_ARGS="$(snapctl get mongos-args)"

if [[ -n "${SNAP_ARGS}" ]]; then
    MONGOS_ARGS="${SNAP_ARGS}"
fi

# For security measures, daemons should not be run as sudo. Execute mongos as the non-sudo user: snap-daemon.
exec $SNAP/usr/bin/setpriv --clear-groups --reuid snap_daemon \
  --regid snap_daemon -- $SNAP/usr/bin/mongos --config ${SNAP_DATA}/etc/mongod/mongos.conf ${MONGOS_ARGS} "$@"
