#!/bin/bash
# Wrapper script for mongodb-server-replicaset applications to be run with restricted privileges

pushd "${SNAP}" > /dev/null

if [[ $(id -u) == "0" ]]; then
    exec "${SNAP}"/usr/bin/setpriv \
        --clear-groups \
        --reuid snap_daemon \
        --regid snap_daemon \
        -- \
        "${SNAP}/usr/bin/$@"
else
    exec "${SNAP}/usr/bin/$@"
fi

popd > /dev/null
