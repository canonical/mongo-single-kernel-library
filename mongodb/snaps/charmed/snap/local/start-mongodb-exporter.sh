#!/bin/bash

# set the URI as an environment variable to be used by mongodb-exporter
export MONGODB_URI="$(snapctl get monitor-uri)"

# For security measures, daemons should not be run as sudo. Execute mongod as the non-sudo user: 
# snap-daemon and use the configured value for the uri
exec "${SNAP}"/usr/bin/setpriv \
        --clear-groups \
        --reuid snap_daemon \
        --regid snap_daemon -- \
        "$SNAP/usr/bin/mongodb_exporter" --collector.diagnosticdata --compatible-mode

