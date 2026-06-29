#!/bin/sh
# Wrapper script for pbm-agent. The agent needs access to the PBM_MONGODB_URI environment 
# variable, but snap daemons don't have access to environment variables, so this must be loaded
# via `snapctl get`

# execute pbm-agent as the snap-daemon user and use the configured value for the uri
export PBM_MONGODB_URI="$(snapctl get pbm-uri)"
exec "${SNAP}"/usr/bin/setpriv \
        --clear-groups \
        --reuid snap_daemon \
        --regid snap_daemon -- \
        "$SNAP/usr/bin/pbm-agent" 
