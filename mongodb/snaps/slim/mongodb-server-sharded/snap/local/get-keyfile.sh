#!/bin/bash
# Print the contents of the MongoDB internal-authentication keyfile to stdout.
#
# Use it to copy the auto-generated key from one snap into the others so that
# every member of a sharded cluster shares the same key:
#
#   key="$(sudo snap run mongodb-server-sharded.get-keyfile)"
#   sudo snap run mongodb-server-sharded.set-keyfile "$key"
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: mongodb-server-sharded.get-keyfile

Print the contents of the stored MongoDB internal-authentication keyfile.

The same keyfile must be shared by every member of the sharded cluster
(config servers, shard servers and query routers).

Example:
  key="$(sudo snap run mongodb-server-sharded.get-keyfile)"
  sudo snap run mongodb-server-sharded.set-keyfile "$key"
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

. "${SNAP}/keyfile-common.sh"

if [ "$#" -ne 0 ]; then
    echo "get-keyfile: expected no arguments" >&2
    usage >&2
    exit 1
fi

if [ ! -e "${KEYFILE}" ]; then
    echo "get-keyfile: no keyfile found at ${KEYFILE}" >&2
    exit 1
fi

if [ "$(id -u)" = "0" ]; then
    exec "${SNAP}/usr/bin/setpriv" \
        --clear-groups \
        --reuid snap_daemon \
        --regid snap_daemon \
        -- \
        cat "${KEYFILE}"
fi

cat "${KEYFILE}"
