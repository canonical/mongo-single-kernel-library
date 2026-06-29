#!/bin/bash
# Set the MongoDB internal-authentication keyfile.
#
# Usage:
#   mongodb-server-sharded.set-keyfile KEY
#   mongodb-server-sharded.get-keyfile | mongodb-server-sharded.set-keyfile
#
# Run with sudo; the helper writes the keyfile as the snap_daemon user that
# runs mongod and mongos. The user is responsible for syncing the same keyfile
# value across all cluster members.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  mongodb-server-sharded.set-keyfile KEY
  mongodb-server-sharded.get-keyfile | mongodb-server-sharded.set-keyfile

Set the MongoDB internal-authentication keyfile.

Store KEY as the keyfile contents from one of:
  - the KEY argument
  - standard input

Every member of a sharded cluster must use the same keyfile value; sync it with
get-keyfile/set-keyfile before restarting them.

Example:
  sudo snap run mongodb-server-sharded.set-keyfile "$key"
  sudo snap run mongodb-server-sharded.get-keyfile | sudo snap run mongodb-server-sharded.set-keyfile
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

. "${SNAP}/keyfile-common.sh"

if [ "$#" -gt 1 ]; then
    echo "set-keyfile: expected at most one KEY argument" >&2
    usage >&2
    exit 1
fi

if [ "$(id -u)" = "0" ]; then
    exec "${SNAP}/usr/bin/setpriv" \
        --clear-groups \
        --reuid snap_daemon \
        --regid snap_daemon \
        -- \
        "${SNAP}/set-keyfile.sh" "$@"
fi

if [ "$#" -eq 1 ]; then
    printf '%s\n' "$1" | write_keyfile
elif [ ! -t 0 ]; then
    write_keyfile
else
    echo "set-keyfile: expected KEY argument or stdin" >&2
    usage >&2
    exit 1
fi

echo "Keyfile stored at ${KEYFILE}" >&2
