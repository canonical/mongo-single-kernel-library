#!/bin/bash
# Set the MongoDB internal-authentication keyfile.
#
# Usage:
#   mongodb-server-sharded.set-keyfile <key>   Store <key> as the keyfile.
#
# Run with sudo; the helper writes the keyfile as the snap_daemon user that
# runs mongod and mongos. The user is responsible for syncing the same keyfile
# value across all cluster members.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: mongodb-server-sharded.set-keyfile KEY

Set the MongoDB internal-authentication keyfile.

Store KEY as the keyfile contents. Every member of a sharded cluster must use
the same keyfile value; sync it with get-keyfile/set-keyfile before restarting
them.

Example:
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

if [ "$#" -ne 1 ]; then
    echo "set-keyfile: expected exactly one KEY argument" >&2
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

if [ -z "$1" ]; then
    echo "set-keyfile: KEY must not be empty" >&2
    exit 1
fi

printf '%s\n' "$1" | write_keyfile

echo "Keyfile stored at ${KEYFILE}" >&2
