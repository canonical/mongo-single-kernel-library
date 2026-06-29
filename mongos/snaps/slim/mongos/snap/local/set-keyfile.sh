#!/bin/bash
# Set the MongoDB internal-authentication keyfile.
#
# Run with sudo; the helper writes the keyfile as the snap_daemon user that
# runs mongos.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  mongos.set-keyfile KEY
  mongodb-server-sharded.get-keyfile | mongos.set-keyfile

Set the MongoDB internal-authentication keyfile from either the KEY argument or
standard input.

The same keyfile value must be shared by every member of the sharded cluster.
Run this with sudo; the helper writes the keyfile as the snap_daemon user that
runs mongos.

Example:
  key="$(sudo snap run mongodb-server-sharded.get-keyfile)"
  sudo snap run mongos.set-keyfile "$key"
  sudo snap run mongodb-server-sharded.get-keyfile | sudo snap run mongos.set-keyfile
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
