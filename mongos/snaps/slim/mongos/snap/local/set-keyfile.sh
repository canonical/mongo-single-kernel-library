#!/bin/bash
# Set the MongoDB internal-authentication keyfile.
#
# Run with sudo; the helper writes the keyfile as the snap_daemon user that
# runs mongos.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: mongos.set-keyfile KEY

Set the MongoDB internal-authentication keyfile to KEY.

The same keyfile value must be shared by every member of the sharded cluster.
Run this with sudo; the helper writes the keyfile as the snap_daemon user that
runs mongos.

Example:
  key="$(sudo snap run mongodb-server-sharded.get-keyfile)"
  sudo snap run mongos.set-keyfile "$key"
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
