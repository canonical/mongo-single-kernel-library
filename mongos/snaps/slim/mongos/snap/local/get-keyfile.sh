#!/bin/bash
# Print the contents of the MongoDB internal-authentication keyfile to stdout.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: mongos.get-keyfile

Print the contents of the stored MongoDB internal-authentication keyfile.

Example:
  sudo snap run mongos.get-keyfile "$key"
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

if [ "$#" -ne 0 ]; then
    echo "get-keyfile: expected no arguments" >&2
    usage >&2
    exit 1
fi

. "${SNAP}/keyfile-common.sh"

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
