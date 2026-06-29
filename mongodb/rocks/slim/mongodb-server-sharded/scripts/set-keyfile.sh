#!/bin/bash
# Set the MongoDB internal-authentication keyfile.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  set-keyfile KEY
  get-keyfile | set-keyfile

Set the MongoDB internal-authentication keyfile.

Store KEY as the keyfile contents from either the KEY argument or standard
input. Every member of a sharded cluster must use the same keyfile value; sync
it with get-keyfile/set-keyfile before restarting them.

Example:
  docker exec shard1 set-keyfile "$KEYFILE_CONTENT"
  docker exec configsvr get-keyfile | docker exec -i shard1 set-keyfile
  docker restart shard1
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

source /bin/keyfile-common.sh

if [ "$#" -gt 1 ]; then
    echo "set-keyfile: expected at most one KEY argument" >&2
    usage >&2
    exit 1
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
