#!/usr/bin/env bash
set -euo pipefail

# This script captures the current Snapcraft revisions for snaps that back rocks.
# It is intended for GitHub Actions workflows where we need to know the current
# channel revisions before triggering a promotion or release.

source .github/scripts/snapcraft-revisions-lib.sh

# Identify snaps that back rocks by matching names.
names=$(jq -nr --argjson rocks "$ROCKS" --argjson snaps "$SNAPS" '
  [$rocks[].name] as $rock_names
  | [$snaps[].name | select(. as $snap_name | $rock_names | index($snap_name))]
  | .[]')

result='{}'
for snap in $names; do
  # Query Snapcraft for the current revisions on the target channel.
  revisions=$(get_live_snap_revisions_by_arch "$snap")

  # `revisions` looks like {"amd64":2,"arm64":1}
  echo "Current ${snap} on ${CHANNEL}: ${revisions}"
  # Build a JSON object mapping snap name to architecture-specific revision values.
  result=$(jq -c --arg s "$snap" --argjson r "$revisions" '. + {($s): $r}' <<<"$result")
done

# Export the collected revisions as a GitHub Actions output variable.
echo "current-revisions=${result}" >> "$GITHUB_OUTPUT"
