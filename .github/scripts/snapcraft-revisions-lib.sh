#!/usr/bin/env bash

get_live_snap_revisions_by_arch() {
  local snap="$1"

  # `snapcraft revisions` prints a table, so read it as raw text and turn the
  # rows for the current live channel into {"amd64":2,"arm64":1}.
  snapcraft revisions "$snap" \
    | jq -Rsc --arg channel "$CHANNEL" '
        # Split the raw table output into lines.
        split("\n")
        # Drop the header row: Rev. Uploaded Arches Version Channels.
        | .[1:]
        # Ignore empty lines, split rows on spaces, and remove empty columns
        # caused by table alignment.
        | map(select(length > 0) | split(" ") | map(select(length > 0)))
        # Keep only rows with the expected table columns.
        | map(select(length >= 5))
        # Convert each row into a clearer object:
        #   column 1 is revision, column 3 is architecture, column 5 is channels.
        | map({
            revision: (.[0] | tonumber),
            arch: .[2],
            channels: (.[4] | split(","))
          })
        # Keep only rows where the target channel is marked live with "*".
        | map(select(.channels | index($channel + "*")))
        # Convert matching rows to architecture keyed objects.
        | map({(.arch): .revision})
        # Merge architecture objects; return {} if no revisions matched.
        | add // {}'
}
