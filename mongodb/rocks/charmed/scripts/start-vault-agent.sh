#!/bin/bash 

# This starts vault as an agent with the provided arguments
exec /bin/vault agent -config /etc/vault/agent-config.hcl
