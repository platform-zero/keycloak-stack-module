#!/usr/bin/env bash
set -euo pipefail

realm="${KEYCLOAK_REALM:-webservices}"
output="${1:-/tmp/${realm}-realm-export.json}"

if ! command -v docker >/dev/null 2>&1; then
  printf 'docker is required to export the Keycloak realm\n' >&2
  exit 1
fi

podman exec keycloak /opt/keycloak/bin/kc.sh export \
  --realm "$realm" \
  --file "$output" \
  --users different_files

cat <<EOF
Realm export written inside the keycloak container at:
  $output

Review and sanitize the export before copying anything back to stack.config/keycloak/.
Do not commit users, credentials, sessions, private keys, or client secrets.
EOF
