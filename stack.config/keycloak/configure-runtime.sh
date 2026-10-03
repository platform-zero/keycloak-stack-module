#!/usr/bin/env bash
set -euo pipefail

REALM="${KEYCLOAK_REALM:-webservices}"
KEYCLOAK_SERVER="${KEYCLOAK_SERVER:-http://keycloak:8080}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:?ERROR: KEYCLOAK_ADMIN_PASSWORD not set}"
DOMAIN="${DOMAIN:?ERROR: DOMAIN not set}"
OAUTH2_PROXY_CLIENT_SECRET="${OAUTH2_PROXY_CLIENT_SECRET:?ERROR: OAUTH2_PROXY_CLIENT_SECRET not set}"

KC_BIN="/opt/keycloak/bin/kcadm.sh"
KC="kc_retry"
GROUPS_CLIENT_SCOPE_ID=""

kc_retry() {
  local attempt=1
  local max_attempts="${KEYCLOAK_CONFIGURE_RETRY_ATTEMPTS:-40}"
  local delay_seconds="${KEYCLOAK_CONFIGURE_RETRY_DELAY_SECONDS:-3}"
  local status

  while true; do
    if "$KC_BIN" "$@"; then
      return 0
    else
      status=$?
    fi
    if [ "$attempt" -ge "$max_attempts" ]; then
      return "$status"
    fi
    echo "[keycloak-configure] kcadm command failed with status $status; retrying in ${delay_seconds}s ($attempt/$max_attempts)" >&2
    sleep "$delay_seconds"
    attempt=$((attempt + 1))
  done
}

# Runtime client registry.
#
# Most services use confidential OIDC clients with the shared groups scope so
# app-local RBAC can be derived from Keycloak group membership. Services that
# cannot fully enforce RBAC natively are additionally protected in Caddy by the
# edge auth gateway. Vaultwarden also receives a hardcoded email_verified claim
# because its SSO path expects verified email identity from the provider.
#
# Client id    Service          Auth mode notes
# webservices-edge  oauth2-proxy edge auth gateway, PKCE S256
# bookstack     native OIDC
# sogo          native OIDC
# jellyfin      native OIDC plus Caddy native-client exceptions
# donetick      native OIDC plus edge group policy
# erpnext       native OIDC plus edge group policy
# forgejo       native OIDC
# mastodon      native OIDC
# matrix        Synapse OIDC for Element/Matrix
# planka        native OIDC
# vaultwarden   native OIDC, PKCE S256, email_verified mapper

first_json_id() {
  sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

json_id_for_name() {
  local expected_name="$1"
  sed -n '
    /^  "id"[[:space:]]*:/ {
      s/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/
      h
    }
    /^  "name"[[:space:]]*:[[:space:]]*"'"$expected_name"'"/ {
      g
      p
      q
    }
  '
}

json_id_for_alias() {
  local expected_alias="$1"
  sed -n '
    /"id"[[:space:]]*:/ {
      s/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/
      h
    }
    /"alias"[[:space:]]*:[[:space:]]*"'"$expected_alias"'"/ {
      g
      p
      q
    }
  '
}

json_id_for_otp_execution() {
  sed -n '
    /"id"[[:space:]]*:/ {
      s/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/
      h
    }
    /"displayName"[[:space:]]*:[[:space:]]*"[^"]*Conditional OTP"/ {
      g
      p
      q
    }
  '
}

ensure_groups_client_scope() {
  local scope_id
  scope_id="$("$KC" get client-scopes -r "$REALM" | json_id_for_name "groups")"

  if [ -z "$scope_id" ]; then
    echo "[keycloak-configure] creating groups client scope"
    scope_json="$(mktemp)"
    cat > "$scope_json" <<'EOF_SCOPE'
{
  "name": "groups",
  "description": "Expose Keycloak group membership in OIDC tokens and userinfo.",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "false"
  }
}
EOF_SCOPE
    "$KC" create client-scopes -r "$REALM" -f "$scope_json" >/dev/null
    scope_id="$("$KC" get client-scopes -r "$REALM" | json_id_for_name "groups")"
  else
    echo "[keycloak-configure] groups client scope already exists"
  fi

  if ! "$KC" get "client-scopes/$scope_id/protocol-mappers/models" -r "$REALM" | grep -q '"name"[[:space:]]*:[[:space:]]*"groups"'; then
    echo "[keycloak-configure] adding groups mapper to groups client scope"
    scope_mapper_json="$(mktemp)"
    cat > "$scope_mapper_json" <<'EOF_SCOPE_MAPPER'
{
  "name": "groups",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-group-membership-mapper",
  "consentRequired": false,
  "config": {
    "full.path": "false",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true",
    "claim.name": "groups",
    "jsonType.label": "String",
    "multivalued": "true"
  }
}
EOF_SCOPE_MAPPER
    "$KC" create "client-scopes/$scope_id/protocol-mappers/models" -r "$REALM" -f "$scope_mapper_json" >/dev/null
  fi

  GROUPS_CLIENT_SCOPE_ID="$scope_id"
}

ensure_client_optional_scope() {
  local client_uuid="$1"
  local client_id_value="$2"
  local scope_uuid="$3"
  local scope_name="$4"

  if [ -z "$scope_uuid" ]; then
    echo "[keycloak-configure] cannot attach $scope_name scope to $client_id_value because scope id is empty" >&2
    return 1
  fi

  if "$KC" get "clients/$client_uuid/optional-client-scopes" -r "$REALM" | grep -q '"name"[[:space:]]*:[[:space:]]*"'"$scope_name"'"'; then
    return 0
  fi

  echo "[keycloak-configure] attaching $scope_name optional client scope to $client_id_value client"
  "$KC" update "clients/$client_uuid/optional-client-scopes/$scope_uuid" -r "$REALM" -n >/dev/null
}

ensure_group() {
  local group_name="$1"

  if "$KC" get groups -r "$REALM" | grep -q '"name"[[:space:]]*:[[:space:]]*"'"$group_name"'"'; then
    echo "[keycloak-configure] group $group_name already exists"
    return 0
  fi

  echo "[keycloak-configure] creating group $group_name"
  group_json="$(mktemp)"
  cat > "$group_json" <<EOF_GROUP
{
  "name": "$group_name"
}
EOF_GROUP
  "$KC" create groups -r "$REALM" -f "$group_json" >/dev/null
}

echo "[keycloak-configure] authenticating admin API"
"$KC" config credentials \
  --server "$KEYCLOAK_SERVER" \
  --realm master \
  --user "$KEYCLOAK_ADMIN_USER" \
  --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null

echo "[keycloak-configure] verifying realm: $REALM"
"$KC" get "realms/$REALM" >/dev/null

echo "[keycloak-configure] applying realm runtime settings"
realm_theme_json="$(mktemp)"
cat > "$realm_theme_json" <<EOF_REALM_THEME
{
  "displayName": "webservices",
  "displayNameHtml": "webservices",
  "eventsEnabled": true,
  "adminEventsEnabled": true,
  "adminEventsDetailsEnabled": true,
  "eventsListeners": [
    "jboss-logging",
    "webservices-onboarding-marker"
  ]
}
EOF_REALM_THEME
"$KC" update "realms/$REALM" -f "$realm_theme_json" >/dev/null

ensure_groups_client_scope
ensure_group "agents"
ensure_group "developers"

ensure_confidential_client() {
  local client_id_value="$1"
  local client_name="$2"
  local client_secret="$3"
  local redirect_uris_json="$4"
  local web_origins_json="${5:-[\"+\"]}"
  local pkce_method="${6:-}"

  if [ -z "$client_secret" ]; then
    echo "[keycloak-configure] ERROR: enabled OIDC client '$client_id_value' has an empty secret" >&2
    exit 1
  fi

  client_json="$(mktemp)"
  local attributes_json="{\"pkce.code.challenge.method\":\"\"}"
  if [ -n "$pkce_method" ]; then
    attributes_json="{\"pkce.code.challenge.method\":\"$pkce_method\"}"
  fi

  cat > "$client_json" <<EOF_CLIENT
{
  "clientId": "$client_id_value",
  "name": "$client_name",
  "enabled": true,
  "publicClient": false,
  "secret": "$client_secret",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": $redirect_uris_json,
  "webOrigins": $web_origins_json,
  "attributes": $attributes_json,
  "protocol": "openid-connect",
  "defaultClientScopes": [
    "web-origins",
    "acr",
    "profile",
    "email",
    "roles"
  ],
  "optionalClientScopes": [
    "address",
    "phone",
    "groups",
    "offline_access",
    "microprofile-jwt"
  ]
}
EOF_CLIENT

  client_id="$("$KC" get clients -r "$REALM" -q clientId="$client_id_value" | first_json_id)"
  if [ -z "$client_id" ]; then
    echo "[keycloak-configure] creating $client_id_value client"
    "$KC" create clients -r "$REALM" -f "$client_json" >/dev/null
    client_id="$("$KC" get clients -r "$REALM" -q clientId="$client_id_value" | first_json_id)"
  else
    echo "[keycloak-configure] updating $client_id_value client"
    "$KC" update "clients/$client_id" -r "$REALM" -f "$client_json" >/dev/null
  fi

  if ! "$KC" get "clients/$client_id/protocol-mappers/models" -r "$REALM" | grep -q '"name"[[:space:]]*:[[:space:]]*"groups"'; then
    echo "[keycloak-configure] adding groups mapper to $client_id_value client"
    mapper_json="$(mktemp)"
    cat > "$mapper_json" <<'EOF_MAPPER'
{
  "name": "groups",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-group-membership-mapper",
  "consentRequired": false,
  "config": {
    "full.path": "false",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true",
    "claim.name": "groups",
    "jsonType.label": "String",
    "multivalued": "true"
  }
}
EOF_MAPPER
    "$KC" create "clients/$client_id/protocol-mappers/models" -r "$REALM" -f "$mapper_json" >/dev/null
  fi

  ensure_client_optional_scope "$client_id" "$client_id_value" "$GROUPS_CLIENT_SCOPE_ID" "groups"
}

ensure_hardcoded_claim_mapper() {
  local client_id_value="$1"
  local mapper_name="$2"
  local claim_name="$3"
  local claim_value="$4"
  local claim_type="${5:-boolean}"
  local client_id

  client_id="$("$KC" get clients -r "$REALM" -q clientId="$client_id_value" | first_json_id)"
  if [ -z "$client_id" ]; then
    echo "[keycloak-configure] cannot add $mapper_name mapper; $client_id_value client is missing"
    return 0
  fi

  if "$KC" get "clients/$client_id/protocol-mappers/models" -r "$REALM" | grep -q '"name"[[:space:]]*:[[:space:]]*"'"$mapper_name"'"'; then
    return 0
  fi

  echo "[keycloak-configure] adding $mapper_name mapper to $client_id_value client"
  mapper_json="$(mktemp)"
  cat > "$mapper_json" <<EOF_MAPPER
{
  "name": "$mapper_name",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-hardcoded-claim-mapper",
  "consentRequired": false,
  "config": {
    "claim.value": "$claim_value",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true",
    "claim.name": "$claim_name",
    "jsonType.label": "$claim_type"
  }
}
EOF_MAPPER
  "$KC" create "clients/$client_id/protocol-mappers/models" -r "$REALM" -f "$mapper_json" >/dev/null
}

ensure_user_property_claim_mapper() {
  local client_id_value="$1"
  local mapper_name="$2"
  local user_attribute="$3"
  local claim_name="$4"
  local client_id

  client_id="$("$KC" get clients -r "$REALM" -q clientId="$client_id_value" | first_json_id)"
  if [ -z "$client_id" ]; then
    echo "[keycloak-configure] cannot add $mapper_name mapper; $client_id_value client is missing"
    return 0
  fi

  if "$KC" get "clients/$client_id/protocol-mappers/models" -r "$REALM" | grep -q '"name"[[:space:]]*:[[:space:]]*"'"$mapper_name"'"'; then
    return 0
  fi

  echo "[keycloak-configure] adding $mapper_name mapper to $client_id_value client"
  mapper_json="$(mktemp)"
  cat > "$mapper_json" <<EOF_MAPPER
{
  "name": "$mapper_name",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-property-mapper",
  "consentRequired": false,
  "config": {
    "user.attribute": "$user_attribute",
    "claim.name": "$claim_name",
    "jsonType.label": "String",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true",
    "introspection.token.claim": "true"
  }
}
EOF_MAPPER
  "$KC" create "clients/$client_id/protocol-mappers/models" -r "$REALM" -f "$mapper_json" >/dev/null
}

ensure_mail_resource_client() {
  local secret="${P0_MAIL_OAUTH_SECRET:-}"
  if [ -z "$secret" ]; then
    echo "[keycloak-configure] ERROR: p0-mail introspection secret is empty" >&2
    exit 1
  fi
  local client_json client_uuid
  client_json="$(mktemp)"
  cat > "$client_json" <<EOF_P0_MAIL
{
  "clientId": "p0-mail",
  "name": "Platform Zero mail token introspection",
  "enabled": true,
  "publicClient": false,
  "secret": "$secret",
  "protocol": "openid-connect",
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "fullScopeAllowed": false
}
EOF_P0_MAIL
  client_uuid="$("$KC" get clients -r "$REALM" -q clientId=p0-mail | first_json_id)"
  if [ -z "$client_uuid" ]; then
    "$KC" create clients -r "$REALM" -f "$client_json" >/dev/null
  else
    "$KC" update "clients/$client_uuid" -r "$REALM" -f "$client_json" >/dev/null
  fi
  rm -f "$client_json"
}

ensure_mail_audience_mapper() {
  local client_id_value="$1"
  local client_uuid mapper_json
  client_uuid="$("$KC" get clients -r "$REALM" -q clientId="$client_id_value" | first_json_id)"
  [ -n "$client_uuid" ] || return 1
  if "$KC" get "clients/$client_uuid/protocol-mappers/models" -r "$REALM" | grep -q '"name"[[:space:]]*:[[:space:]]*"p0-mail-audience"'; then
    return 0
  fi
  mapper_json="$(mktemp)"
  cat > "$mapper_json" <<'EOF_P0_MAIL_MAPPER'
{
  "name": "p0-mail-audience",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "consentRequired": false,
  "config": {
    "included.client.audience": "p0-mail",
    "id.token.claim": "false",
    "access.token.claim": "true",
    "introspection.token.claim": "true"
  }
}
EOF_P0_MAIL_MAPPER
  "$KC" create "clients/$client_uuid/protocol-mappers/models" -r "$REALM" -f "$mapper_json" >/dev/null
  rm -f "$mapper_json"
}

ensure_confidential_client \
  "webservices-edge" \
  "Webservices edge auth gateway" \
  "$OAUTH2_PROXY_CLIENT_SECRET" \
  "[\"https://keycloak-auth.$DOMAIN/oauth2/callback\"]" \
  "[\"https://keycloak-auth.$DOMAIN\"]" \
  "S256"

# webservices-component-start ntfy
ensure_confidential_client "ntfy-native" "Ntfy native password validation" "${NTFY_NATIVE_CLIENT_SECRET:-}" "[]" "[]"
ntfy_native_client_id="$("$KC" get clients -r "$REALM" -q clientId=ntfy-native | first_json_id)"
"$KC" update "clients/$ntfy_native_client_id" -r "$REALM" \
  -s standardFlowEnabled=false -s directAccessGrantsEnabled=true >/dev/null
ntfy_native_flow_id="$("$KC" get authentication/flows -r "$REALM" | json_id_for_alias ntfy-native-password)"
if [ -z "$ntfy_native_flow_id" ]; then
  ntfy_native_flow_copy="$(mktemp)"
  printf '{"newName":"ntfy-native-password"}\n' > "$ntfy_native_flow_copy"
  "$KC" create 'authentication/flows/direct%20grant/copy' -r "$REALM" -f "$ntfy_native_flow_copy" >/dev/null
  rm -f "$ntfy_native_flow_copy"
  ntfy_native_flow_id="$("$KC" get authentication/flows -r "$REALM" | json_id_for_alias ntfy-native-password)"
fi
if [ -z "$ntfy_native_flow_id" ]; then
  echo '[keycloak-configure] ERROR: ntfy native direct grant flow was not created' >&2
  exit 1
fi
ntfy_native_otp_id="$("$KC" get 'authentication/flows/ntfy-native-password/executions' -r "$REALM" | json_id_for_otp_execution)"
if [ -z "$ntfy_native_otp_id" ]; then
  echo '[keycloak-configure] ERROR: ntfy native conditional OTP execution was not found' >&2
  exit 1
fi
ntfy_native_otp_json="$(mktemp)"
printf '{"id":"%s","requirement":"DISABLED"}\n' "$ntfy_native_otp_id" > "$ntfy_native_otp_json"
"$KC" update 'authentication/flows/ntfy-native-password/executions' -r "$REALM" -f "$ntfy_native_otp_json" >/dev/null
rm -f "$ntfy_native_otp_json"
ntfy_native_binding_json="$(mktemp)"
printf '{"authenticationFlowBindingOverrides":{"direct_grant":"%s"}}\n' "$ntfy_native_flow_id" > "$ntfy_native_binding_json"
"$KC" update "clients/$ntfy_native_client_id" -r "$REALM" -f "$ntfy_native_binding_json" >/dev/null
rm -f "$ntfy_native_binding_json"
# webservices-component-end ntfy

# webservices-component-start bookstack
ensure_confidential_client "bookstack" "BookStack" "${BOOKSTACK_OAUTH_SECRET:-}" "[\"https://bookstack.$DOMAIN/oidc/callback\"]" "[\"https://bookstack.$DOMAIN\"]"
# webservices-component-end bookstack
# webservices-component-start sogo
ensure_confidential_client "sogo" "SOGo" "${SOGO_OAUTH_SECRET:-}" "[\"https://sogo.$DOMAIN/SOGo/\"]" "[\"https://sogo.$DOMAIN\"]"
ensure_user_property_claim_mapper "sogo" "sogo-dovecot-email" "email" "email"
ensure_mail_resource_client
ensure_mail_audience_mapper "sogo"
# webservices-component-end sogo
# webservices-component-start jellyfin
ensure_confidential_client "jellyfin" "Jellyfin" "${JELLYFIN_OIDC_SECRET:-}" "[\"https://jellyfin.$DOMAIN/sso/OID/redirect/keycloak\"]" "[\"https://jellyfin.$DOMAIN\"]"
# webservices-component-end jellyfin
# webservices-component-start donetick
ensure_confidential_client "donetick" "Donetick" "${DONETICK_OAUTH_SECRET:-}" "[\"https://donetick.$DOMAIN/auth/oauth2\"]" "[\"https://donetick.$DOMAIN\"]"
# webservices-component-end donetick
# webservices-component-start erpnext
ensure_confidential_client "erpnext" "ERPNext" "${ERPNEXT_OAUTH_SECRET:-}" "[\"https://erpnext.$DOMAIN/api/method/frappe.integrations.oauth2_logins.login_via_keycloak\"]" "[\"https://erpnext.$DOMAIN\"]"
# webservices-component-end erpnext
# webservices-component-start forgejo
ensure_confidential_client "forgejo" "Forgejo" "${FORGEJO_OAUTH_SECRET:-}" "[\"https://forgejo.$DOMAIN/user/oauth2/Keycloak/callback\"]" "[\"https://forgejo.$DOMAIN\"]"
# webservices-component-end forgejo
# webservices-component-start mastodon
ensure_confidential_client "mastodon" "Mastodon" "${MASTODON_OAUTH_SECRET:-}" "[\"https://mastodon.$DOMAIN/auth/auth/openid_connect/callback\"]" "[\"https://mastodon.$DOMAIN\"]"
# webservices-component-end mastodon
# webservices-component-start matrix
ensure_confidential_client "matrix" "Matrix Synapse" "${MATRIX_OAUTH_SECRET:-}" "[\"https://matrix.$DOMAIN/_synapse/client/oidc/callback\"]" "[\"https://matrix.$DOMAIN\",\"https://element.$DOMAIN\"]"
ensure_confidential_client "matrix-authentication-service" "Matrix Authentication Service" "${MATRIX_AUTHENTICATION_SERVICE_OAUTH_SECRET:-}" "[\"https://matrix-auth.$DOMAIN/upstream/callback/${MATRIX_AUTHENTICATION_SERVICE_UPSTREAM_PROVIDER_ID:-01JY9K7VKQ23V93TP9FB9VYQVM}\"]" "[\"https://matrix-auth.$DOMAIN\",\"https://matrix.$DOMAIN\",\"https://element.$DOMAIN\"]"
# webservices-component-end matrix
# webservices-component-start librechat
ensure_confidential_client "librechat" "LibreChat" "${LIBRECHAT_OAUTH_SECRET:-}" "[\"https://ai.$DOMAIN/oauth/openid/callback\"]" "[\"https://ai.$DOMAIN\"]" "S256"
# webservices-component-end librechat
# webservices-component-start planka
ensure_confidential_client "planka" "Planka" "${PLANKA_OAUTH_SECRET:-}" "[\"https://planka.$DOMAIN/oidc-callback\"]" "[\"https://planka.$DOMAIN\"]"
# webservices-component-end planka
# webservices-component-start vaultwarden
ensure_confidential_client "vaultwarden" "Vaultwarden" "${VAULTWARDEN_OAUTH_SECRET:-}" "[\"https://vaultwarden.$DOMAIN/identity/connect/oidc-signin\"]" "[\"https://vaultwarden.$DOMAIN\"]" "S256"
# webservices-component-end vaultwarden
# webservices-component-start huly
ensure_confidential_client "huly" "Huly" "${HULY_OPENID_CLIENT_SECRET:-}" "[\"https://huly.$DOMAIN/_accounts/auth/openid/callback\"]" "[\"https://huly.$DOMAIN\"]"
# webservices-component-end huly

echo "[keycloak-configure] runtime Keycloak clients are ready"
