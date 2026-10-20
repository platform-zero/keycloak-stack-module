#!/usr/bin/env bash
# Sourced by the existing selected-component Keycloak installer. Native kcadm
# only; no new authentication protocol, runtime dependency build or password argv.
configure_finance_identity() (
  set -euo pipefail
  shopt -s inherit_errexit
  umask 077
  local_uuid='[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}'
  [[ "$DOMAIN" =~ ^[a-z0-9]+([.-][a-z0-9]+)*$ ]]
  owner="${FIREFLY_OWNER_SUBJECT:?Explicit finance owner subject required}"
  [[ "$owner" =~ ^${local_uuid}$ ]]
  for secret in "${FIREFLY_OAUTH_SECRET:?}" "${FIREFLY_IMPORTER_OAUTH_SECRET:?}" "${FIREFLY_IDENTITY_CLIENT_SECRET:?}"; do
    [[ "$secret" =~ ^[A-Za-z0-9_+/=-]{32,256}$ ]]
  done
  [[ "$FIREFLY_OAUTH_SECRET" != "$FIREFLY_IMPORTER_OAUTH_SECRET" && "$FIREFLY_OAUTH_SECRET" != "$FIREFLY_IDENTITY_CLIENT_SECRET" && "$FIREFLY_IMPORTER_OAUTH_SECRET" != "$FIREFLY_IDENTITY_CLIENT_SECRET" ]]
  tmp="$(mktemp -d /tmp/p0-finance-config-XXXXXXXX)"
  trap 'rm -rf -- "$tmp"' EXIT

  finance_id() {
    local ids
    ids="$(sed -n 's/^[[:space:]]*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)"[,[:space:]]*$/\1/p')"
    [[ -z "$ids" || "$ids" =~ ^${local_uuid}$ ]] || return 1
    printf '%s' "$ids"
  }
  finance_human() {
    local subject="$1" compact
    [[ "$subject" =~ ^${local_uuid}$ ]]
    "$KC" get "users/$subject" -r "$REALM" --fields id,enabled,emailVerified,requiredActions,serviceAccountClientId > "$tmp/human.json"
    [[ "$(finance_id < "$tmp/human.json")" == "$subject" ]]
    compact="$(tr -d '[:space:]' < "$tmp/human.json")"
    [[ "$compact" == *'"enabled":true'* && "$compact" == *'"emailVerified":true'* && "$compact" == *'"requiredActions":[]'* ]]
    [[ ! "$compact" =~ \"serviceAccountClientId\":\"[^\"]+\" ]]
  }
  finance_group() {
    local name="$1" id compact
    "$KC" get groups -r "$REALM" -q "search=$name" -q exact=true --fields id,name,path > "$tmp/group.json"
    id="$(finance_id < "$tmp/group.json")"
    if [[ -z "$id" ]]; then
      printf '{"name":"%s"}\n' "$name" > "$tmp/new-group.json"
      "$KC" create groups -r "$REALM" -f "$tmp/new-group.json" >/dev/null
      "$KC" get groups -r "$REALM" -q "search=$name" -q exact=true --fields id,name,path > "$tmp/group.json"
      id="$(finance_id < "$tmp/group.json")"
    fi
    [[ -n "$id" ]]
    compact="$(tr -d '[:space:]' < "$tmp/group.json")"
    [[ "$compact" == *"\"path\":\"/$name\""* ]]
    printf '%s' "$id"
  }
  finance_owned_client() {
    local name="$1" payload="$2" id compact
    "$KC" get clients -r "$REALM" -q "clientId=$name" --fields id,attributes > "$tmp/client.json"
    id="$(finance_id < "$tmp/client.json")"
    if [[ -n "$id" ]]; then
      compact="$(tr -d '[:space:]' < "$tmp/client.json")"
      [[ "$compact" == *'"p0.managed-module":"firefly-iii"'* ]]
      "$KC" update "clients/$id" -r "$REALM" -f "$payload" >/dev/null
    else
      "$KC" create clients -r "$REALM" -f "$payload" >/dev/null
    fi
    id="$("$KC" get clients -r "$REALM" -q "clientId=$name" --fields id | finance_id)"
    [[ -n "$id" ]]
    printf '%s' "$id"
  }
  finance_browser_client() {
    local name="$1" hostname="$2" secret="$3"
    cat > "$tmp/browser-client.json" <<EOF_FINANCE_CLIENT
{
 "clientId":"$name", "name":"Subject-bound finance SSO", "enabled":true,
 "publicClient":false, "secret":"$secret", "protocol":"openid-connect",
 "standardFlowEnabled":true, "implicitFlowEnabled":false,
 "directAccessGrantsEnabled":false, "serviceAccountsEnabled":false,
 "fullScopeAllowed":false,
 "redirectUris":["https://$hostname.$DOMAIN/oauth2/callback"],
 "webOrigins":["https://$hostname.$DOMAIN"],
 "attributes":{"p0.managed-module":"firefly-iii","pkce.code.challenge.method":"S256","access.token.lifespan":"60","post.logout.redirect.uris":"https://firefly.$DOMAIN/sso/logged-out"},
 "defaultClientScopes":["profile","email"], "optionalClientScopes":[],
 "protocolMappers":[{"name":"finance-groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper","consentRequired":false,
 "config":{"full.path":"true","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","claim.name":"groups","jsonType.label":"String","multivalued":"true"}}]
}
EOF_FINANCE_CLIENT
    finance_owned_client "$name" "$tmp/browser-client.json" >/dev/null
  }

  # Explicit enrollment, never all realm users or the first browser visitor.
  finance_human "$owner"
  owner_group="$(finance_group finance-owner)"
  user_group="$(finance_group finance-users)"
  members="$("$KC" get "groups/$owner_group/members" -r "$REALM" -q first=0 -q max=2 --fields id | finance_id)"
  [[ -z "$members" || "$members" == "$owner" ]]
  "$KC" update "users/$owner/groups/$owner_group" -r "$REALM" -n >/dev/null
  members="$("$KC" get "groups/$owner_group/members" -r "$REALM" -q first=0 -q max=2 --fields id | finance_id)"
  [[ "$members" == "$owner" ]]
  # Deliberate site-owned non-admin enrollment; no bank or service-account users.
  IFS=',' read -r -a subjects <<< "${FIREFLY_USER_SUBJECTS:-}"
  [[ "${#subjects[@]}" -le 20 ]]
  for subject in "${subjects[@]}"; do
    [[ -n "$subject" ]] || continue
    [[ "$subject" != "$owner" ]]
    finance_human "$subject"
    "$KC" update "users/$subject/groups/$user_group" -r "$REALM" -n >/dev/null
  done
  finance_browser_client firefly-sso firefly "$FIREFLY_OAUTH_SECRET"
  finance_browser_client firefly-importer-sso firefly-importer "$FIREFLY_IMPORTER_OAUTH_SECRET"

  cat > "$tmp/reader-client.json" <<EOF_FINANCE_READER
{
 "clientId":"firefly-identity-reader", "name":"Finance eligibility read gate", "enabled":true,
 "publicClient":false, "secret":"$FIREFLY_IDENTITY_CLIENT_SECRET", "protocol":"openid-connect",
 "standardFlowEnabled":false, "implicitFlowEnabled":false,
 "directAccessGrantsEnabled":false, "serviceAccountsEnabled":true,
 "fullScopeAllowed":false, "redirectUris":[], "webOrigins":[],
 "attributes":{"p0.managed-module":"firefly-iii","access.token.lifespan":"60"},
 "defaultClientScopes":["roles"], "optionalClientScopes":[]
}
EOF_FINANCE_READER
  reader="$(finance_owned_client firefly-identity-reader "$tmp/reader-client.json")"
  management="$("$KC" get clients -r "$REALM" -q clientId=realm-management --fields id | finance_id)"
  account="$("$KC" get "clients/$reader/service-account-user" -r "$REALM" --fields id | finance_id)"
  [[ -n "$management" && -n "$account" ]]
  for role in view-users query-users query-groups; do
    "$KC" get "clients/$management/roles/$role" -r "$REALM" --fields id,name > "$tmp/role-$role.json"
    [[ -n "$(finance_id < "$tmp/role-$role.json")" ]]
  done
  printf '[%s,%s,%s]\n' "$(<"$tmp/role-view-users.json")" "$(<"$tmp/role-query-users.json")" "$(<"$tmp/role-query-groups.json")" > "$tmp/reader-roles.json"
  "$KC" create "users/$account/role-mappings/clients/$management" -r "$REALM" -f "$tmp/reader-roles.json" >/dev/null
  "$KC" create "clients/$reader/scope-mappings/clients/$management" -r "$REALM" -f "$tmp/reader-roles.json" >/dev/null
  "$KC" get "users/$account/role-mappings/clients/$management/composite" -r "$REALM" --fields name > "$tmp/effective-roles.json"
  names="$(sed -n 's/^[[:space:]]*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)"[,[:space:]]*$/\1/p' "$tmp/effective-roles.json")"
  [[ -n "$names" ]]
  while IFS= read -r name; do
    case "$name" in view-users|query-users|query-groups) ;; *) echo '[keycloak-configure] unexpected finance reader privilege; refusing' >&2; exit 1 ;; esac
  done <<< "$names"
  echo '[keycloak-configure] explicit finance enrollment, PKCE clients and read-only eligibility identity provisioned'
)
