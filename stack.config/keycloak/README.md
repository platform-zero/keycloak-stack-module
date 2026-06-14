# Keycloak Runtime Configuration

`configure-runtime.sh` applies runtime-only Keycloak state after the realm is available.

It owns:

- groups client scope
- shared group claim mapper
- platform groups
- service OIDC clients
- service-specific protocol mappers

## Client Registry

The shell script currently declares clients through `ensure_confidential_client` calls. Each client should have:

- stable client id
- human-readable name
- secret rendered from runtime env
- public redirect URI
- web origin
- PKCE setting when required by the app

Services using edge auth still need the `webservices-edge` client because Caddy delegates auth checks through the Keycloak auth gateway.

## Editing Rules

- Keep group claims available in ID token, access token, and userinfo.
- Prefer Keycloak groups for RBAC source data.
- Skip clients with empty secrets rather than creating broken OIDC clients.
- Update auth docs and tests when adding or changing a client.

