import { expect, test } from '@playwright/test';
import { serviceUrl } from '../../../utils/stack-urls';

const keycloakRealm = process.env.KEYCLOAK_REALM || 'webservices';
const keycloakBaseUrl = process.env.KEYCLOAK_URL || serviceUrl('keycloak');

const oidcRedirectContracts = [
  ['webservices-edge', serviceUrl('keycloak-auth', '/oauth2/callback')],
  ['bookstack', serviceUrl('bookstack', '/oidc/callback')],
  ['sogo', serviceUrl('sogo', '/SOGo/')],
  ['jellyfin', serviceUrl('jellyfin', '/sso/OID/redirect/keycloak')],
  ['donetick', serviceUrl('donetick', '/auth/oauth2')],
  ['erpnext', serviceUrl('erpnext', '/api/method/frappe.integrations.oauth2_logins.login_via_keycloak')],
  ['forgejo', serviceUrl('forgejo', '/user/oauth2/Keycloak/callback')],
  ['mastodon', serviceUrl('mastodon', '/auth/auth/openid_connect/callback')],
  ['matrix', serviceUrl('matrix', '/_synapse/client/oidc/callback')],
  [
    'matrix-authentication-service',
    serviceUrl(
      'matrix-auth',
      `/upstream/callback/${process.env.MATRIX_AUTHENTICATION_SERVICE_UPSTREAM_PROVIDER_ID || '01JY9K7VKQ23V93TP9FB9VYQVM'}`
    ),
  ],
  ['planka', serviceUrl('planka', '/oidc-callback')],
  ['vaultwarden', serviceUrl('vaultwarden', '/identity/connect/oidc-signin')],
  ['test-runner', 'http://localhost:8080/callback'],
  ['test-runner', 'http://test-runner/callback'],
  ['test-runner', 'http://test-runner-managed/callback'],
] as const;

test.describe('Keycloak OIDC smoke', () => {
  test('serves the webservices realm discovery document', async ({ request }) => {
    const response = await request.get(`${keycloakBaseUrl}/realms/${keycloakRealm}/.well-known/openid-configuration`);
    expect(response.status()).toBe(200);

    const discovery = await response.json();
    expect(discovery.issuer).toBe(`${keycloakBaseUrl}/realms/${keycloakRealm}`);
    expect(discovery.authorization_endpoint).toContain('/protocol/openid-connect/auth');
    expect(discovery.token_endpoint).toContain('/protocol/openid-connect/token');
    expect(discovery.jwks_uri).toContain('/protocol/openid-connect/certs');
  });

  test('protects the low-risk whoami route through the Keycloak auth gateway', async ({ request }) => {
    const protectedResponse = await request.get(serviceUrl('keycloak-whoami'), { maxRedirects: 0 });
    expect([302, 303]).toContain(protectedResponse.status());
    expect(protectedResponse.headers().location).toContain(serviceUrl('keycloak-auth', '/oauth2/start'));

    const authStart = await request.get(
      serviceUrl('keycloak-auth', `/oauth2/start?rd=${encodeURIComponent(serviceUrl('keycloak-whoami'))}`),
      { maxRedirects: 0 }
    );
    expect([302, 303]).toContain(authStart.status());
    expect(authStart.headers().location).toContain(`${keycloakBaseUrl}/realms/${keycloakRealm}/protocol/openid-connect/auth`);
  });

  for (const [clientId, redirectUri] of oidcRedirectContracts) {
    test(`${clientId} accepts only the explicit redirect URI ${redirectUri}`, async ({ request }) => {
      const authorize = new URL(`${keycloakBaseUrl}/realms/${keycloakRealm}/protocol/openid-connect/auth`);
      authorize.searchParams.set('response_type', 'code');
      authorize.searchParams.set('scope', 'openid');
      authorize.searchParams.set('client_id', clientId);
      authorize.searchParams.set('redirect_uri', redirectUri);
      authorize.searchParams.set('state', 'redirect-contract-probe');
      authorize.searchParams.set('code_challenge_method', 'S256');
      authorize.searchParams.set('code_challenge', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');

      const accepted = await request.get(authorize.toString(), { maxRedirects: 0 });
      expect(accepted.status(), `${clientId} rejected ${redirectUri}`).toBe(200);

      authorize.searchParams.set('redirect_uri', `${redirectUri}not-registered`);
      const rejected = await request.get(authorize.toString(), { maxRedirects: 0 });
      expect(rejected.status(), `${clientId} accepted a redirect URI outside its exact allow-list`).toBe(400);
    });
  }
});
