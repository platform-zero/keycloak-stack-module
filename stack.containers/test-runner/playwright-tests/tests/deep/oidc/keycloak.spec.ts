import { expect, test } from '@playwright/test';
import { serviceUrl } from '../../../utils/stack-urls';

const keycloakRealm = process.env.KEYCLOAK_REALM || 'webservices';
const keycloakBaseUrl = process.env.KEYCLOAK_URL || serviceUrl('keycloak');

test.describe('Keycloak OIDC smoke', () => {
  test('serves the webservices realm discovery document', async ({ request }) => {
    const response = await request.get(`${keycloakBaseUrl}/realms/${keycloakRealm}/.well-known/openid-configuration`);
    expect(response.ok()).toBeTruthy();

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
});
