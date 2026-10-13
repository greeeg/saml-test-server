// Ported from mcguinness/node-samlp (MIT, see ./LICENSE): lib/metadata.js.
import { removeHeaders } from './encoders.js';
import { passportProfileMapper, type ProfileMapper } from './profile-mapper.js';
import * as templates from './templates.js';

export interface MetadataOptions {
  issuer: string;
  cert: string | Buffer;
  /** Defaults to the Passport profile mapper. */
  profileMapper?: ProfileMapper;
  /** Path of the HTTP-Redirect SingleSignOnService (appended to the origin). */
  redirectEndpointPath?: string;
  /** Path of the HTTP-POST SingleSignOnService (appended to the origin). */
  postEndpointPath?: string;
  /** Paths of the SingleLogoutService endpoints. */
  logoutEndpointPaths?: { redirect?: string; post?: string };
}

/**
 * Builds the IdP SAML metadata document.
 *
 * @param origin scheme + host the IdP is reachable at, e.g. `https://idp.example.com`
 */
export function buildMetadata(options: MetadataOptions, origin: string): string {
  if (!options.issuer) throw new Error('options.issuer is required');
  if (!options.cert) throw new Error('options.cert is required');

  const pem = removeHeaders(options.cert);
  if (!pem) throw new Error('options.cert must be a PEM certificate');

  const logoutPaths = options.logoutEndpointPaths ?? { redirect: '/logout' };
  const logoutEndpoints: { redirect?: string; post?: string } = {};
  if (logoutPaths.redirect) logoutEndpoints.redirect = origin + logoutPaths.redirect;
  if (logoutPaths.post) logoutEndpoints.post = origin + logoutPaths.post;

  return templates
    .metadata({
      claimTypes: (options.profileMapper ?? passportProfileMapper).metadata,
      pem,
      issuer: options.issuer,
      redirectEndpoint: origin + (options.redirectEndpointPath ?? ''),
      postEndpoint: origin + (options.postEndpointPath ?? ''),
      logoutEndpoints,
    })
    .replace(/\n(?:\s*\n)+/g, '\n');
}
