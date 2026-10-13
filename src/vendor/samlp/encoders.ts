// Ported from mcguinness/node-samlp (MIT, see ./LICENSE).
import { createHash } from 'node:crypto';

/** Returns the base64 body of the first PEM block (no armor, no line breaks). */
export function removeHeaders(cert: string | Buffer): string | null {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\r\n]/g, '');
  }
  return null;
}

/** SHA-1 thumbprint (upper-case hex) of a base64 DER certificate. */
export function calculateThumbprint(base64Cert: string): string {
  return createHash('sha1')
    .update(Buffer.from(base64Cert.replace(/\s/g, ''), 'base64'))
    .digest('hex')
    .toUpperCase();
}

export function thumbprint(pem: string | Buffer): string {
  const cert = removeHeaders(pem);
  if (!cert) throw new Error('Invalid certificate');
  return calculateThumbprint(cert);
}
