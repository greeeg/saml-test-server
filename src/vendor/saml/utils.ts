// Ported from mcguinness/node-saml (MIT, see ./LICENSE).
import { randomInt } from 'node:crypto';

export type PemInput = string | Buffer;

/** Strips the PEM armor from a certificate and returns the base64 body on a single line. */
export function pemToCert(pem: PemInput): string | null {
  const cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/.exec(pem.toString());
  if (cert) {
    return cert[1].replace(/[\r\n]/g, '');
  }
  return null;
}

const UID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Returns a random alphanumeric identifier of the given length. */
export function uid(len: number): string {
  let out = '';
  for (let i = 0; i < len; i++) {
    out += UID_CHARS[randomInt(0, UID_CHARS.length)];
  }
  return out;
}

export function removeWhitespace(xml: string): string {
  return xml
    .replace(/\r\n/g, '')
    .replace(/\n/g, '')
    .replace(/>(\s*)</g, '><') // unindent
    .trim();
}

/**
 * Standardizes PEM content to match the spec (best effort).
 * The original value is returned unmodified if the content is not PEM.
 */
export function fixPemFormatting(pem: PemInput): PemInput {
  const entries = pem
    .toString()
    .matchAll(/([-]{5}[^-\r\n]+[-]{5})([^-]*)([-]{5}[^-\r\n]+[-]{5})/g);
  let fixed = '';
  for (const parts of entries) {
    fixed += `${parts[1]}\n${parts[2].replace(/[\r\n]/g, '')}\n${parts[3]}\n`;
  }
  if (fixed.length === 0) {
    return pem;
  }
  return Buffer.from(fixed);
}

/**
 * Formats a date as an `xs:dateTime` in UTC with millisecond precision
 * (`YYYY-MM-DDTHH:mm:ss.SSSZ`).
 */
export function formatInstant(date: Date): string {
  return date.toISOString();
}

/** Escapes a string for use in XML text or double-quoted attribute values. */
export function escapeXml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
