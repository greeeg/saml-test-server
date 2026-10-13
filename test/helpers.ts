import { readFileSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { SignedXml } from 'xml-crypto';
import * as xmlenc from 'xml-encryption';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url));

export const idpKey = read('../assets/idp-private-key.pem');
export const idpCert = read('../assets/idp-public-cert.pem');
export const sp1Key = read('./fixture/sp1.key');
export const sp1Cert = read('./fixture/sp1.pem');
export const sp2Key = read('./fixture/sp2.key');
export const sp2Cert = read('./fixture/sp2.pem');

export const NS = {
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
};

export const select = xpath.useNamespaces({
  samlp: NS.samlp,
  saml: NS.saml,
  ds: NS.ds,
  xenc: 'http://www.w3.org/2001/04/xmlenc#',
  xsi: 'http://www.w3.org/2001/XMLSchema-instance',
});

export function parse(xml: string) {
  return new DOMParser().parseFromString(xml, 'text/xml');
}

/** Returns the elements of the xpath selection as nodes. */
export function nodes(expression: string, doc: unknown): any[] {
  const result = select(expression, doc as Node);
  return Array.isArray(result) ? (result as any[]) : [];
}

/** Text of the first match of the xpath expression. */
export function text(expression: string, doc: unknown): string | undefined {
  return nodes(expression, doc)[0]?.textContent ?? undefined;
}

/**
 * Verifies the enveloped signature that is a direct child of `container`
 * against `cert`; throws when invalid.
 */
export function verifySignature(xml: string, containerXPath: string, cert: Buffer | string): void {
  const doc = parse(xml);
  const container = nodes(containerXPath, doc)[0];
  if (!container) throw new Error(`No element for ${containerXPath}`);
  const signature = nodes('./ds:Signature', container)[0];
  if (!signature) throw new Error(`No signature in ${containerXPath}`);
  const sig = new SignedXml({ publicCert: cert.toString() });
  sig.loadSignature(signature);
  if (!sig.checkSignature(xml)) {
    throw new Error('Invalid signature');
  }
}

export function decryptAssertion(xml: string, key: Buffer | string): Promise<string> {
  const doc = parse(xml);
  const encrypted = nodes('//xenc:EncryptedData', doc)[0];
  return new Promise((resolve, reject) => {
    xmlenc.decrypt(encrypted.toString(), { key: key.toString() }, (err, result) =>
      err ? reject(err) : resolve(result),
    );
  });
}

export function authnRequest(opts: {
  id?: string;
  issuer?: string;
  acsUrl?: string;
  destination?: string;
  forceAuthn?: boolean;
}): string {
  return (
    `<samlp:AuthnRequest xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}"` +
    ` ID="${opts.id ?? '_req1'}" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"` +
    (opts.destination ? ` Destination="${opts.destination}"` : '') +
    (opts.acsUrl ? ` AssertionConsumerServiceURL="${opts.acsUrl}"` : '') +
    (opts.forceAuthn ? ` ForceAuthn="true"` : '') +
    `><saml:Issuer>${opts.issuer ?? 'https://sp.example.com'}</saml:Issuer></samlp:AuthnRequest>`
  );
}

/** Encodes a SAML message for the HTTP-Redirect binding (deflate + base64). */
export const redirectEncode = (xml: string) => deflateRawSync(Buffer.from(xml)).toString('base64');
/** Encodes a SAML message for the HTTP-POST binding (base64). */
export const postEncode = (xml: string) => Buffer.from(xml).toString('base64');

// ---------------------------------------------------------------------------
// HTTP client for `app.request()` with a cookie jar and tiny HTML helpers
// ---------------------------------------------------------------------------

export function decodeEntities(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

export interface AutoPost {
  action: string;
  fields: Record<string, string>;
}

/** Extracts the action and hidden fields of the first form of an HTML page. */
export function parseForm(html: string): AutoPost {
  const action = /<form[^>]*\saction="([^"]*)"/.exec(html)?.[1];
  const fields: Record<string, string> = {};
  for (const m of html.matchAll(/<input[^>]*\sname="([^"]+)"[^>]*\svalue="([^"]*)"/g)) {
    fields[decodeEntities(m[1])] = decodeEntities(m[2]);
  }
  return { action: decodeEntities(action ?? ''), fields };
}

/** Text content of the element with the given id. */
export function elementText(html: string, id: string): string | undefined {
  const m = new RegExp(`id="${id}"[^>]*>([^<]*)<`).exec(html);
  return m ? decodeEntities(m[1]) : undefined;
}

export class Client {
  private cookies = new Map<string, string>();

  constructor(private readonly app: { request: (path: string, init?: RequestInit) => Response | Promise<Response> }) {}

  async request(path: string, init: RequestInit & { form?: Record<string, string> } = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.cookies.size) {
      headers.set('cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    }
    let body = init.body;
    if (init.form) {
      headers.set('content-type', 'application/x-www-form-urlencoded');
      body = new URLSearchParams(init.form).toString();
    }
    const res = await this.app.request(path, { ...init, headers, body, redirect: 'manual' });
    for (const setCookie of res.headers.getSetCookie()) {
      const [pair, ...attrs] = setCookie.split(';');
      const [name, ...value] = pair.split('=');
      const expired = attrs.some((a) => /max-age=0/i.test(a) || /expires=thu, 01 jan 1970/i.test(a));
      if (expired || value.join('=') === '') this.cookies.delete(name.trim());
      else this.cookies.set(name.trim(), value.join('='));
    }
    return res;
  }

  get(path: string) {
    return this.request(path);
  }

  post(path: string, form: Record<string, string>) {
    return this.request(path, { method: 'POST', form });
  }

  /** Cookie value of the IdP session (for assertions on session handling). */
  get sessionCookie(): string | undefined {
    return this.cookies.get('idp_sid');
  }
}

export function loadFixture(name: string): string {
  return readFileSync(new URL(`./fixture/${name}`, import.meta.url), 'utf8');
}
