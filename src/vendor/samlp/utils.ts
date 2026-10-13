// Ported from mcguinness/node-samlp (MIT, see ./LICENSE).
import { randomBytes } from 'node:crypto';
import { inflateRaw } from 'node:zlib';
import { promisify } from 'node:util';
import qs from 'node:querystring';
import { ELEMENTS, type ElementType } from './constants.js';
import * as signers from './signers.js';
import { parseXml, selectNodes, type XmlDocument } from './xml.js';

const inflateRawAsync = promisify(inflateRaw);

const SIGNATURE_ALGORITHM_NAMES: Record<string, string> = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'rsa-sha256',
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'rsa-sha1',
};

/** Minimal, framework-agnostic view of an incoming HTTP request. */
export interface SamlHttpInput {
  query: Record<string, string | undefined>;
  body: Record<string, string | undefined>;
}

export interface SigningCredentials {
  cert?: string | Buffer;
  thumbprints?: string | string[];
}

export interface ParseRequestOptions {
  signingCert?: string | Buffer;
  thumbprints?: string | string[];
  relayState?: string;
  signaturePath?: string;
  /**
   * Resolves the credentials used to validate the signature of the incoming
   * message from its issuer (and for logout requests, session index / NameID).
   */
  getCredentials?: (
    issuer: string | undefined,
    sessionIndices: string[] | undefined,
    nameId: string | undefined,
  ) => SigningCredentials | undefined | Promise<SigningCredentials | undefined>;
}

interface ValidateOptions {
  signingCert?: string | Buffer;
  thumbprints?: string | string[];
  deflate?: boolean;
  relayState?: string;
  signaturePath?: string;
}

/** Generates a random 20 character hexadecimal identifier. */
export function generateUniqueID(): string {
  return randomBytes(10).toString('hex');
}

/**
 * Formats the given date in `xs:DateTime` format as per Core SAML "1.3.3 Time Values":
 * UTC, no time zone component, millisecond precision.
 */
export function formatXmlDateTime(date: Date): string {
  return date.toISOString();
}

export function generateInstant(): string {
  return formatXmlDateTime(new Date());
}

export function appendQueryString(initialUrl: string, query: Record<string, string>): string {
  const parsed = new URL(initialUrl);
  for (const [key, value] of Object.entries(query)) {
    parsed.searchParams.set(key, value);
  }
  return parsed.toString();
}

function isXmlBuffer(input: Buffer): boolean {
  return input[0] === 60; // '<'
}

/**
 * Decodes (base64, then optionally inflates) and parses a SAML request, and
 * validates its signature when a signing credential is available.
 *
 * @returns the parsed DOM, or `undefined` when there is no SAML message
 */
export async function parseSamlRequest(
  input: SamlHttpInput,
  samlRequest: string | undefined,
  type: ElementType,
  options: ParseRequestOptions = {},
): Promise<XmlDocument | undefined> {
  if (!samlRequest) return undefined;

  const raw = Buffer.from(samlRequest, 'base64');
  let xmlString: string;
  if (isXmlBuffer(raw)) {
    // content is just encoded, not zipped
    xmlString = raw.toString();
  } else {
    xmlString = (await inflateRawAsync(raw)).toString();
  }

  let xml: XmlDocument;
  try {
    xml = parseXml(xmlString);
  } catch (e) {
    throw new Error(e instanceof Error ? e.message : String(e));
  }
  if (!xml || !xml.documentElement) {
    throw new Error('Invalid SAML Request');
  }

  const credentials = await configureSigningCredentials(xml, type, options);
  if (!credentials) return xml;

  validateSignature(input, type, xml, xmlString, {
    signingCert: credentials.cert,
    thumbprints: credentials.thumbprints,
    deflate: !!input.query.Signature,
    relayState: options.relayState,
    signaturePath: options.signaturePath,
  });
  return xml;
}

/**
 * Determines whether the message signature must be validated and with which
 * credentials. Returns `undefined` when no validation is needed.
 */
async function configureSigningCredentials(
  xml: XmlDocument,
  type: ElementType,
  options: ParseRequestOptions,
): Promise<SigningCredentials | undefined> {
  if (options.signingCert || (options.thumbprints && options.thumbprints.length > 0)) {
    return { cert: options.signingCert, thumbprints: options.thumbprints };
  }
  if (!options.getCredentials) return undefined;

  const descriptor = ELEMENTS[type];
  const issuer = descriptor.ISSUER_PATH
    ? selectNodes(descriptor.ISSUER_PATH, xml)[0]?.textContent ?? undefined
    : undefined;

  let sessionIndices: string[] | undefined;
  if (descriptor.SESSION_INDEX_PATH) {
    const nodes = selectNodes(descriptor.SESSION_INDEX_PATH, xml);
    if (nodes.length > 0) sessionIndices = nodes.map((n) => n.textContent ?? '');
  }

  let nameId: string | undefined;
  if (descriptor.NAME_ID) {
    nameId = selectNodes(descriptor.NAME_ID, xml)[0]?.textContent ?? undefined;
  }

  if (!issuer && !(sessionIndices && sessionIndices.length) && !nameId) {
    return undefined;
  }

  let credentials: SigningCredentials | undefined;
  try {
    credentials = await options.getCredentials(issuer, sessionIndices, nameId);
  } catch {
    return undefined;
  }
  if (!credentials) return undefined;
  return credentials;
}

/**
 * Validates the signature of a SAML request/response received through the
 * HTTP-POST binding (embedded XML signature) or HTTP-Redirect binding
 * (detached `Signature` / `SigAlg` query parameters).
 *
 * @throws when the message is signed with an invalid signature, or unsigned
 * while a signing certificate is configured.
 */
export function validateSignature(
  input: SamlHttpInput,
  elementType: ElementType,
  xml: XmlDocument,
  xmlString: string,
  options: ValidateOptions,
): void {
  const descriptor = ELEMENTS[elementType];
  const prop = descriptor.PROP;

  const isRequestSigned = !options.deflate
    ? selectNodes((options.signaturePath ?? descriptor.SIGNATURE_VALIDATION_PATH) as string, xml).length > 0
    : !!input.query.Signature;

  if (isRequestSigned) {
    if (input.body[prop] || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      const errors = signers.validateXmlEmbeddedSignature(xml, xmlString, options);
      if (errors.length > 0) {
        throw new Error('Signature check errors: ' + errors.join('; '));
      }
    } else {
      // HTTP-Redirect with deflate encoding
      const signedContent: Record<string, string | undefined> = {
        [prop]: input.query[prop],
        RelayState: input.query.RelayState || options.relayState,
        SigAlg: input.query.SigAlg,
      };

      if (!signedContent.RelayState) {
        delete signedContent.RelayState;
      }
      if (!signedContent.SigAlg) {
        throw new Error('Signature Algorithm is missing');
      }
      if (!SIGNATURE_ALGORITHM_NAMES[signedContent.SigAlg]) {
        throw new Error(
          'Invalid signature algorithm. Supported algorithms are http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 and http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        );
      }
      if (!options.signingCert) {
        throw new Error('options.signingCert must be specified to validate a detached signature');
      }

      const valid = signers.isValidContentAndSignature(
        qs.stringify(signedContent as Record<string, string>),
        input.query.Signature as string,
        { signingCert: options.signingCert, signatureAlgorithm: signedContent.SigAlg },
      );
      if (!valid) {
        throw new Error(
          'Signature check errors: The signature provided (' +
            input.query.Signature +
            ') does not match the one calculated',
        );
      }
    }
  } else if (options.signingCert) {
    throw new Error(prop + ' message MUST be signed when using an asynchronous binding (POST or Redirect)');
  }
}
