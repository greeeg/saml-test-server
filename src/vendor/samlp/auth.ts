// Ported from mcguinness/node-samlp (MIT, see ./LICENSE): lib/samlp.js.
// The Express middlewares were rewritten as framework-agnostic async functions.
import { createAssertion, type Saml20Options } from '../saml/saml20.js';
import type { DigestAlgorithm, SignatureAlgorithm } from '../saml/sign.js';
import { ELEMENTS, STATUS } from './constants.js';
import { removeHeaders } from './encoders.js';
import { passportProfileMapper, type ProfileMapper } from './profile-mapper.js';
import { signXml } from './signers.js';
import * as templates from './templates.js';
import {
  generateInstant,
  generateUniqueID,
  parseSamlRequest,
  type ParseRequestOptions,
  type SamlHttpInput,
} from './utils.js';
import { selectNodes, type XmlDocument } from './xml.js';

const ISSUER_XPATH =
  "//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()";

/** Error that carries the HTTP status the caller should answer with. */
export class SamlpError extends Error {
  status: number;
  context?: unknown;
  constructor(message: string, status = 500, context?: unknown) {
    super(message);
    this.name = 'SamlpError';
    this.status = status;
    this.context = context;
  }
}

export interface ResponseOptions
  extends Omit<Saml20Options, 'attributes' | 'audiences' | 'nameIdentifier'> {
  issuer: string;
  cert: string | Buffer;
  key: string | Buffer;
  audience?: string;
  destination?: string;
  signResponse?: boolean;
  signAssertion?: boolean;
  signatureAlgorithm?: SignatureAlgorithm;
  digestAlgorithm?: DigestAlgorithm;
  signatureNamespacePrefix?: string;
  profileMapper?: ProfileMapper;
  nameIdentifierProbes?: string[];
  samlStatusCode?: string;
  samlStatusMessage?: string;
}

export interface AuthOptions extends ResponseOptions, ParseRequestOptions {
  RelayState?: string;
  /** Resolves where the SAMLResponse is posted to. */
  getPostURL: (
    audience: string | undefined,
    authnRequest: XmlDocument | undefined,
  ) => string | undefined | Promise<string | undefined>;
}

export interface PostForm {
  /** Form action (Assertion Consumer Service URL). */
  url: string;
  /** `SAMLResponse` or `SAMLRequest`. */
  field: 'SAMLResponse' | 'SAMLRequest';
  /** Base64 value of the SAML message. */
  value: string;
  relayState: string;
}

export interface AuthResult extends PostForm {
  /** The XML of the (signed) SAML Response. */
  xml: string;
  /** Options that were effective for this response. */
  options: AuthOptions & { postUrl: string; audience?: string };
}

export function buildSamlResponse(
  options: ResponseOptions & { samlAssertion?: string; inResponseTo?: string },
): string {
  let response = templates.samlResponse({
    id: '_' + generateUniqueID(),
    instant: generateInstant(),
    destination: options.destination || options.audience,
    inResponseTo: options.inResponseTo,
    issuer: options.issuer,
    samlStatusCode: options.samlStatusCode ?? STATUS.SUCCESS,
    samlStatusMessage: options.samlStatusMessage,
    assertion: options.samlAssertion || '',
  });

  if (options.signResponse) {
    response = signXml(
      {
        key: options.key,
        cert: options.cert,
        signatureAlgorithm: options.signatureAlgorithm,
        digestAlgorithm: options.digestAlgorithm,
        reference: ELEMENTS.RESPONSE.SIGNATURE_LOCATION_PATH,
      },
      response,
    );
  }

  return response;
}

function nameIdentifierNotFoundErrorMessage(options: ResponseOptions): string {
  const probes = Array.isArray(options.nameIdentifierProbes)
    ? options.nameIdentifierProbes.join(', ')
    : '';
  return 'No attribute was found to generate the nameIdentifier. We tried with: ' + probes;
}

/** Maps `user` to claims, builds + signs (+ encrypts) the assertion and wraps it in a Response. */
export async function createSamlResponse(
  samlConfig: ResponseOptions,
  user: unknown,
): Promise<string> {
  const options = {
    ...samlConfig,
    profileMapper: (samlConfig.profileMapper ?? passportProfileMapper) as ProfileMapper,
    signAssertion: typeof samlConfig.signAssertion !== 'boolean' || samlConfig.signAssertion,
    signatureNamespacePrefix:
      typeof samlConfig.signatureNamespacePrefix === 'string' ? samlConfig.signatureNamespacePrefix : '',
  };
  const mapper = options.profileMapper;
  const claims = mapper.getClaims(user);
  const ni = mapper.getNameIdentifier(user);

  if (!ni || !ni.nameIdentifier) {
    throw new SamlpError(nameIdentifierNotFoundErrorMessage(options), 500, { user });
  }

  const samlAssertion = await createAssertion({
    signatureAlgorithm: options.signatureAlgorithm,
    digestAlgorithm: options.digestAlgorithm,
    signAssertion: options.signAssertion,
    cert: options.cert,
    key: options.key,
    issuer: options.issuer,
    lifetimeInSeconds: options.lifetimeInSeconds || 3600,
    audiences: options.audience,
    attributes: claims || undefined,
    nameIdentifier: ni.nameIdentifier,
    nameIdentifierFormat: ni.nameIdentifierFormat || options.nameIdentifierFormat,
    nameIdentifierNameQualifier: ni.nameIdentifierNameQualifier,
    nameIdentifierSPNameQualifier: ni.nameIdentifierSPNameQualifier,
    nameIdentifierSPProvidedID: ni.nameIdentifierSPProvidedID,
    recipient: options.recipient,
    inResponseTo: options.inResponseTo,
    authnContextClassRef: options.authnContextClassRef,
    encryptionPublicKey: options.encryptionPublicKey,
    encryptionCert: options.encryptionCert,
    encryptionAlgorithm: options.encryptionAlgorithm,
    keyEncryptionAlgorithm: options.keyEncryptionAlgorithm,
    sessionIndex: options.sessionIndex,
    typedAttributes: options.typedAttributes,
    includeAttributeNameFormat: options.includeAttributeNameFormat,
    signatureNamespacePrefix: options.signatureNamespacePrefix,
    transformAssertion: options.transformAssertion,
  });

  return buildSamlResponse({
    ...options,
    samlAssertion,
    samlStatusCode: options.samlStatusCode || STATUS.SUCCESS,
  });
}

/**
 * Handles an SP-initiated or IdP-initiated SSO request for an authenticated user:
 * parses the optional AuthnRequest, then mints a SAML Response for `user`.
 */
export async function authenticate(
  input: SamlHttpInput,
  options: AuthOptions,
  user: unknown,
): Promise<AuthResult> {
  const opts = {
    ...options,
    signatureAlgorithm: options.signatureAlgorithm || 'rsa-sha256',
    digestAlgorithm: options.digestAlgorithm || 'sha256',
  } as AuthOptions & { postUrl: string };

  if (typeof opts.getPostURL !== 'function') {
    throw new Error('getPostURL is required');
  }

  const samlRequest = input.query.SAMLRequest || input.body.SAMLRequest;
  const samlRequestDom = await parseSamlRequest(input, samlRequest, 'AUTHN_REQUEST', {
    ...opts,
    relayState: opts.RelayState || input.query.RelayState,
  });

  let audience = opts.audience;
  if (samlRequestDom) {
    if (!audience) {
      audience = selectNodes(ISSUER_XPATH, samlRequestDom)[0]?.textContent ?? undefined;
    }
    const id = samlRequestDom.documentElement?.getAttribute('ID');
    if (id) opts.inResponseTo = opts.inResponseTo || id;
  }

  const postUrl = await opts.getPostURL(audience, samlRequestDom);
  if (!postUrl) throw new SamlpError('Unable to determine the Assertion Consumer Service URL', 401);

  if (!user) throw new SamlpError('Unauthorized', 401);

  opts.audience = audience;
  opts.postUrl = postUrl;

  const xml = await createSamlResponse(opts, user);

  return {
    url: postUrl,
    field: 'SAMLResponse',
    value: Buffer.from(xml).toString('base64'),
    relayState: opts.RelayState || input.query.RelayState || input.body.RelayState || '',
    xml,
    options: opts,
  };
}

export interface AuthnRequestData {
  id?: string;
  issuer?: string;
  subject?: string;
  destination?: string;
  assertionConsumerServiceURL?: string;
  forceAuthn?: string;
  requestedAuthnContext?: { authnContextClassRef: string };
}

/** Parses an incoming `AuthnRequest`. Returns `undefined` when the request carries none. */
export async function parseRequest(
  input: SamlHttpInput,
  options: ParseRequestOptions = {},
): Promise<AuthnRequestData | undefined> {
  const samlRequest = input.query.SAMLRequest || input.body.SAMLRequest;
  if (!samlRequest) return undefined;

  const dom = await parseSamlRequest(input, samlRequest, 'AUTHN_REQUEST', options);
  if (!dom) return undefined;

  const data: AuthnRequestData = {};
  const root = dom.documentElement!;

  const issuer = selectNodes(ISSUER_XPATH, dom);
  if (issuer.length > 0) data.issuer = issuer[0].textContent ?? undefined;

  const subject = selectNodes(
    "//*[local-name(.)='Subject' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/*[local-name(.)='NameID']",
    dom,
  );
  if (subject.length > 0) data.subject = subject[0].textContent ?? undefined;

  const acs = root.getAttribute('AssertionConsumerServiceURL');
  if (acs) data.assertionConsumerServiceURL = acs;

  const destination = root.getAttribute('Destination');
  if (destination) data.destination = destination;

  const forceAuthn = root.getAttribute('ForceAuthn');
  if (forceAuthn) data.forceAuthn = forceAuthn;

  const id = root.getAttribute('ID');
  if (id) data.id = id;

  const classRefs = selectNodes(ELEMENTS.AUTHN_REQUEST.AUTHN_CONTEXT_CLASS_REF_PATH as string, dom);
  if (classRefs.length === 1) {
    data.requestedAuthnContext = { authnContextClassRef: classRefs[0].textContent ?? '' };
  }

  return data;
}

export interface ErrorResponseOptions extends ResponseOptions {
  RelayState?: string;
  error?: { code?: string; description?: string };
  postUrl: string;
  inResponseTo?: string;
}

/** Builds a (signed) error Response to be posted back to the SP. */
export function createErrorResponse(options: ErrorResponseOptions): PostForm {
  const error = options.error ?? {};
  const xml = buildSamlResponse({
    ...options,
    samlStatusCode: error.code || STATUS.RESPONDER,
    samlStatusMessage: error.description,
  });
  return {
    url: options.postUrl,
    field: 'SAMLResponse',
    value: Buffer.from(xml).toString('base64'),
    relayState: options.RelayState ?? '',
  };
}

export { removeHeaders };
