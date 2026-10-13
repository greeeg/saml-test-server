// Ported from mcguinness/node-samlp (MIT, see ./LICENSE): lib/logout.js.
// The Express middleware was rewritten as a framework-agnostic async function that
// returns what the HTTP layer must do (POST form, redirect, or "done").
import qs from 'node:querystring';
import { deflateRaw, inflateRaw } from 'node:zlib';
import { promisify } from 'node:util';
import type { DigestAlgorithm, SignatureAlgorithm } from '../saml/sign.js';
import { SamlpError, type PostForm } from './auth.js';
import { BINDINGS, ELEMENTS, STATUS, type ElementType } from './constants.js';
import { SessionParticipants } from './session-participants.js';
import * as signers from './signers.js';
import * as templates from './templates.js';
import { trimXml } from './trim-xml.js';
import {
  appendQueryString,
  generateInstant,
  generateUniqueID,
  parseSamlRequest,
  validateSignature,
  type SamlHttpInput,
} from './utils.js';
import { parseXml, selectNodes, type XmlDocument } from './xml.js';

const deflateRawAsync = promisify(deflateRaw);
const inflateRawAsync = promisify(inflateRaw);

export type LogoutState = Record<string, any>;

/** Persists the state of an in-flight logout transaction (keyed by an opaque handle). */
export interface LogoutStore {
  /** Stores the state and returns its handle (used as `RelayState`). */
  save(state: LogoutState): string;
  load(handle: string | undefined, options?: { destroy?: boolean }): LogoutState | undefined;
  update(handle: string, state: LogoutState): void;
}

export interface LogoutOptions {
  issuer: string;
  cert: string | Buffer;
  key: string | Buffer;
  digestAlgorithm?: DigestAlgorithm;
  signatureAlgorithm?: SignatureAlgorithm;
  sessionParticipants: SessionParticipants;
  store: LogoutStore;
  /** Called once all participants are logged out. */
  clearIdPSession?: () => void | Promise<void>;
  /** Fallback SP logout URL. */
  destination?: string;
  protocolBinding?: string;
  /** Deflate + detached signature (HTTP-Redirect binding). */
  deflate?: boolean;
  samlStatusMessage?: string;
}

export type LogoutResult =
  | ({ type: 'post' } & PostForm)
  | { type: 'redirect'; url: string }
  /** IdP-initiated flow finished: reply with an empty 200. */
  | { type: 'done' };

interface SendContext {
  destination?: string;
  relayState?: string;
  reference?: string;
}

interface LogoutRequestData {
  id?: string;
  issuer?: string;
  sessionIndices?: string[];
  nameId?: string;
  nameIdFormat?: string;
  destination?: string;
  signature?: string;
}

/** Parses an SP-initiated `LogoutRequest`. */
async function parseIncomingLogoutRequest(
  input: SamlHttpInput,
  samlRequest: string,
  options: Parameters<typeof parseSamlRequest>[3],
): Promise<LogoutRequestData> {
  const type: ElementType = 'LOGOUT_REQUEST';
  const dom = (await parseSamlRequest(input, samlRequest, type, options)) as XmlDocument;
  const descriptor = ELEMENTS[type];
  const data: LogoutRequestData = {};

  const issuer = selectNodes(descriptor.ISSUER_PATH as string, dom);
  if (issuer.length > 0) data.issuer = issuer[0].textContent ?? undefined;

  const sessionIndexNodes = selectNodes("//*[local-name(.)='SessionIndex']/text()", dom);
  if (sessionIndexNodes.length > 0) data.sessionIndices = sessionIndexNodes.map((n) => n.textContent ?? '');

  const nameId = selectNodes("//*[local-name(.)='NameID']", dom);
  if (nameId.length > 0) {
    data.nameId = nameId[0].textContent ?? undefined;
    data.nameIdFormat = nameId[0].getAttribute('Format') ?? undefined;
  }

  const root = dom.documentElement!;
  const destination = root.getAttribute('Destination');
  if (destination) data.destination = destination;
  const id = root.getAttribute('ID');
  if (id) data.id = id;

  const signature = selectNodes(descriptor.SIGNATURE_VALIDATION_PATH as string, dom);
  if (signature.length > 0) data.signature = signature[0].textContent ?? undefined;

  return data;
}

async function prepareAndSendToken(
  elementType: 'LOGOUT_REQUEST' | 'LOGOUT_RESPONSE',
  token: string,
  options: LogoutOptions,
  ctx: SendContext,
): Promise<LogoutResult> {
  const type = ELEMENTS[elementType].PROP;
  const params: Record<string, string> = { [type]: '', RelayState: ctx.relayState || '' };

  const send = (): LogoutResult => {
    if (options.protocolBinding !== BINDINGS.HTTP_REDIRECT) {
      // HTTP-POST
      return {
        type: 'post',
        url: ctx.destination as string,
        field: type,
        value: params[type],
        relayState: params.RelayState ?? '',
      };
    }
    // HTTP-Redirect
    try {
      return { type: 'redirect', url: appendQueryString(ctx.destination as string, params) };
    } catch {
      throw new Error('The logout URL may be missing or misconfigured');
    }
  };

  // canonical request
  const canonical = trimXml(token);
  const signingOptions: signers.SigningOptions = {
    key: options.key,
    cert: options.cert,
    signatureAlgorithm: options.signatureAlgorithm,
    digestAlgorithm: options.digestAlgorithm,
    reference: ctx.reference,
  };

  if (options.protocolBinding !== BINDINGS.HTTP_REDIRECT || !options.deflate) {
    // HTTP-POST or HTTP-Redirect without deflate encoding
    params[type] = Buffer.from(signers.signXml(signingOptions, canonical)).toString('base64');
    return send();
  }

  // Default: HTTP-Redirect with deflate encoding
  // (http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - section 3.4.4.1)
  params[type] = (await deflateRawAsync(Buffer.from(canonical))).toString('base64');

  // The signature covers SAMLRequest|SAMLResponse, RelayState (if present) and SigAlg
  if (params.RelayState === '') delete params.RelayState;

  params.SigAlg = signers.getSigAlg(options);
  params.Signature = signers.sign(options, qs.stringify(params));
  return send();
}

async function prepareAndSendLogoutRequest(
  options: LogoutOptions,
  transactionId: string,
): Promise<LogoutResult> {
  const { sessionParticipants } = options;

  // Finished if there are no more session participants - finish logout
  if (!sessionParticipants.hasElements()) {
    return finalize(options, transactionId);
  }

  const participant = sessionParticipants.getFirst()!;

  // Store the sessionIndex in session so when the logout response comes back we can validate it
  const relayState = options.store.save({
    transactionId,
    sessionIndex: participant.sessionIndex,
    issuer: participant.serviceProviderId,
    nameId: participant.nameId,
  });

  const logoutRequest = templates.logoutRequest({
    ID: generateUniqueID(),
    IssueInstant: generateInstant(),
    Issuer: options.issuer, // IdP identifier
    NameID: { value: participant.nameId, Format: participant.nameIdFormat },
    SessionIndex: participant.sessionIndex,
    Destination: participant.serviceProviderLogoutURL,
  });

  return prepareAndSendToken('LOGOUT_REQUEST', logoutRequest, options, {
    destination: participant.serviceProviderLogoutURL,
    relayState,
  });
}

async function finalize(options: LogoutOptions, transactionId: string): Promise<LogoutResult> {
  const transaction = options.store.load(transactionId, { destroy: true });
  let isPartialLogout = !!transaction && transaction.global_status === 'failed';

  try {
    await options.clearIdPSession?.();
  } catch {
    // If there was an issue cleaning the session, reply with partial logout
    isPartialLogout = true;
  }

  // No data - It was an IdP initiated flow
  if (!transaction || !transaction.parsedRequest) {
    return { type: 'done' };
  }

  const data = transaction.parsedRequest;
  const destination: string | undefined = data.serviceProviderLogoutURL || options.destination;

  // IdP is the Issuer for this LogoutResponse
  const logoutResponse = templates.logoutResponse({
    id: '_' + generateUniqueID(),
    instant: generateInstant(),
    inResponseTo: data.id,
    destination,
    issuer: options.issuer,
    samlStatusCode: isPartialLogout ? STATUS.PARTIAL_LOGOUT : STATUS.SUCCESS,
    samlStatusMessage: options.samlStatusMessage,
  });

  return prepareAndSendToken('LOGOUT_RESPONSE', logoutResponse, options, {
    destination,
    // We stored the relay state of the initial request
    relayState: transaction.relayState,
    reference: ELEMENTS.LOGOUT_RESPONSE.SIGNATURE_LOCATION_PATH,
  });
}

interface ParsedLogoutResponse {
  status?: string;
  subCode?: string;
  message?: string;
  detail?: string;
  issuer?: string;
}

async function validateSamlResponse(
  input: SamlHttpInput,
  options: LogoutOptions,
  cert: string | Buffer | undefined,
): Promise<ParsedLogoutResponse> {
  const samlResponse = (input.query.SAMLResponse || input.body.SAMLResponse) as string;
  const raw = Buffer.from(samlResponse, 'base64');
  const xmlString =
    input.body.SAMLResponse || !options.deflate
      ? raw.toString() // HTTP-POST or HTTP-Redirect without deflate encoding
      : (await inflateRawAsync(raw)).toString(); // Default: HTTP-Redirect with deflate encoding

  const xml = parseXml(xmlString);
  const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
  const parsed: ParsedLogoutResponse = {};

  const statusCodes = xml.getElementsByTagNameNS(PROTOCOL_NS, 'StatusCode');
  if (statusCodes[0]) {
    parsed.status = statusCodes[0].getAttribute('Value') ?? undefined;
    if (statusCodes[1]) parsed.subCode = statusCodes[1].getAttribute('Value') ?? undefined;
  }
  const message = xml.getElementsByTagNameNS(PROTOCOL_NS, 'StatusMessage')[0];
  if (message) parsed.message = message.textContent ?? undefined;
  const detail = xml.getElementsByTagNameNS(PROTOCOL_NS, 'StatusDetail')[0];
  if (detail) parsed.detail = detail.textContent ?? undefined;
  const issuer = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
  if (issuer) parsed.issuer = issuer.textContent ?? undefined;

  // If there's no certificate to check the signature, let it pass
  if (cert) {
    validateSignature(input, 'LOGOUT_RESPONSE', xml, xmlString, {
      signingCert: cert,
      deflate: options.deflate,
    });
  }
  return parsed;
}

/**
 * Handles the three legs of the SAML Single Logout profile:
 * - SP-initiated: an incoming `SAMLRequest` (LogoutRequest)
 * - in-flight: an incoming `SAMLResponse` (LogoutResponse) from a participant
 * - IdP-initiated: neither, starts the logout of all session participants
 */
export async function logout(input: SamlHttpInput, options: LogoutOptions): Promise<LogoutResult> {
  const relayStateParam = input.query.RelayState || input.body.RelayState;

  // SP Initiated flow.
  const samlRequest = input.query.SAMLRequest || input.body.SAMLRequest;
  if (samlRequest) {
    const requestData = await parseIncomingLogoutRequest(input, samlRequest, {
      getCredentials: (issuer, sessionIndices, nameId) => {
        const session = options.sessionParticipants.get(issuer, sessionIndices, nameId);
        if (!session) throw new Error('Invalid Session Participant');
        if (!session.cert) return undefined;
        return { cert: session.cert, thumbprints: session.thumbprint };
      },
    });

    if (!requestData.issuer) {
      throw new SamlpError('SAML Request with no issuer. Issuer is a mandatory element.', 400);
    }

    const session = options.sessionParticipants.get(
      requestData.issuer,
      requestData.sessionIndices,
      requestData.nameId,
    );
    if (!session && !options.destination) {
      throw new SamlpError('Invalid Session Participant', 400);
    }

    // We should store who requested the logout, so we can reply back with LogoutResponse
    const transactionId = options.store.save({
      parsedRequest: {
        id: requestData.id,
        serviceProviderLogoutURL: session?.serviceProviderLogoutURL || options.destination,
      },
      relayState: relayStateParam,
    });

    // We remove the session from the LogoutRequest originator. This session is already saved
    // in the store: we must not send a LogoutRequest to it, only a LogoutResponse once there
    // are no other session participants left.
    options.sessionParticipants.remove(session?.serviceProviderId, session?.sessionIndex, session?.nameId);

    return prepareAndSendLogoutRequest(options, transactionId);
  }

  // Logout flow in progress, incoming SAMLResponse from SP (SP or IdP initiated).
  if (input.query.SAMLResponse || input.body.SAMLResponse) {
    // Verify that the state sent to the SP matches the one returned
    const state = options.store.load(relayStateParam, { destroy: true });
    if (!state) throw new SamlpError('Invalid RelayState', 400);

    const participant = options.sessionParticipants.get(state.issuer, [state.sessionIndex], state.nameId);
    if (!participant) throw new SamlpError('Invalid Session Participant', 400);

    const logoutResponse = await validateSamlResponse(input, options, participant.cert);
    const transactionId: string = state.transactionId;

    if (logoutResponse.status !== STATUS.SUCCESS) {
      // Mark global status as partial logout if a logout does not succeed
      const globalState = options.store.load(transactionId) ?? {};
      globalState.global_status = 'failed';
      options.store.update(transactionId, globalState);
    }

    // The participant replied: remove it and continue with the next one (if any)
    options.sessionParticipants.remove(state.issuer, state.sessionIndex, state.nameId);
    return prepareAndSendLogoutRequest(options, transactionId);
  }

  // IdP initiated - Start flow. When complete the result is "done" (HTTP 200).
  const transactionId = options.store.save({});
  return prepareAndSendLogoutRequest(options, transactionId);
}

export interface LogoutErrorOptions {
  issuer: string;
  cert: string | Buffer;
  key: string | Buffer;
  destination?: string;
  inResponseTo?: string;
  relayState?: string;
  error?: { code?: string; description?: string };
  digestAlgorithm?: DigestAlgorithm;
  signatureAlgorithm?: SignatureAlgorithm;
  protocolBinding?: string;
  deflate?: boolean;
}

/** Builds a signed `LogoutResponse` carrying an error status. */
export async function createLogoutError(
  input: SamlHttpInput,
  options: LogoutErrorOptions,
): Promise<LogoutResult> {
  if (!options.destination) throw new Error('Destination not specified');
  const error = options.error ?? {};

  const logoutResponse = templates.logoutResponse({
    id: '_' + generateUniqueID(),
    instant: generateInstant(),
    inResponseTo: options.inResponseTo,
    destination: options.destination,
    issuer: options.issuer,
    samlStatusCode: error.code || STATUS.RESPONDER,
    samlStatusMessage: error.description,
  });

  return prepareAndSendToken(
    'LOGOUT_RESPONSE',
    logoutResponse,
    {
      ...options,
      sessionParticipants: new SessionParticipants(),
      store: undefined as unknown as LogoutStore,
    },
    {
      destination: options.destination,
      relayState: options.relayState || input.query.RelayState || input.body.RelayState,
      reference: ELEMENTS.LOGOUT_RESPONSE.SIGNATURE_LOCATION_PATH,
    },
  );
}
