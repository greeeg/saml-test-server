import type { UserProfile } from "./default-config.js";
import type { ResolvedOptions } from "./options.js";
import type { ClaimMetadata } from "./vendor/samlp/index.js";
import type { DigestAlgorithm, SignatureAlgorithm } from "./vendor/saml/sign.js";

export const IDP_PATHS = {
  SSO: "/saml/sso",
  SLO: "/saml/slo",
  METADATA: "/metadata",
  SIGN_IN: "/signin",
  SIGN_OUT: "/signout",
  SETTINGS: "/settings",
} as const;

/** IdP settings. They can be changed at runtime from the settings page (or by tests). */
export interface IdpSettings {
  issuer: string;
  serviceProviderId: string;
  cert: string;
  key: string;
  audience: string;
  recipient: string;
  destination: string;
  acsUrl: string;
  sloUrl?: string;
  RelayState?: string;
  allowRequestAcsUrl: boolean;
  digestAlgorithm: DigestAlgorithm;
  signatureAlgorithm: SignatureAlgorithm;
  signResponse: boolean;
  encryptAssertion: boolean;
  encryptionCert?: string;
  encryptionPublicKey?: string;
  encryptionAlgorithm: string;
  keyEncryptionAlgorithm: string;
  lifetimeInSeconds: number;
  authnContextClassRef?: string;
  authnContextDecl?: string;
  includeAttributeNameFormat: boolean;
}

/** Mutable state shared by all the requests served by an IdP instance. */
export interface IdpState {
  settings: IdpSettings;
  /** The user that is "signed in". Updated by the sign-in form. */
  user: UserProfile;
  /** SAML attributes (claims) the IdP can issue. */
  metadata: ClaimMetadata[];
  /** Restores settings, user and metadata to the values the IdP was started with. */
  reset(): void;
}

function initialSettings(options: ResolvedOptions): IdpSettings {
  return {
    issuer: options.issuer,
    serviceProviderId: options.serviceProviderId,
    cert: options.cert,
    key: options.key,
    audience: options.audience,
    recipient: options.acsUrl,
    destination: options.acsUrl,
    acsUrl: options.acsUrl,
    sloUrl: options.sloUrl,
    RelayState: options.relayState,
    allowRequestAcsUrl: !options.disableRequestAcsUrl,
    digestAlgorithm: "sha256",
    signatureAlgorithm: "rsa-sha256",
    signResponse: options.signResponse,
    encryptAssertion: options.encryptAssertion,
    encryptionCert: options.encryptionCert,
    encryptionPublicKey: options.encryptionPublicKey,
    encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
    keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    lifetimeInSeconds: 3600,
    authnContextClassRef: options.authnContextClassRef,
    authnContextDecl: options.authnContextDecl,
    includeAttributeNameFormat: true,
  };
}

export function createState(options: ResolvedOptions): IdpState {
  const snapshot = () => ({
    settings: initialSettings(options),
    user: structuredClone(options.config.user),
    metadata: structuredClone(options.config.metadata),
  });

  const state: IdpState = {
    ...snapshot(),
    reset() {
      Object.assign(state, snapshot());
    },
  };
  return state;
}
