// Ported from mcguinness/node-samlp (MIT, see ./LICENSE).

export const BINDINGS = {
  HTTP_POST: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
} as const;

export const STATUS = {
  SUCCESS: 'urn:oasis:names:tc:SAML:2.0:status:Success',
  PARTIAL_LOGOUT: 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
  RESPONDER: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
} as const;

export type ElementType = 'LOGOUT_REQUEST' | 'LOGOUT_RESPONSE' | 'RESPONSE' | 'AUTHN_REQUEST';

export interface ElementDescriptor {
  PROP: 'SAMLRequest' | 'SAMLResponse';
  SIGNATURE_VALIDATION_PATH?: string;
  SIGNATURE_LOCATION_PATH?: string;
  ISSUER_PATH?: string;
  SESSION_INDEX_PATH?: string;
  NAME_ID?: string;
  AUTHN_CONTEXT_CLASS_REF_PATH?: string;
}

export const ELEMENTS: Record<ElementType, ElementDescriptor> = {
  LOGOUT_REQUEST: {
    PROP: 'SAMLRequest',
    SIGNATURE_VALIDATION_PATH:
      "//*[local-name(.)='LogoutRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    SIGNATURE_LOCATION_PATH:
      "//*[local-name(.)='LogoutRequest' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
    ISSUER_PATH:
      "//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()",
    SESSION_INDEX_PATH:
      "//*[local-name(.)='SessionIndex' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']/text()",
    NAME_ID:
      "//*[local-name(.)='NameID' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()",
  },
  LOGOUT_RESPONSE: {
    PROP: 'SAMLResponse',
    SIGNATURE_VALIDATION_PATH:
      "//*[local-name(.)='LogoutResponse']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    SIGNATURE_LOCATION_PATH:
      "//*[local-name(.)='LogoutResponse' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
  },
  RESPONSE: {
    PROP: 'SAMLResponse',
    SIGNATURE_LOCATION_PATH:
      "//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
  },
  AUTHN_REQUEST: {
    PROP: 'SAMLRequest',
    SIGNATURE_VALIDATION_PATH:
      "//*[local-name(.)='AuthnRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    AUTHN_CONTEXT_CLASS_REF_PATH: "//*[local-name(.)='AuthnContextClassRef']/text()",
  },
};

export const ALGORITHMS = {
  SIGNATURE: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  },
  DIGEST: {
    sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
    sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
  },
} as const;
