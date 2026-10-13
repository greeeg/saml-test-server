// Vendored subset (SAML 2.0 assertions only) of mcguinness/node-saml, MIT licensed.
export { createAssertion, buildAssertionDocument, SAML_ASSERTION_NS } from './saml20.js';
export type { Saml20Options, Attributes, AttributeValue } from './saml20.js';
export { signXml, SIGNATURE_ALGORITHMS, DIGEST_ALGORITHMS } from './sign.js';
export type { SignatureAlgorithm, DigestAlgorithm } from './sign.js';
export { encryptXml } from './encrypt.js';
export { escapeXml, pemToCert, removeWhitespace, fixPemFormatting } from './utils.js';
export type { PemInput } from './utils.js';
