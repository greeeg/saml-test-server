// Ported from mcguinness/node-saml (MIT, see ./LICENSE).
// Builds, signs and optionally encrypts a SAML 2.0 Assertion.
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { name as isXmlName } from 'xml-name-validator';
import { encryptXml, type EncryptXmlOptions } from './encrypt.js';
import { signXml, unsigned, type DigestAlgorithm, type SignatureAlgorithm } from './sign.js';
import { formatInstant, removeWhitespace, uid, type PemInput } from './utils.js';

/** DOM document type produced by `@xmldom/xmldom`. */
export type XmlDocument = ReturnType<DOMParser['parseFromString']>;

export const SAML_ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

const ASSERTION_TEMPLATE = `<saml:Assertion xmlns:saml="${SAML_ASSERTION_NS}" Version="2.0" ID="" IssueInstant="">
  <saml:Issuer></saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData />
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions />
  <saml:AuthnStatement AuthnInstant="">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>`;

export type AttributeValue = string | number | boolean | undefined;
export type Attributes = Record<string, AttributeValue | AttributeValue[]>;

export interface Saml20Options {
  uid?: string;
  issuer?: string;
  lifetimeInSeconds?: number;
  audiences?: string | string[];
  recipient?: string;
  inResponseTo?: string;
  attributes?: Attributes;
  includeAttributeNameFormat?: boolean;
  typedAttributes?: boolean;
  sessionIndex?: string;
  nameIdentifier?: string;
  nameIdentifierFormat?: string;
  nameIdentifierNameQualifier?: string;
  nameIdentifierSPNameQualifier?: string;
  nameIdentifierSPProvidedID?: string;
  authnContextClassRef?: string;
  /** Lets the caller mutate the assertion DOM before it is signed. */
  transformAssertion?: (doc: XmlDocument) => void;

  // XML Dsig
  signAssertion?: boolean;
  key?: PemInput;
  cert?: PemInput;
  signatureAlgorithm?: SignatureAlgorithm;
  digestAlgorithm?: DigestAlgorithm;
  signatureNamespacePrefix?: string;

  // XML Encryption
  encryptionCert?: PemInput;
  encryptionPublicKey?: PemInput;
  encryptionAlgorithm?: string;
  keyEncryptionAlgorithm?: string;
}

function getAttributeType(value: unknown): string {
  switch (typeof value) {
    case 'string':
      return 'xs:string';
    case 'boolean':
      return 'xs:boolean';
    case 'number':
      return 'xs:double';
    default:
      return 'xs:anyType';
  }
}

const URI_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$/;

function getNameFormat(name: string): string {
  if (URI_RE.test(name)) {
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
  }
  // Check that the name is a valid xs:Name -> https://www.w3.org/TR/xmlschema-2/#Name
  if (isXmlName(name)) {
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';
  }
  return 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
}

/** Builds the assertion DOM (unsigned, unencrypted). */
export function buildAssertionDocument(options: Saml20Options): XmlDocument {
  const doc = new DOMParser().parseFromString(ASSERTION_TEMPLATE, 'text/xml');
  const root = doc.documentElement!;

  root.setAttribute('ID', `_${options.uid || uid(32)}`);
  if (options.issuer) {
    root.getElementsByTagName('saml:Issuer')[0].textContent = options.issuer;
  }

  const now = new Date();
  root.setAttribute('IssueInstant', formatInstant(now));

  const conditions = root.getElementsByTagName('saml:Conditions')[0];
  const confirmationData = root.getElementsByTagName('saml:SubjectConfirmationData')[0];

  if (options.lifetimeInSeconds) {
    const notOnOrAfter = formatInstant(new Date(now.getTime() + options.lifetimeInSeconds * 1000));
    conditions.setAttribute('NotBefore', formatInstant(now));
    conditions.setAttribute('NotOnOrAfter', notOnOrAfter);
    confirmationData.setAttribute('NotOnOrAfter', notOnOrAfter);
  }

  if (options.audiences) {
    const audienceRestriction = doc.createElementNS(SAML_ASSERTION_NS, 'saml:AudienceRestriction');
    const audiences = Array.isArray(options.audiences) ? options.audiences : [options.audiences];
    for (const audience of audiences) {
      const element = doc.createElementNS(SAML_ASSERTION_NS, 'saml:Audience');
      element.textContent = audience;
      audienceRestriction.appendChild(element);
    }
    conditions.appendChild(audienceRestriction);
  }

  if (options.recipient) confirmationData.setAttribute('Recipient', options.recipient);
  if (options.inResponseTo) confirmationData.setAttribute('InResponseTo', options.inResponseTo);

  const typedAttributes = options.typedAttributes ?? true;
  const includeAttributeNameFormat = options.includeAttributeNameFormat ?? true;

  if (options.attributes) {
    const statement = doc.createElementNS(SAML_ASSERTION_NS, 'saml:AttributeStatement');
    statement.setAttribute('xmlns:xs', 'http://www.w3.org/2001/XMLSchema');
    statement.setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
    root.appendChild(statement);

    for (const [prop, raw] of Object.entries(options.attributes)) {
      if (typeof raw === 'undefined') continue;

      const attributeElement = doc.createElementNS(SAML_ASSERTION_NS, 'saml:Attribute');
      attributeElement.setAttribute('Name', prop);
      if (includeAttributeNameFormat) {
        attributeElement.setAttribute('NameFormat', getNameFormat(prop));
      }

      const values = (Array.isArray(raw) ? raw : [raw]).filter((v) => typeof v !== 'undefined');
      for (const value of values) {
        const valueElement = doc.createElementNS(SAML_ASSERTION_NS, 'saml:AttributeValue');
        valueElement.setAttribute('xsi:type', typedAttributes ? getAttributeType(value) : 'xs:anyType');
        valueElement.textContent = String(value);
        attributeElement.appendChild(valueElement);
      }

      // saml:Attribute must have at least one saml:AttributeValue
      if (values.length > 0) {
        statement.appendChild(attributeElement);
      }
    }
  }

  const authnStatement = root.getElementsByTagName('saml:AuthnStatement')[0];
  authnStatement.setAttribute('AuthnInstant', formatInstant(now));
  if (options.sessionIndex) {
    authnStatement.setAttribute('SessionIndex', options.sessionIndex);
  }

  const nameID = root.getElementsByTagNameNS(SAML_ASSERTION_NS, 'NameID')[0];
  if (options.nameIdentifier) nameID.textContent = options.nameIdentifier;
  if (options.nameIdentifierFormat) nameID.setAttribute('Format', options.nameIdentifierFormat);
  if (options.nameIdentifierNameQualifier) {
    nameID.setAttribute('NameQualifier', options.nameIdentifierNameQualifier);
  }
  if (options.nameIdentifierSPNameQualifier) {
    nameID.setAttribute('SPNameQualifier', options.nameIdentifierSPNameQualifier);
  }
  if (options.nameIdentifierSPProvidedID) {
    nameID.setAttribute('SPProvidedID', options.nameIdentifierSPProvidedID);
  }

  if (options.authnContextClassRef) {
    root.getElementsByTagName('saml:AuthnContextClassRef')[0].textContent =
      options.authnContextClassRef;
  }

  if (typeof options.transformAssertion === 'function') {
    options.transformAssertion(doc);
  }

  return doc;
}

/**
 * Creates a SAML 2.0 assertion.
 *
 * The assertion is signed unless `signAssertion === false` and is wrapped in a
 * `<saml:EncryptedAssertion>` when `encryptionCert` is provided.
 */
export async function createAssertion(options: Saml20Options): Promise<string> {
  const doc = buildAssertionDocument(options);
  const xml = removeWhitespace(new XMLSerializer().serializeToString(doc));

  const signed =
    options.signAssertion === false
      ? unsigned(xml)
      : signXml(xml, {
          key: options.key as PemInput,
          cert: options.cert as PemInput,
          signatureAlgorithm: options.signatureAlgorithm,
          digestAlgorithm: options.digestAlgorithm,
          signatureNamespacePrefix: options.signatureNamespacePrefix,
          xpathToNodeBeforeSignature: "//*[local-name(.)='Issuer']",
          xpathToSign: "//*[local-name(.)='Assertion']",
          signatureIdAttribute: 'ID',
        });

  if (!options.encryptionCert) {
    return signed;
  }

  const encryptOptions: EncryptXmlOptions = {
    encryptionCert: options.encryptionCert,
    encryptionPublicKey: options.encryptionPublicKey,
    encryptionAlgorithm: options.encryptionAlgorithm,
    keyEncryptionAlgorithm: options.keyEncryptionAlgorithm,
  };
  const encrypted = await encryptXml(signed, encryptOptions);
  return removeWhitespace(
    `<saml:EncryptedAssertion xmlns:saml="${SAML_ASSERTION_NS}">${encrypted}</saml:EncryptedAssertion>`,
  );
}
