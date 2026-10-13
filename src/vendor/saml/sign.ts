// Ported from mcguinness/node-saml (MIT, see ./LICENSE).
import { SignedXml } from 'xml-crypto';
import { fixPemFormatting, pemToCert, removeWhitespace, type PemInput } from './utils.js';

export const SIGNATURE_ALGORITHMS = {
  'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
} as const;

export const DIGEST_ALGORITHMS = {
  sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
  sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
} as const;

export type SignatureAlgorithm = keyof typeof SIGNATURE_ALGORITHMS;
export type DigestAlgorithm = keyof typeof DIGEST_ALGORITHMS;

export const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
export const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

export interface SignXmlOptions {
  key: PemInput;
  cert: PemInput;
  signatureAlgorithm?: SignatureAlgorithm;
  digestAlgorithm?: DigestAlgorithm;
  /** Namespace prefix of the generated `<Signature>` element (default: none). */
  signatureNamespacePrefix?: string;
  /** XPath of the element that the signature is placed after. */
  xpathToNodeBeforeSignature: string;
  /** XPath of the element to sign. */
  xpathToSign: string;
  signatureIdAttribute?: string;
}

/** Signs an XML string with an enveloped, exclusive-c14n XML signature. */
export function signXml(xml: string, options: SignXmlOptions): string {
  if (!options.key) throw new Error('Expect a private key in pem format');
  if (!options.cert) throw new Error('Expect a public key cert in pem format');

  const cert = pemToCert(options.cert);
  if (!cert) throw new Error('Expect a public key cert in pem format');

  const sign = (key: PemInput) => {
    const sig = new SignedXml({
      privateKey: key,
      signatureAlgorithm: SIGNATURE_ALGORITHMS[options.signatureAlgorithm ?? 'rsa-sha256'],
      canonicalizationAlgorithm: EXC_C14N,
      idAttribute: options.signatureIdAttribute,
      getKeyInfoContent: ({ prefix } = {}) => {
        const p = prefix ? `${prefix}:` : '';
        return `<${p}X509Data><${p}X509Certificate>${cert}</${p}X509Certificate></${p}X509Data>`;
      },
    });
    sig.addReference({
      xpath: options.xpathToSign,
      transforms: [ENVELOPED_SIGNATURE, EXC_C14N],
      digestAlgorithm: DIGEST_ALGORITHMS[options.digestAlgorithm ?? 'sha256'],
    });
    sig.computeSignature(xml, {
      location: { reference: options.xpathToNodeBeforeSignature, action: 'after' },
      prefix: options.signatureNamespacePrefix ?? '',
    });
    return sig.getSignedXml();
  };

  try {
    return sign(options.key);
  } catch {
    return sign(fixPemFormatting(options.key));
  }
}

/** Serializes without signing (strategy used when `signAssertion` is false). */
export function unsigned(xml: string): string {
  return removeWhitespace(xml);
}
