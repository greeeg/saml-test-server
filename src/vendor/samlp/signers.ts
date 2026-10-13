// Ported from mcguinness/node-samlp (MIT, see ./LICENSE).
import { createSign, createVerify } from 'node:crypto';
import { SignedXml } from 'xml-crypto';
import { signXml as signXmlDsig } from '../saml/sign.js';
import { ALGORITHMS, ELEMENTS } from './constants.js';
import { calculateThumbprint } from './encoders.js';
import { selectNodes, type XmlDocument } from './xml.js';

type SignatureAlgorithmName = keyof typeof ALGORITHMS.SIGNATURE;
type DigestAlgorithmName = keyof typeof ALGORITHMS.DIGEST;

const DEFAULT_SIG_ALG: SignatureAlgorithmName = 'rsa-sha256';
const DEFAULT_DIGEST_ALG: DigestAlgorithmName = 'sha256';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

export interface SigningOptions {
  key: string | Buffer;
  cert: string | Buffer;
  signatureAlgorithm?: SignatureAlgorithmName;
  digestAlgorithm?: DigestAlgorithmName;
  /** XPath of the element to sign (default: `<LogoutRequest>`). */
  reference?: string;
}

export interface ValidationOptions {
  signingCert?: string | Buffer;
  thumbprints?: string | string[];
}

export function getSigAlg(options: { signatureAlgorithm?: SignatureAlgorithmName }): string {
  return ALGORITHMS.SIGNATURE[options.signatureAlgorithm ?? DEFAULT_SIG_ALG];
}

/** Adds an enveloped signature (placed after `<Issuer>`) to the root element. */
export function signXml(options: SigningOptions, xml: string): string {
  return signXmlDsig(xml, {
    key: options.key,
    cert: options.cert,
    signatureAlgorithm: options.signatureAlgorithm ?? DEFAULT_SIG_ALG,
    digestAlgorithm: options.digestAlgorithm ?? DEFAULT_DIGEST_ALG,
    xpathToSign: options.reference ?? (ELEMENTS.LOGOUT_REQUEST.SIGNATURE_LOCATION_PATH as string),
    xpathToNodeBeforeSignature: "//*[local-name(.)='Issuer']",
    signatureIdAttribute: 'ID',
  });
}

export function certToPEM(cert: string | Buffer): string {
  const value = cert.toString();
  if (/-----BEGIN CERTIFICATE-----/.test(value)) {
    return value;
  }
  const body = value.replace(/\s/g, '').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

/**
 * Validates the enveloped signature of the root element of `xml`.
 *
 * - If thumbprints are configured, the certificate embedded in `<KeyInfo>` is
 *   used and its thumbprint must match one of them.
 * - Otherwise the configured `signingCert` is the only trusted key.
 *
 * @returns a list of validation errors (empty when the signature is valid)
 */
export function validateXmlEmbeddedSignature(
  xml: XmlDocument,
  xmlString: string,
  options: ValidationOptions,
): string[] {
  const signature = selectNodes(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='" + DSIG_NS + "']",
    xml,
  )[0];
  if (!signature) {
    return ['Signature is missing'];
  }

  const thumbprints = options.thumbprints
    ? Array.isArray(options.thumbprints)
      ? options.thumbprints
      : [options.thumbprints]
    : [];

  let calculatedThumbprint = '';

  const sig = new SignedXml({
    publicCert: options.signingCert ? certToPEM(options.signingCert) : undefined,
    getCertFromKeyInfo: (keyInfo) => {
      if (thumbprints.length === 0 || !keyInfo) return null;
      const certNode = selectNodes(".//*[local-name(.)='X509Certificate']", keyInfo)[0];
      const base64 = certNode?.textContent?.replace(/\s/g, '');
      if (!base64) return null;
      calculatedThumbprint = calculateThumbprint(base64);
      return certToPEM(base64);
    },
  });

  if (!options.signingCert && thumbprints.length === 0) {
    return ['options.signingCert or options.thumbprints must be specified to validate the signature'];
  }

  try {
    sig.loadSignature(signature as unknown as Node);
    if (!sig.checkSignature(xmlString)) {
      return sig.getSignedReferences().length === 0 ? ['Invalid signature'] : ['Invalid signature reference'];
    }
  } catch (e) {
    return [e instanceof Error ? e.message : String(e)];
  }

  if (thumbprints.length > 0 && !options.signingCert) {
    const valid = thumbprints.some((t) => calculatedThumbprint === t.replace(/:/g, '').toUpperCase());
    if (!valid) {
      return [
        `Invalid thumbprint (configured: ${thumbprints.join(', ').toUpperCase()}. calculated: ${calculatedThumbprint})`,
      ];
    }
  }

  return [];
}

/** Computes a detached signature (HTTP-Redirect binding) over `content`. */
export function sign(
  options: { key: string | Buffer; signatureAlgorithm?: SignatureAlgorithmName },
  content: string,
): string {
  const signer = createSign((options.signatureAlgorithm ?? DEFAULT_SIG_ALG).toUpperCase());
  signer.update(content);
  return signer.sign(options.key, 'base64');
}

/** Verifies a detached signature. `signatureAlgorithm` is the `SigAlg` URI. */
export function isValidContentAndSignature(
  content: string,
  signature: string,
  options: { signingCert: string | Buffer; signatureAlgorithm: string },
): boolean {
  const verifier = createVerify(options.signatureAlgorithm.split('#')[1].toUpperCase());
  verifier.update(content);
  return verifier.verify(certToPEM(options.signingCert), signature, 'base64');
}
