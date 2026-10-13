// Ported from mcguinness/node-saml (MIT, see ./LICENSE).
import { X509Certificate } from 'node:crypto';
import * as xmlenc from 'xml-encryption';
import { fixPemFormatting, removeWhitespace, type PemInput } from './utils.js';

export interface EncryptXmlOptions {
  /** Service Provider certificate (PEM). */
  encryptionCert: PemInput;
  /**
   * Service Provider RSA public key (PEM). Derived from `encryptionCert`
   * when omitted.
   */
  encryptionPublicKey?: PemInput;
  encryptionAlgorithm?: string;
  keyEncryptionAlgorithm?: string;
}

export const DEFAULT_ENCRYPTION_ALGORITHM = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
export const DEFAULT_KEY_ENCRYPTION_ALGORITHM = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

function derivePublicKey(cert: PemInput): string {
  return new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

function encryptOnce(xml: string, options: xmlenc.EncryptOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    xmlenc.encrypt(xml, options, (err, encrypted) => (err ? reject(err) : resolve(encrypted)));
  });
}

/** Encrypts an XML fragment for the given Service Provider (XML Encryption). */
export async function encryptXml(xml: string, options: EncryptXmlOptions): Promise<string> {
  const encryptOptions: xmlenc.EncryptOptions = {
    rsa_pub: options.encryptionPublicKey ?? derivePublicKey(options.encryptionCert),
    pem: options.encryptionCert,
    encryptionAlgorithm: options.encryptionAlgorithm ?? DEFAULT_ENCRYPTION_ALGORITHM,
    keyEncryptionAlgorithm: options.keyEncryptionAlgorithm ?? DEFAULT_KEY_ENCRYPTION_ALGORITHM,
  };

  try {
    return removeWhitespace(await encryptOnce(xml, encryptOptions));
  } catch {
    // Attempt to fix PEM formatting issues and retry
    const retried = await encryptOnce(xml, {
      ...encryptOptions,
      rsa_pub: fixPemFormatting(encryptOptions.rsa_pub),
      pem: fixPemFormatting(encryptOptions.pem),
    });
    return removeWhitespace(retried);
  }
}
