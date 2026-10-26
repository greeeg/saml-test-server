declare module "xml-encryption" {
  export interface EncryptOptions {
    rsa_pub: string | Buffer;
    pem: string | Buffer;
    encryptionAlgorithm: string;
    keyEncryptionAlgorithm: string;
    keyEncryptionDigest?: string;
    disallowEncryptionWithInsecureAlgorithm?: boolean;
    warnInsecureAlgorithm?: boolean;
  }

  export interface DecryptOptions {
    key: string | Buffer;
    disallowDecryptionWithInsecureAlgorithm?: boolean;
    warnInsecureAlgorithm?: boolean;
  }

  export function encrypt(
    content: string,
    options: EncryptOptions,
    callback: (err: Error | null, result: string) => void,
  ): void;

  export function decrypt(
    xml: string | Document,
    options: DecryptOptions,
    callback: (err: Error | null, result: string) => void,
  ): void;
}
