import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createDefaultConfig, type IdpConfig } from "./default-config.js";
import { isLogLevel, LOG_LEVELS, type LogLevel } from "./log.js";

/** Root of the package (works from `src/` and from the built `dist/`). */
export const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));

const DEFAULT_CERT_PATH = resolve(PACKAGE_ROOT, "assets/idp-public-cert.pem");
const DEFAULT_KEY_PATH = resolve(PACKAGE_ROOT, "assets/idp-private-key.pem");
/** Special `configFile` value that selects the built-in default user + metadata. */
export const DEFAULT_CONFIG_FILE = "saml-idp/config.js";

export const KEY_CERT_HELP_TEXT = `To generate a key/cert pair for the IdP, run the following command:

  openssl req -x509 -new -newkey rsa:2048 -nodes \\
    -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' \\
    -keyout idp-private-key.pem \\
    -out idp-public-cert.pem -days 7300`;

const CRYPT_TYPES = {
  certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
  // PKCS#1 (RSA PRIVATE KEY) and PKCS#8 (PRIVATE KEY)
  "private key": /-----BEGIN (?:RSA )?PRIVATE KEY-----[^-]*-----END (?:RSA )?PRIVATE KEY-----/,
  "public key": /-----BEGIN (?:RSA )?PUBLIC KEY-----[^-]*-----END (?:RSA )?PUBLIC KEY-----/,
} as const;

type CryptType = keyof typeof CRYPT_TYPES;

/** Thrown when the options are invalid. The message is meant to be shown to the user. */
export class OptionsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OptionsError";
  }
}

/** A PEM string / Buffer, or the path of a PEM file. */
export type PemOrPath = string | Buffer;

/** Options of the IdP. They match the CLI flags of the original `saml-idp`. */
export interface IdpOptions {
  /** IdP web server listener host. Default: `localhost`. */
  host?: string;
  /** IdP web server listener port (`0` picks a free port). Default: `7000`. */
  port?: number;
  /** IdP signature public key certificate (PEM or path). Defaults to the bundled test certificate. */
  cert?: PemOrPath;
  /** IdP signature private key (PEM or path). Defaults to the bundled test key. */
  key?: PemOrPath;
  /** IdP issuer URI. Default: `urn:example:idp`. */
  issuer?: string;
  /** SP Assertion Consumer Service URL. */
  acsUrl: string;
  /** SP single logout URL. Enables SLO when set. */
  sloUrl?: string;
  /** SP audience URI. */
  audience: string;
  /** SP issuer / entity URI. Defaults to the audience. */
  serviceProviderId?: string;
  /** Default SAML RelayState. */
  relayState?: string;
  /** Ignore the ACS URL of the AuthnRequest. */
  disableRequestAcsUrl?: boolean;
  /** Encrypt the assertion with the SP public key. */
  encryptAssertion?: boolean;
  /** SP certificate (PEM or path) used for assertion encryption. */
  encryptionCert?: PemOrPath;
  /** SP RSA public key (PEM or path). Derived from `encryptionCert` when omitted. */
  encryptionPublicKey?: PemOrPath;
  /** Web server TLS private key (PEM or path). */
  httpsPrivateKey?: PemOrPath;
  /** Web server TLS certificate (PEM or path). */
  httpsCert?: PemOrPath;
  /** Enable the HTTPS listener (requires `httpsPrivateKey` and `httpsCert`). */
  https?: boolean;
  /** Sign the SAML Response (the assertion is always signed). Default: `true`. */
  signResponse?: boolean;
  /**
   * Path to a module (`.js`, `.mjs`, `.json`) that exports `{ user, metadata }`.
   * Ignored when `config` is given.
   */
  configFile?: string;
  /** Inline user profile and attribute metadata (overrides `configFile`). */
  config?: Partial<IdpConfig>;
  /** Create a new session for every authn request. Default: `false`. */
  rollSession?: boolean;
  /** Authentication Context Class Reference. */
  authnContextClassRef?: string;
  /** Authentication Context Declaration (XML or path to an XML file). */
  authnContextDecl?: string;
  /**
   * Verbosity of the logs: `silent` (nothing), `error` (unexpected errors only) or `info`.
   * Defaults to the `SAML_IDP_LOG_LEVEL` environment variable, then to `info`.
   */
  logLevel?: LogLevel;
  /** @deprecated Use `logLevel: 'silent'`. */
  silent?: boolean;
}

export interface ResolvedOptions {
  host: string;
  port: number;
  cert: string;
  key: string;
  issuer: string;
  acsUrl: string;
  sloUrl?: string;
  audience: string;
  serviceProviderId: string;
  relayState?: string;
  disableRequestAcsUrl: boolean;
  encryptAssertion: boolean;
  encryptionCert?: string;
  encryptionPublicKey?: string;
  httpsPrivateKey?: string;
  httpsCert?: string;
  https: boolean;
  signResponse: boolean;
  rollSession: boolean;
  authnContextClassRef?: string;
  authnContextDecl?: string;
  logLevel: LogLevel;
  config: IdpConfig;
}

export function matchesCertType(value: string, type: CryptType): boolean {
  return CRYPT_TYPES[type].test(value);
}

/** Resolves a file path option, the same way the original `saml-idp` did. */
export function resolveFilePath(filePath: string): string | undefined {
  if (filePath.startsWith("saml-idp/")) {
    // Allows file path options to files included in this package
    const resolved = resolve(PACKAGE_ROOT, filePath.replace(/^saml-idp\//, ""));
    return existsSync(resolved) ? resolved : undefined;
  }
  if (isAbsolute(filePath) && existsSync(filePath)) return filePath;
  if (filePath.startsWith("~/")) {
    const expanded = resolve(process.env.HOME ?? homedir(), filePath.slice(2));
    return existsSync(expanded) ? expanded : undefined;
  }
  return [process.cwd(), PACKAGE_ROOT]
    .map((base) => resolve(base, filePath))
    .find((candidate) => existsSync(candidate));
}

/** Accepts PEM content or a file path and returns the PEM content. */
export function coerceCertFile(
  value: PemOrPath,
  type: CryptType,
  description: string,
  helpText?: string,
): string {
  const asString = value.toString();
  if (matchesCertType(asString, type)) {
    return asString;
  }
  const filePath = resolveFilePath(asString);
  if (filePath) {
    const content = readFileSync(filePath, "utf8");
    if (matchesCertType(content, type)) return content;
    throw new OptionsError(
      `Invalid ${description}: "${filePath}" does not contain a valid ${type}`,
    );
  }
  throw new OptionsError(
    `Invalid / missing ${description} - not a valid crypt key/cert or file path` +
      (helpText ? "\n" + helpText : ""),
  );
}

async function loadConfigFile(configFile: string): Promise<Partial<IdpConfig>> {
  if (configFile === DEFAULT_CONFIG_FILE) return {};

  const filePath = resolveFilePath(configFile);
  if (!filePath) {
    throw new OptionsError(`SAML attribute config file path "${configFile}" is not a valid path.`);
  }
  try {
    if (filePath.endsWith(".json")) {
      return JSON.parse(readFileSync(filePath, "utf8"));
    }
    const mod = await import(/* @vite-ignore */ pathToFileURL(filePath).href);
    return (mod.default?.user || mod.default?.metadata ? mod.default : mod) as Partial<IdpConfig>;
  } catch (error) {
    throw new OptionsError(
      `Encountered an exception while loading SAML attribute config file "${filePath}".\n${error}`,
    );
  }
}

function coerceAuthnContextDecl(value: string): string {
  if (value.trimStart().startsWith("<")) return value;
  const filePath = resolveFilePath(value);
  if (!filePath) {
    throw new OptionsError(`Authentication Context Declaration file "${value}" was not found.`);
  }
  return readFileSync(filePath, "utf8");
}

/** Validates the options, applies defaults and reads certificates / config files. */
export async function resolveOptions(options: IdpOptions): Promise<ResolvedOptions> {
  if (!options.acsUrl) throw new OptionsError("Missing required option: acsUrl");
  if (!options.audience) throw new OptionsError("Missing required option: audience");

  const encryptAssertion = options.encryptAssertion ?? false;
  if (encryptAssertion && options.encryptionCert === undefined) {
    throw new OptionsError("encryptionCert argument is required for assertion encryption");
  }

  const logLevel =
    options.logLevel ?? (options.silent ? "silent" : (process.env.SAML_IDP_LOG_LEVEL ?? "info"));
  if (!isLogLevel(logLevel)) {
    throw new OptionsError(
      `Invalid logLevel "${logLevel}", expected one of: ${LOG_LEVELS.join(", ")}`,
    );
  }

  const https = options.https ?? false;
  if (https && (options.httpsPrivateKey === undefined || options.httpsCert === undefined)) {
    throw new OptionsError("httpsPrivateKey and httpsCert arguments are required to enable HTTPS");
  }

  const fileConfig = options.config
    ? {}
    : await loadConfigFile(options.configFile ?? DEFAULT_CONFIG_FILE);
  const inlineConfig = options.config ?? fileConfig;
  const defaults = createDefaultConfig();
  const config: IdpConfig = {
    // the user is merged with the defaults so that a partial profile still has a NameID
    user: { ...defaults.user, ...inlineConfig.user },
    metadata: inlineConfig.metadata ?? defaults.metadata,
  };

  return {
    host: options.host ?? "localhost",
    port: options.port ?? 7000,
    cert: coerceCertFile(
      options.cert ?? DEFAULT_CERT_PATH,
      "certificate",
      "IdP Signature PublicKey Certificate",
      KEY_CERT_HELP_TEXT,
    ),
    key: coerceCertFile(
      options.key ?? DEFAULT_KEY_PATH,
      "private key",
      "IdP Signature PrivateKey Certificate",
      KEY_CERT_HELP_TEXT,
    ),
    issuer: options.issuer ?? "urn:example:idp",
    acsUrl: options.acsUrl,
    sloUrl: options.sloUrl,
    audience: options.audience,
    serviceProviderId: options.serviceProviderId || options.audience,
    relayState: options.relayState,
    disableRequestAcsUrl: options.disableRequestAcsUrl ?? false,
    encryptAssertion,
    encryptionCert:
      options.encryptionCert !== undefined
        ? coerceCertFile(options.encryptionCert, "certificate", "Encryption cert")
        : undefined,
    encryptionPublicKey:
      options.encryptionPublicKey !== undefined
        ? coerceCertFile(options.encryptionPublicKey, "public key", "Encryption public key")
        : undefined,
    httpsPrivateKey:
      options.httpsPrivateKey !== undefined
        ? coerceCertFile(options.httpsPrivateKey, "private key", "Web Server TLS/SSL Private Key")
        : undefined,
    httpsCert:
      options.httpsCert !== undefined
        ? coerceCertFile(options.httpsCert, "certificate", "Web Server TLS/SSL Certificate")
        : undefined,
    https,
    signResponse: options.signResponse ?? true,
    rollSession: options.rollSession ?? false,
    authnContextClassRef:
      options.authnContextClassRef ??
      "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    authnContextDecl: options.authnContextDecl
      ? coerceAuthnContextDecl(options.authnContextDecl)
      : undefined,
    logLevel,
    config,
  };
}
