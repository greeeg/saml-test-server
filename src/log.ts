import pc from "picocolors";
import xmlFormat from "xml-formatter";
import type { ResolvedOptions } from "./options.js";

export const UNDEFINED_VALUE = "None";

const CERT_OPTIONS = [
  "cert",
  "key",
  "encryptionCert",
  "encryptionPublicKey",
  "httpsPrivateKey",
  "httpsCert",
];

export const LOG_LEVELS = ["silent", "error", "info"] as const;

/**
 * - `silent`: no output at all
 * - `error`: only unexpected errors (HTTP 5xx), on stderr
 * - `info`: banners, requests and SAML messages (default)
 */
export type LogLevel = (typeof LOG_LEVELS)[number];

export function isLogLevel(value: unknown): value is LogLevel {
  return (LOG_LEVELS as readonly unknown[]).includes(value);
}

export interface Logger {
  /** Informational output (shown at level `info`). */
  log(message?: string, ...rest: unknown[]): void;
  /** Errors (shown at levels `error` and `info`). */
  error(message?: string, ...rest: unknown[]): void;
}

export function createLogger(level: LogLevel = "info"): Logger {
  const noop = () => {};
  return {
    log: level === "info" ? (...args) => console.log(...args) : noop,
    error: level === "silent" ? noop : (...args) => console.error(...args),
  };
}

/** Indents every line of `text` by `indent` spaces. */
function indentLines(text: string, indent: number): string {
  const pad = " ".repeat(indent);
  return text.replace(/(^|\n)/g, `$1${pad}`);
}

/** Pretty prints XML with syntax coloring (used to log SAML responses). */
export function prettyPrintXml(xml: string, indent = 0): string {
  // This works well, because we format the xml before applying the replacements
  const pretty = xmlFormat(xml, { indentation: "  ", collapseContent: true })
    // Matches `<{prefix}:{name} .*?>`
    .replace(
      /<(\/)?((?:[\w]+)(?::))?([\w]+)(.*?)>/g,
      (_m, slash = "", prefix = "", name, rest) =>
        `<${pc.green(`${slash}${prefix}${pc.bold(name)}`)}${rest}>`,
    )
    // Matches ` {attribute}="{value}"`
    .replace(
      / ([\w:]+)="(.+?)"/g,
      (_m, attr, value) => ` ${pc.white(attr)}=${pc.cyan(`"${value}"`)}`,
    );
  return indent ? indentLines(pretty, indent) : pretty;
}

/** Short, single line representation of an option value for logs. */
export function formatOptionValue(key: string, value: unknown): string {
  if (typeof value === "string" && !CERT_OPTIONS.includes(key)) {
    return value;
  }
  if (CERT_OPTIONS.includes(key) && value) {
    return (
      value
        .toString()
        .replace(/-----.+?-----|\n/g, "")
        .substring(0, 80) + pc.white("…")
    );
  }
  if (!value && value !== false) {
    return UNDEFINED_VALUE;
  }
  if (typeof value === "function") {
    return `${value}`.split("\n")[0].slice(0, -2);
  }
  return JSON.stringify(value);
}

export function describeRecord(
  record: Record<string, unknown>,
  indent: number,
  format = formatOptionValue,
): string {
  return Object.entries(record)
    .map(([key, value]) => `${" ".repeat(indent)}${key}: ${pc.cyan(format(key, value))}`)
    .join("\n");
}

/** Startup banner describing the effective configuration. */
export function configBanner(options: ResolvedOptions): string {
  const v = (value: unknown) =>
    pc.cyan(value === false ? "false" : String(value || UNDEFINED_VALUE));
  return [
    `Listener Port:`,
    `  ${pc.cyan(`${options.host}:${options.port}`)}`,
    `HTTPS Enabled:`,
    `  ${pc.cyan(String(options.https))}`,
    ``,
    pc.bold(`[${pc.yellow("Identity Provider")}]`),
    ``,
    `Issuer URI:`,
    `  ${v(options.issuer)}`,
    `Sign Response Message:`,
    `  ${v(options.signResponse)}`,
    `Encrypt Assertion:`,
    `  ${v(options.encryptAssertion)}`,
    `Authentication Context Class Reference:`,
    `  ${v(options.authnContextClassRef)}`,
    `Authentication Context Declaration:`,
    `  ${v(options.authnContextDecl)}`,
    `Default RelayState:`,
    `  ${v(options.relayState)}`,
    ``,
    pc.bold(`[${pc.yellow("Service Provider")}]`),
    ``,
    `Issuer URI:`,
    `  ${v(options.serviceProviderId)}`,
    `Audience URI:`,
    `  ${v(options.audience)}`,
    `ACS URL:`,
    `  ${v(options.acsUrl)}`,
    `SLO URL:`,
    `  ${v(options.sloUrl)}`,
    `Trust ACS URL in Request:`,
    `  ${pc.cyan(String(!options.disableRequestAcsUrl))}`,
    ``,
  ].join("\n");
}

/** Banner printed once the server listens. */
export function listeningBanner(baseUrl: string, sloEnabled: boolean): string {
  const lines = [
    `IdP Metadata URL:`,
    `  ${pc.cyan(`${baseUrl}/metadata`)}`,
    ``,
    `SSO Bindings:`,
    `  urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`,
    `    => ${pc.cyan(`${baseUrl}/saml/sso`)}`,
    `  urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`,
    `    => ${pc.cyan(`${baseUrl}/saml/sso`)}`,
  ];
  if (sloEnabled) {
    lines.push(
      ``,
      `SLO Bindings:`,
      `  urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`,
      `    => ${pc.cyan(`${baseUrl}/saml/slo`)}`,
      `  urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`,
      `    => ${pc.cyan(`${baseUrl}/saml/slo`)}`,
    );
  }
  lines.push(``, `IdP server ready at`, `  ${pc.cyan(baseUrl)}`);
  return lines.join("\n");
}
