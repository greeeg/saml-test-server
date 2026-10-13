import { Command, InvalidArgumentError, Option } from 'commander';
import { LOG_LEVELS } from './log.js';
import pc from 'picocolors';
import { OptionsError, type IdpOptions } from './options.js';

/** Long option aliases of the original `saml-idp` CLI. */
export const ALIASES: Record<string, string> = {
  '--iss': '--issuer',
  '--acs': '--acsUrl',
  '--slo': '--sloUrl',
  '--aud': '--audience',
  '--spId': '--serviceProviderId',
  '--rs': '--relayState',
  '--static': '--disableRequestAcsUrl',
  '--enc': '--encryptAssertion',
  '--encCert': '--encryptionCert',
  '--encKey': '--encryptionPublicKey',
  '--conf': '--configFile',
  '--acr': '--authnContextClassRef',
  '--acd': '--authnContextDecl',
};

const BOOLEAN_OPTIONS = [
  'disableRequestAcsUrl',
  'encryptAssertion',
  'https',
  'signResponse',
  'rollSession',
  'silent',
];

/**
 * Expands the aliases (`--acs` => `--acsUrl`) and the `--no-<flag>` form of boolean
 * flags (`--no-signResponse` => `--signResponse=false`).
 */
export function normalizeArgv(argv: string[]): string[] {
  return argv.map((arg) => {
    if (!arg.startsWith('--')) return arg;
    const [flag, ...rest] = arg.split('=');
    const value = rest.length ? `=${rest.join('=')}` : '';
    const canonical = ALIASES[flag] ?? flag;
    const negated = /^--no-(.+)$/.exec(canonical);
    if (negated && BOOLEAN_OPTIONS.includes(negated[1]) && !value) {
      return `--${negated[1]}=false`;
    }
    return canonical + value;
  });
}

function parseBoolean(value: string): boolean {
  if (['true', 'yes', '1'].includes(value.toLowerCase())) return true;
  if (['false', 'no', '0'].includes(value.toLowerCase())) return false;
  throw new InvalidArgumentError('Expected true or false.');
}

function booleanOption(flag: string, description: string, defaultValue = false): Option {
  return new Option(`${flag} [bool]`, description)
    .argParser(parseBoolean)
    .preset(true)
    .default(defaultValue);
}

export function buildProgram(onRun: (options: IdpOptions) => Promise<void>): Command {
  const program = new Command('saml-idp')
    .description(
      'Simple IdP for SAML 2.0 WebSSO & SLO Profile\n\n' +
        'Launches an IdP web server that mints SAML assertions or logout responses for a Service Provider (SP)',
    )
    .usage('--acsUrl {url} --audience {uri} [options]')
    .showHelpAfterError()
    .configureHelp({ sortOptions: false })
    .addHelpText(
      'after',
      '\nAliases: --iss, --acs, --slo, --aud, --spId, --rs, --static, --enc, --encCert, --encKey, --conf, --acr, --acd\n' +
        '\nExample:\n  saml-idp --acsUrl http://acme.okta.com/auth/saml20/exampleidp ' +
        '--audience https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV',
    );

  program
    .addOption(new Option('--host <host>', 'IdP Web Server Listener Host').default('localhost'))
    .addOption(
      new Option('-p, --port <port>', 'IdP Web Server Listener Port')
        .default(7000)
        .argParser((v) => {
          const port = Number.parseInt(v, 10);
          if (Number.isNaN(port) || port < 0 || port > 65535) throw new InvalidArgumentError('Invalid port.');
          return port;
        }),
    )
    .option('--cert <cert>', 'IdP Signature PublicKey Certificate (PEM or path) [default: bundled test certificate]')
    .option('--key <key>', 'IdP Signature PrivateKey Certificate (PEM or path) [default: bundled test key]')
    .addOption(new Option('--issuer <uri>', 'IdP Issuer URI').default('urn:example:idp'))
    .option('--acsUrl <url>', 'SP Assertion Consumer URL')
    .option('--sloUrl <url>', 'SP Single Logout URL')
    .option('--audience <uri>', 'SP Audience URI')
    .option('--serviceProviderId <uri>', 'SP Issuer/Entity URI')
    .option('--relayState <state>', 'Default SAML RelayState for SAMLResponse')
    .addOption(
      booleanOption(
        '--disableRequestAcsUrl',
        'Disables ability for SP AuthnRequest to specify Assertion Consumer URL',
      ),
    )
    .addOption(booleanOption('--encryptAssertion', 'Encrypts assertion with SP Public Key'))
    .option('--encryptionCert <cert>', 'SP Certificate (pem) for Assertion Encryption')
    .option(
      '--encryptionPublicKey <key>',
      'SP RSA Public Key (pem) for Assertion Encryption (derived from the certificate when omitted)',
    )
    .option('--httpsPrivateKey <key>', 'Web Server TLS/SSL Private Key (pem)')
    .option('--httpsCert <cert>', 'Web Server TLS/SSL Certificate (pem)')
    .addOption(booleanOption('--https', 'Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)'))
    .addOption(booleanOption('--signResponse', 'Enables signing of responses', true))
    .addOption(
      new Option('--configFile <path>', 'Path to a SAML attribute config file').default('saml-idp/config.js'),
    )
    .addOption(
      booleanOption(
        '--rollSession',
        'Create a new session for every authn request instead of reusing an existing session',
      ),
    )
    .addOption(
      new Option('--authnContextClassRef <uri>', 'Authentication Context Class Reference').default(
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      ),
    )
    .option('--authnContextDecl <path>', 'Authentication Context Declaration (XML FilePath)')
    .addOption(
      new Option('--logLevel <level>', 'Verbosity of the logs (env: SAML_IDP_LOG_LEVEL)').choices(LOG_LEVELS),
    )
    .addOption(booleanOption('--silent', 'Disables logging (same as --logLevel silent)'))
    .action(async (opts: IdpOptions) => {
      if (!opts.acsUrl) program.error("error: required option '--acsUrl <url>' not specified");
      if (!opts.audience) program.error("error: required option '--audience <uri>' not specified");
      try {
        await onRun({
          ...opts,
          host: process.env.HOST ?? opts.host,
          port: process.env.PORT ? Number.parseInt(process.env.PORT, 10) : opts.port,
        });
      } catch (error) {
        if (error instanceof OptionsError) {
          console.error(pc.red(error.message));
          process.exit(1);
        }
        throw error;
      }
    });

  return program;
}
