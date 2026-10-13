# saml-idp-test-server

A simple SAML 2.0 Identity Provider (IdP) to test Service Providers (SPs) in **E2E tests**.

> **Not intended for use with production systems!** The bundled signing key is public.

## Usage

```ts
import { runServer } from 'saml-idp-test-server';

export default async function globalSetup() {
  const idp = await runServer({
    port: 7000,
    acsUrl: 'http://localhost:3000/auth/saml/callback',
    sloUrl: 'http://localhost:3000/auth/saml/logout',
    audience: 'http://localhost:3000/auth/saml/metadata',
    logLevel: 'silent',
  });

  // Change the signed-in user at any time, without going through the UI:
  idp.state.user.userName = 'jane@example.com';
  idp.state.user.email = 'jane@example.com';
  // ...and restore the defaults between tests:
  idp.state.reset();

  return () => idp.close();
}
```

Custom claims (the user is merged with the defaults):

```ts
await runServer({
  acsUrl,
  audience,
  config: {
    user: { userName: 'jane@example.com', email: 'jane@example.com', userType: 'Admin' },
    metadata: [
      { id: 'email', displayName: 'E-Mail Address', optional: false },
      { id: 'userType', displayName: 'User Type', optional: true, options: ['Admin', 'Editor'] },
    ],
  },
});
```

`configFile` (a `.js`, `.mjs` or `.json` module exporting `{ user, metadata }`) is also supported.

### In-process (no port)

```ts
import { createIdp } from 'saml-idp-test-server';

const { app, state } = await createIdp({ acsUrl, audience, logLevel: 'silent' });
const res = await app.request('/metadata');
```

### Command line

```shell
saml-idp --acsUrl {POST URL} --audience {audience}
saml-idp --acsUrl {POST URL} --sloUrl {POST URL} --audience {audience}
```

Open `http://localhost:7000` in your browser to start an IdP initiated flow to your SP.
All flags of the original CLI and their aliases (`--acs`, `--aud`, `--slo`, `--iss`, `--spId`, `--rs`, `--static`,
`--enc`, `--encCert`, `--encKey`, `--conf`, `--acr`, `--acd`) are supported. Run `saml-idp --help`.
`HOST` and `PORT` environment variables override `--host` and `--port`.

### Options

Passed as `--<option>` to the CLI or in the options object of `runServer` / `createIdp`.

| Option (* required)    | Description                                                              | Default                                  |
| ---------------------- | ------------------------------------------------------------------------ | ---------------------------------------- |
| `host`                 | IdP web server listener host                                             | `localhost`                              |
| `port`                 | IdP web server listener port (`0` picks a free port)                     | `7000`                                   |
| `cert`                 | IdP signature public key certificate (PEM or path)                       | bundled test certificate                 |
| `key`                  | IdP signature private key (PEM or path, PKCS#1 or PKCS#8)                | bundled test key                         |
| `issuer`               | IdP issuer URI                                                           | `urn:example:idp`                        |
| `acsUrl` *             | SP Assertion Consumer Service URL                                        |                                          |
| `sloUrl`               | SP Single Logout URL (enables SLO)                                       |                                          |
| `audience` *           | SP audience URI                                                          |                                          |
| `serviceProviderId`    | SP issuer / entity URI                                                   | `audience`                               |
| `relayState`           | Default RelayState                                                       |                                          |
| `disableRequestAcsUrl` | Ignore the ACS URL of the AuthnRequest                                   | `false`                                  |
| `encryptAssertion`     | Encrypt the assertion with the SP public key                             | `false`                                  |
| `encryptionCert`       | SP certificate (PEM or path) for assertion encryption                    |                                          |
| `encryptionPublicKey`  | SP RSA public key (PEM or path); derived from `encryptionCert` if absent |                                          |
| `https`                | Enable the HTTPS listener (needs `httpsPrivateKey` and `httpsCert`)      | `false`                                  |
| `httpsPrivateKey`      | Web server TLS private key (PEM or path)                                 |                                          |
| `httpsCert`            | Web server TLS certificate (PEM or path)                                 |                                          |
| `signResponse`         | Sign the SAML Response (the Assertion is always signed)                  | `true`                                   |
| `configFile`           | Module exporting `{ user, metadata }`                                    | built-in defaults                        |
| `config`               | Inline `{ user, metadata }` (library only)                               |                                          |
| `rollSession`          | New session for every authn request                                      | `false`                                  |
| `authnContextClassRef` | Authentication Context Class Reference                                   | `...:PasswordProtectedTransport`         |
| `authnContextDecl`     | Authentication Context Declaration (XML or path to an XML file)          |                                          |
| `logLevel`             | `silent` (no output), `error` (unexpected errors only) or `info`. Env: `SAML_IDP_LOG_LEVEL` | `info`                                   |
| `silent`               | Deprecated, same as `logLevel: 'silent'`                                  | `false`                                  |

### Endpoints

| Path                           | Description                                                          |
| ------------------------------ | -------------------------------------------------------------------- |
| `/`, `/idp`, `/saml/sso`       | SSO (HTTP-Redirect and HTTP-POST). Shows the sign in form            |
| `/signin` (POST)               | Mints the SAML Response and POSTs it to the ACS URL                  |
| `/saml/slo`                    | Single Logout (SP or IdP initiated, HTTP-Redirect and HTTP-POST)     |
| `/signout`                     | Starts IdP initiated logout (or just ends the session without SLO)   |
| `/metadata`                    | IdP metadata. `POST` adds an attribute (`attributeName`, `displayName`, ...) |
| `/settings`                    | Edit the IdP settings at runtime                                     |

Useful element ids for browser tests: `#userName`, `#nameIdFormat`, one input per attribute (`#email`, `#groups`, ...),
`#btn-sign-in`, `#btn-sign-out`.

## Development

```shell
npm install
npm run dev        # Vite dev server (SAML_ACS_URL, SAML_AUDIENCE, SAML_SLO_URL env vars)
npm test           # Vitest
npm run typecheck
npm run build      # dist/index.js, dist/cli.js, dist/types
```

Generate your own IdP key pair with:

```shell
openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' \
  -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300
```

## License

MIT, see [LICENSE](./LICENSE). Vendored code keeps its own license in `src/vendor/*/LICENSE`.
