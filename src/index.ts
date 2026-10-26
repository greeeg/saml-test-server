import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { hostname as osHostname } from "node:os";
import type { Server } from "node:http";
import { serve } from "@hono/node-server";
import type { Hono } from "hono";
import { createApp } from "./app.js";
import { configBanner, createLogger, listeningBanner, type Logger } from "./log.js";
import { resolveOptions, type IdpOptions, type ResolvedOptions } from "./options.js";
import type { SessionVariables } from "./session.js";
import { createState, type IdpState } from "./state.js";
import pc from "picocolors";

export { OptionsError } from "./options.js";
export type { IdpOptions, ResolvedOptions, PemOrPath } from "./options.js";
export type { LogLevel } from "./log.js";
export { createDefaultConfig } from "./default-config.js";
export type { IdpConfig, UserProfile } from "./default-config.js";
export { IDP_PATHS } from "./state.js";
export type { IdpSettings, IdpState } from "./state.js";
export type { ClaimMetadata } from "./vendor/samlp/index.js";

const WILDCARD_ADDRESSES = ["0.0.0.0", "::"];

export interface Idp {
  /** The Hono application. Use `app.request()` / `app.fetch` to call it without a network port. */
  app: Hono<{ Variables: SessionVariables }>;
  /** Mutable state (settings, user, attribute metadata). */
  state: IdpState;
  /** The effective options after defaults were applied. */
  options: ResolvedOptions;
  logger: Logger;
}

export interface RunningIdp extends Idp {
  /** Base URL of the IdP, e.g. `http://localhost:7000`. */
  url: string;
  /** The IdP metadata URL. */
  metadataUrl: string;
  server: Server;
  /** Stops the server and drops open connections. */
  close(): Promise<void>;
}

/** Creates the IdP application without starting a server. */
export async function createIdp(input: IdpOptions): Promise<Idp> {
  const options = await resolveOptions(input);
  const logger = createLogger(options.logLevel);
  const state = createState(options);
  const app = createApp({ state, logger, rollSession: options.rollSession });
  return { app, state, options, logger };
}

/**
 * Creates the IdP and starts listening. The returned promise resolves once the
 * server accepts connections, so it can be awaited from a test `globalSetup`.
 */
export async function runServer(input: IdpOptions): Promise<RunningIdp> {
  const idp = await createIdp(input);
  const { app, options, logger } = idp;

  logger.log(configBanner(options));
  logger.log(`Starting IdP server on port ${pc.cyan(`${options.host}:${options.port}`)}...\n`);

  const server = await new Promise<Server>((resolve, reject) => {
    const instance = serve(
      {
        fetch: app.fetch,
        port: options.port,
        hostname: options.host,
        ...(options.https
          ? {
              createServer: createHttpsServer,
              serverOptions: { key: options.httpsPrivateKey, cert: options.httpsCert },
            }
          : {}),
      },
      () => resolve(instance as Server),
    ) as Server;
    instance.once("error", reject);
  });

  const { address, port } = server.address() as AddressInfo;
  const scheme = options.https ? "https" : "http";
  const bannerHost = WILDCARD_ADDRESSES.includes(address) ? osHostname() : "localhost";
  const url = `${scheme}://localhost:${port}`;
  logger.log(listeningBanner(`${scheme}://${bannerHost}:${port}`, !!options.sloUrl));

  return {
    ...idp,
    url,
    metadataUrl: `${url}/metadata`,
    server,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}
