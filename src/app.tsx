import { randomBytes } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { Hono, type Context } from "hono";
import { logger as honoLogger } from "hono/logger";
import {
  createLogger,
  describeRecord,
  formatOptionValue,
  prettyPrintXml,
  type Logger,
} from "./log.js";
import { createSimpleProfileMapper } from "./profile-mapper.js";
import {
  createLogoutStore,
  getSessionIndex,
  sessionMiddleware,
  SessionStore,
  type SessionVariables,
} from "./session.js";
import { IDP_PATHS, type IdpSettings, type IdpState } from "./state.js";
import {
  authenticate,
  buildMetadata,
  logout,
  parseRequest,
  SamlpError,
  SessionParticipants,
  type AuthOptions,
  type LogoutResult,
  type PostForm,
  type SamlHttpInput,
} from "./vendor/samlp/index.js";
import {
  AutoPostForm,
  ErrorPage,
  SettingsPage,
  UserPage,
  type AuthnRequestInfo,
} from "./views/index.js";

type AppEnv = { Variables: SessionVariables };
type AppContext = Context<AppEnv>;

const SSO_PATHS = ["/", "/idp", IDP_PATHS.SSO];
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export interface CreateAppOptions {
  state: IdpState;
  logger?: Logger;
  /** Create a new session for every authn request instead of reusing an existing session. */
  rollSession?: boolean;
}

/** Reads the query string and (form) body of the request in a framework independent shape. */
async function readInput(c: AppContext): Promise<SamlHttpInput> {
  const query = c.req.query();
  const body: Record<string, string | undefined> = {};
  if (c.req.method === "POST") {
    const contentType = c.req.header("content-type") ?? "";
    if (/application\/x-www-form-urlencoded|multipart\/form-data/.test(contentType)) {
      const parsed = await c.req.parseBody();
      for (const [key, value] of Object.entries(parsed)) {
        if (typeof value === "string") body[key] = value;
      }
    }
  }
  return { query, body };
}

function errorPage(c: AppContext, state: IdpState, message: string, status = 500, error?: unknown) {
  const stack = error instanceof Error ? error.stack : undefined;
  return c.html(
    <ErrorPage message={message} status={status} stack={stack} issuer={state.settings.issuer} />,
    status as 400,
  );
}

function postFormResponse(c: AppContext, form: PostForm) {
  return c.html(
    <AutoPostForm
      url={form.url}
      field={form.field}
      value={form.value}
      relayState={form.relayState}
    />,
  );
}

function toBoolean(value: string): boolean {
  return ["true", "yes", "1", "on"].includes(value.toLowerCase());
}

/** Fields of the settings page and how their value is parsed. */
const SETTINGS_FIELDS: Record<string, "string" | "boolean" | "number" | "optional"> = {
  issuer: "string",
  signatureAlgorithm: "string",
  digestAlgorithm: "string",
  signResponse: "boolean",
  lifetimeInSeconds: "number",
  authnContextClassRef: "string",
  allowRequestAcsUrl: "boolean",
  serviceProviderId: "string",
  sloUrl: "optional",
  acsUrl: "string",
  destination: "string",
  recipient: "string",
  audience: "string",
  RelayState: "optional",
};

function applySettings(settings: IdpSettings, body: Record<string, string | undefined>): void {
  for (const [key, kind] of Object.entries(SETTINGS_FIELDS)) {
    const value = body[key];
    if (value === undefined) continue;
    const target = settings as unknown as Record<string, unknown>;
    switch (kind) {
      case "boolean":
        target[key] = toBoolean(value);
        break;
      case "number": {
        const parsed = Number.parseInt(value, 10);
        if (!Number.isNaN(parsed)) target[key] = parsed;
        break;
      }
      case "optional":
        target[key] = value === "" ? undefined : value;
        break;
      default:
        target[key] = value;
    }
  }
}

/** Adds an `AuthnContextDecl` (parsed from XML) to the assertion's `AuthnContext`. */
function authnContextDeclTransformer(
  decl: string | undefined,
  logger: Logger,
): AuthOptions["transformAssertion"] {
  if (!decl) return undefined;
  return (assertionDom) => {
    let declDoc;
    try {
      declDoc = new DOMParser().parseFromString(decl, "text/xml");
    } catch (err) {
      logger.log("Unable to parse Authentication Context Declaration XML", err);
      return;
    }
    if (!declDoc?.documentElement) return;
    const declEl = assertionDom.createElementNS(
      "urn:oasis:names:tc:SAML:2.0:assertion",
      "saml:AuthnContextDecl",
    );
    declEl.appendChild(assertionDom.importNode(declDoc.documentElement, true));
    assertionDom.getElementsByTagName("saml:AuthnContext")[0].appendChild(declEl);
  };
}

function requestOrigin(c: AppContext): string {
  const url = new URL(c.req.url);
  const proto =
    c.req.header("x-forwarded-proto")?.split(",")[0].trim() ?? url.protocol.replace(":", "");
  const host = c.req.header("x-forwarded-host") ?? c.req.header("host") ?? url.host;
  return `${proto}://${host}`;
}

/** Creates the Hono application that serves the IdP. */
export function createApp({
  state,
  logger = createLogger("info"),
  rollSession = false,
}: CreateAppOptions): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  /** Renders the error page and logs unexpected (5xx) errors. */
  const fail: typeof errorPage = (c, st, message, status = 500, error) => {
    if (status >= 500) logger.error(error instanceof Error ? (error.stack ?? message) : message);
    return errorPage(c, st, message, status, error);
  };
  const sessions = new SessionStore();
  const profileMapper = createSimpleProfileMapper(() => state.metadata);

  /** Everything the IdP does for a request: settings + derived callbacks. */
  const logoutCredentials = (c: AppContext) => {
    const settings = state.settings;
    const session = c.get("session");
    return {
      participant: {
        serviceProviderId: settings.serviceProviderId,
        sessionIndex: getSessionIndex(session),
        nameId: state.user.userName,
        nameIdFormat: state.user.nameIdFormat,
        serviceProviderLogoutURL: settings.sloUrl,
      },
      session,
    };
  };

  /**
   * Middleware
   */
  app.use(
    "*",
    honoLogger((message, ...rest) => logger.log(message, ...rest)),
  );
  app.use("*", sessionMiddleware(sessions, randomBytes(32).toString("hex")));

  // Optionally start a fresh session on every authn request
  app.use("*", async (c, next) => {
    if (rollSession && SSO_PATHS.includes(c.req.path) && ["GET", "POST"].includes(c.req.method)) {
      c.get("session").regenerate();
    }
    await next();
  });

  /**
   * View handlers
   */
  const showUser = (c: AppContext, authnRequest?: AuthnRequestInfo) => {
    const session = c.get("session");
    return c.html(
      <UserPage
        user={state.user}
        sessionIndex={getSessionIndex(session)}
        metadata={state.metadata}
        authnRequest={authnRequest}
        idp={state.settings}
      />,
    );
  };

  /**
   * SSO: parse the (optional) AuthnRequest and show the sign-in form
   */
  const parseSamlRequest = async (c: AppContext) => {
    const input = await readInput(c);
    let data;
    try {
      data = await parseRequest(input);
    } catch (err) {
      return fail(c, state, "SAML AuthnRequest Parse Error: " + (err as Error).message, 400, err);
    }

    let authnRequest: AuthnRequestInfo | undefined;
    if (data) {
      authnRequest = {
        relayState: input.query.RelayState || input.body.RelayState,
        id: data.id,
        issuer: data.issuer,
        destination: data.destination,
        acsUrl: data.assertionConsumerServiceURL,
        forceAuthn: data.forceAuthn === "true",
      };
      logger.log("Received AuthnRequest => \n", authnRequest);
    }
    return showUser(c, authnRequest);
  };
  app.on(["GET", "POST"], SSO_PATHS, parseSamlRequest);

  /**
   * SLO
   */
  const handleLogout = async (c: AppContext) => {
    const settings = state.settings;
    if (!settings.sloUrl) {
      return fail(c, state, "SAML Single Logout Service URL not defined for Service Provider", 400);
    }
    const { participant, session } = logoutCredentials(c);
    logger.log("Processing SAML SLO request for participant => \n", participant);

    const input = await readInput(c);
    let result: LogoutResult;
    try {
      result = await logout(input, {
        issuer: settings.issuer,
        cert: settings.cert,
        key: settings.key,
        digestAlgorithm: settings.digestAlgorithm,
        signatureAlgorithm: settings.signatureAlgorithm,
        sessionParticipants: new SessionParticipants([participant]),
        store: createLogoutStore(session),
        clearIdPSession: () => {
          logger.log("Destroying session " + session.id + " for participant", participant);
          session.destroy();
        },
      });
    } catch (err) {
      const status = err instanceof SamlpError ? err.status : 500;
      return fail(c, state, (err as Error).message, status, err);
    }

    switch (result.type) {
      case "post":
        return postFormResponse(c, result);
      case "redirect":
        return c.redirect(result.url);
      default:
        return c.text("OK", 200);
    }
  };
  app.get(IDP_PATHS.SLO, handleLogout);
  app.post(IDP_PATHS.SLO, handleLogout);

  /**
   * Sign in: mint the SAML Response and POST it to the Service Provider
   */
  app.post(IDP_PATHS.SIGN_IN, async (c) => {
    const settings = state.settings;
    const session = c.get("session");
    const input = await readInput(c);

    const authOptions: AuthOptions & Record<string, unknown> = {
      ...settings,
      profileMapper,
      postEndpointPath: IDP_PATHS.SSO,
      redirectEndpointPath: IDP_PATHS.SSO,
      getPostURL: () => settings.acsUrl,
      transformAssertion: authnContextDeclTransformer(settings.authnContextDecl, logger),
    };

    let authnRequest: AuthnRequestInfo | undefined;
    for (const [key, value] of Object.entries(input.body)) {
      if (value === undefined) continue;
      if (key === "_authnRequest") {
        try {
          authnRequest = JSON.parse(Buffer.from(value, "base64").toString("utf8"));
        } catch {
          return fail(c, state, "Invalid _authnRequest", 400);
        }
        if (!authnRequest) continue;

        // Apply AuthnRequest params
        authOptions.inResponseTo = authnRequest.id;
        if (settings.allowRequestAcsUrl && authnRequest.acsUrl) {
          authOptions.acsUrl = authnRequest.acsUrl;
          authOptions.recipient = authnRequest.acsUrl;
          authOptions.destination = authnRequest.acsUrl;
          authOptions.forceAuthn = authnRequest.forceAuthn;
          authOptions.getPostURL = () => authnRequest!.acsUrl;
        }
        if (authnRequest.relayState) {
          authOptions.RelayState = authnRequest.relayState;
        }
      } else if (!UNSAFE_KEYS.has(key)) {
        state.user[key] = value;
      }
    }

    if (!authOptions.encryptAssertion) {
      delete authOptions.encryptionCert;
      delete authOptions.encryptionPublicKey;
    }

    // Set Session Index
    authOptions.sessionIndex = getSessionIndex(session);

    // Keep calm and Single Sign On
    logger.log(
      [
        "Generating SAML Response using =>",
        "  User =>",
        describeRecord(state.user, 4, (_k, v) => String(v)),
        "  SAMLP Options =>",
        describeRecord(authOptions, 4),
        "",
      ].join("\n"),
    );

    try {
      // the SAML Response is created for the signed-in user, not for a request
      const result = await authenticate({ query: {}, body: {} }, authOptions, state.user);
      logger.log(
        [
          `Sending SAML Response to ${result.url} =>`,
          `  RelayState =>`,
          `    ${result.relayState || "None"}`,
          `  SAMLResponse =>`,
          prettyPrintXml(result.xml, 4),
          "",
        ].join("\n"),
      );
      return postFormResponse(c, result);
    } catch (err) {
      const status = err instanceof SamlpError ? err.status : 500;
      return fail(c, state, (err as Error).message, status, err);
    }
  });

  /**
   * Metadata
   */
  app.get(IDP_PATHS.METADATA, (c) => {
    const settings = state.settings;
    const xml = buildMetadata(
      {
        issuer: settings.issuer,
        cert: settings.cert,
        profileMapper,
        postEndpointPath: IDP_PATHS.SSO,
        redirectEndpointPath: IDP_PATHS.SSO,
        logoutEndpointPaths: settings.sloUrl
          ? { redirect: IDP_PATHS.SLO, post: IDP_PATHS.SLO }
          : {},
      },
      requestOrigin(c),
    );
    return c.body(xml, 200, { "Content-Type": "application/xml" });
  });

  app.post(IDP_PATHS.METADATA, async (c) => {
    const { body } = await readInput(c);
    if (body.attributeName && body.displayName) {
      const attribute = {
        id: body.attributeName,
        optional: true,
        displayName: body.displayName,
        description: body.description || "",
        multiValue: body.valueType === "multi",
      };
      const index = state.metadata.findIndex((entry) => entry.id === attribute.id);
      if (index === -1) state.metadata.push(attribute);
      else state.metadata[index] = attribute;

      logger.log("Updated SAML Attribute Metadata => \n", state.metadata);
      return c.body(null, 200);
    }
    return c.body(null, 400);
  });

  /**
   * Sign out
   */
  app.get(IDP_PATHS.SIGN_OUT, (c) => {
    const settings = state.settings;
    if (settings.sloUrl) {
      logger.log(
        `Initiating SAML SLO request for user: ${state.user.userName} with sessionIndex: ${getSessionIndex(c.get("session"))}`,
      );
      return c.redirect(IDP_PATHS.SLO);
    }
    logger.log("SAML SLO is not enabled for SP, destroying IDP session");
    c.get("session").destroy();
    return c.redirect(c.req.header("referer") || "/");
  });

  /**
   * Settings
   */
  app.get(IDP_PATHS.SETTINGS, (c) => c.html(<SettingsPage idp={state.settings} />));

  app.post(IDP_PATHS.SETTINGS, async (c) => {
    const { body } = await readInput(c);
    applySettings(state.settings, body);
    logger.log("Updated IdP Configuration => \n", {
      ...state.settings,
      cert: formatOptionValue("cert", state.settings.cert),
      key: formatOptionValue("key", state.settings.key),
    });
    return c.redirect("/");
  });

  /**
   * Errors
   */
  app.notFound((c) => {
    const err = new Error("Route Not Found");
    return fail(c as AppContext, state, err.message, 404, err);
  });

  app.onError((err, c) => {
    const status = (err as { status?: number }).status ?? 500;
    return fail(c as AppContext, state, err.message, status, err);
  });

  return app;
}
