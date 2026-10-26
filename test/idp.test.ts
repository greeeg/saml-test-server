import { beforeEach, describe, expect, it } from "vitest";
import { createIdp, type Idp, type IdpOptions } from "../src/index.js";
import {
  authnRequest,
  Client,
  decryptAssertion,
  elementText,
  idpCert,
  loadFixture,
  nodes,
  parse,
  parseForm,
  postEncode,
  redirectEncode,
  sp1Cert,
  sp1Key,
  text,
  verifySignature,
} from "./helpers.js";

const ACS = "https://sp.example.com/acs";
const SLO = "https://sp.example.com/slo";
const AUDIENCE = "https://sp.example.com/metadata";

async function setup(overrides: Partial<IdpOptions> = {}): Promise<{ idp: Idp; client: Client }> {
  const idp = await createIdp({
    acsUrl: ACS,
    audience: AUDIENCE,
    logLevel: "silent" as const,
    ...overrides,
  });
  return { idp, client: new Client(idp.app) };
}

/** Completes the sign in form and returns the SAML Response XML that is posted to the SP. */
async function signIn(client: Client, extra: Record<string, string> = {}) {
  const res = await client.post("/signin", { userName: "saml.jackson@example.com", ...extra });
  expect(res.status).toBe(200);
  const form = parseForm(await res.text());
  const xml = Buffer.from(form.fields.SAMLResponse ?? "", "base64").toString("utf8");
  return { form, xml, doc: xml ? parse(xml) : undefined };
}

describe("IdP initiated SSO", () => {
  it("shows the sign in form with the default user", async () => {
    const { client } = await setup();
    const res = await client.get("/");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('id="userName"');
    expect(html).toContain('value="saml.jackson@example.com"');
    expect(html).toContain('id="btn-sign-in"');
    expect(html).not.toContain("SAML Authentication Request");
    expect(res.headers.get("set-cookie")).toContain("idp_sid=");
  });

  it("posts a signed Response with the edited claims to the ACS URL", async () => {
    const { client } = await setup({ relayState: "default-relay" });
    const { form, xml, doc } = await signIn(client, {
      email: "edited@example.com",
      groups: "a, b",
    });

    expect(form.action).toBe(ACS);
    expect(form.fields.RelayState).toBe("default-relay");

    expect(text("/samlp:Response/@Destination", doc)).toBe(ACS);
    expect(text("//saml:Issuer", doc)).toBe("urn:example:idp");
    expect(text("//saml:Audience", doc)).toBe(AUDIENCE);
    expect(text("//saml:NameID", doc)).toBe("saml.jackson@example.com");
    expect(text("//saml:NameID/@Format", doc)).toBe(
      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    );
    expect(text("//saml:SubjectConfirmationData/@Recipient", doc)).toBe(ACS);
    expect(text("//saml:AuthnContextClassRef", doc)).toBe(
      "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    );
    expect(text("//saml:Attribute[@Name='email']/saml:AttributeValue", doc)).toBe(
      "edited@example.com",
    );
    expect(
      nodes("//saml:Attribute[@Name='groups']/saml:AttributeValue", doc).map((n) => n.textContent),
    ).toEqual(["a", "b"]);
    expect(nodes("//saml:AuthnStatement/@SessionIndex", doc)).toHaveLength(1);

    verifySignature(xml, "/samlp:Response", idpCert);
    verifySignature(xml, "//saml:Assertion", idpCert);
  });

  it("keeps the edited profile for the next sign in", async () => {
    const { client } = await setup();
    await signIn(client, { firstName: "Edited" });
    const html = await (await client.get("/")).text();
    expect(html).toContain('value="Edited"');
  });

  it("can skip signing the Response", async () => {
    const { client } = await setup({ signResponse: false });
    const { xml, doc } = await signIn(client);
    expect(nodes("/samlp:Response/ds:Signature", doc)).toHaveLength(0);
    verifySignature(xml, "//saml:Assertion", idpCert);
  });

  it("encrypts the assertion for the SP (public key derived from the certificate)", async () => {
    const { client } = await setup({ encryptAssertion: true, encryptionCert: sp1Cert.toString() });
    const { xml, doc } = await signIn(client);
    expect(nodes("//saml:EncryptedAssertion", doc)).toHaveLength(1);
    expect(nodes("/samlp:Response/saml:Assertion", doc)).toHaveLength(0);
    verifySignature(xml, "/samlp:Response", idpCert);

    const decrypted = await decryptAssertion(xml, sp1Key);
    expect(text("/saml:Assertion/saml:Subject/saml:NameID", parse(decrypted))).toBe(
      "saml.jackson@example.com",
    );
    verifySignature(decrypted, "/saml:Assertion", idpCert);
  });

  it("adds the Authentication Context Declaration", async () => {
    const { client } = await setup({
      authnContextDecl: loadFixture("authentication-context-declaration.xml"),
    });
    const { xml, doc } = await signIn(client);
    expect(nodes("//saml:AuthnContext/saml:AuthnContextDecl/*", doc).length).toBeGreaterThan(0);
    verifySignature(xml, "//saml:Assertion", idpCert);
  });

  it("accepts inline config (user + metadata)", async () => {
    const { client } = await setup({
      config: {
        user: {
          userName: "bob@example.com",
          nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
          email: "bob@example.com",
        },
        metadata: [{ id: "email", displayName: "E-Mail", optional: false }],
      },
    });
    const { doc } = await signIn(client, { userName: "bob@example.com" });
    expect(text("//saml:NameID", doc)).toBe("bob@example.com");
    expect(nodes("//saml:Attribute", doc)).toHaveLength(1);
    expect(text("//saml:Attribute[@Name='email']/saml:AttributeValue", doc)).toBe(
      "bob@example.com",
    );
  });
});

describe("SP initiated SSO", () => {
  const request = authnRequest({
    id: "_sp-request-1",
    issuer: AUDIENCE,
    acsUrl: "https://sp.example.com/dynamic-acs",
    destination: "http://localhost/saml/sso",
    forceAuthn: true,
  });

  it.each([
    [
      "HTTP-Redirect",
      (c: Client) =>
        c.get(
          `/saml/sso?SAMLRequest=${encodeURIComponent(redirectEncode(request))}&RelayState=relay-1`,
        ),
    ],
    [
      "HTTP-POST",
      (c: Client) =>
        c.post("/saml/sso", { SAMLRequest: postEncode(request), RelayState: "relay-1" }),
    ],
  ])("answers an AuthnRequest received through %s", async (_name, send) => {
    const { client } = await setup();
    const res = await send(client);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("SAML Authentication Request");
    expect(elementText(html, "requestId")).toBe("_sp-request-1");
    expect(elementText(html, "acsUrl")).toBe("https://sp.example.com/dynamic-acs");
    expect(elementText(html, "relayState")).toBe("relay-1");

    // the form carries the request over to /signin
    const hidden = parseForm(html).fields._authnRequest;
    const signInRes = await client.post("/signin", {
      userName: "saml.jackson@example.com",
      _authnRequest: hidden,
    });
    const form = parseForm(await signInRes.text());
    const xml = Buffer.from(form.fields.SAMLResponse, "base64").toString();
    const doc = parse(xml);

    expect(form.action).toBe("https://sp.example.com/dynamic-acs");
    expect(form.fields.RelayState).toBe("relay-1");
    expect(text("/samlp:Response/@InResponseTo", doc)).toBe("_sp-request-1");
    expect(text("/samlp:Response/@Destination", doc)).toBe("https://sp.example.com/dynamic-acs");
    expect(text("//saml:SubjectConfirmationData/@InResponseTo", doc)).toBe("_sp-request-1");
    expect(text("//saml:SubjectConfirmationData/@Recipient", doc)).toBe(
      "https://sp.example.com/dynamic-acs",
    );
    verifySignature(xml, "/samlp:Response", idpCert);
    verifySignature(xml, "//saml:Assertion", idpCert);
  });

  it("ignores the ACS URL of the request with disableRequestAcsUrl", async () => {
    const { client } = await setup({ disableRequestAcsUrl: true });
    const html = await (
      await client.post("/saml/sso", { SAMLRequest: postEncode(request), RelayState: "relay-1" })
    ).text();
    const hidden = parseForm(html).fields._authnRequest;
    const form = parseForm(
      await (
        await client.post("/signin", { userName: "a@example.com", _authnRequest: hidden })
      ).text(),
    );
    expect(form.action).toBe(ACS);
    const doc = parse(Buffer.from(form.fields.SAMLResponse, "base64").toString());
    expect(text("/samlp:Response/@Destination", doc)).toBe(ACS);
    expect(text("/samlp:Response/@InResponseTo", doc)).toBe("_sp-request-1");
  });

  it("shows an error page for an invalid AuthnRequest", async () => {
    const { client } = await setup();
    const res = await client.post("/saml/sso", {
      SAMLRequest: Buffer.from("definitely not xml").toString("base64"),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("SAML AuthnRequest Parse Error");
  });
});

describe("metadata, settings and errors", () => {
  let idp: Idp;
  let client: Client;
  beforeEach(async () => {
    ({ idp, client } = await setup({ sloUrl: SLO }));
  });

  it("serves the IdP metadata honoring forwarded headers", async () => {
    const res = await client.request("/metadata", {
      headers: { "x-forwarded-proto": "https", "x-forwarded-host": "idp.example.com" },
    });
    expect(res.headers.get("content-type")).toContain("application/xml");
    const doc = parse(await res.text());
    const q = (name: string) => nodes(`//*[local-name()='${name}']`, doc);
    expect(text("/*/@entityID", doc)).toBe("urn:example:idp");
    expect(q("SingleSignOnService").map((n) => n.getAttribute("Location"))).toEqual([
      "https://idp.example.com/saml/sso",
      "https://idp.example.com/saml/sso",
    ]);
    expect(q("SingleLogoutService")).toHaveLength(2);
    expect(q("Attribute").map((n) => n.getAttribute("Name"))).toContain("email");
  });

  it("omits the SLO endpoints when no sloUrl is configured", async () => {
    const other = await setup();
    const doc = parse(await (await other.client.get("/metadata")).text());
    expect(nodes("//*[local-name()='SingleLogoutService']", doc)).toHaveLength(0);
  });

  it("adds attributes through POST /metadata", async () => {
    const res = await client.post("/metadata", {
      attributeName: "department",
      displayName: "Department",
    });
    expect(res.status).toBe(200);
    expect(idp.state.metadata.map((m) => m.id)).toContain("department");

    const { doc } = await signIn(client, { department: "Engineering" });
    expect(text("//saml:Attribute[@Name='department']/saml:AttributeValue", doc)).toBe(
      "Engineering",
    );
  });

  it("updates the settings through the settings page", async () => {
    const page = await (await client.get("/settings")).text();
    expect(page).toContain('name="issuer"');

    const res = await client.post("/settings", {
      issuer: "urn:changed:idp",
      signResponse: "false",
      lifetimeInSeconds: "60",
      audience: "urn:changed:sp",
      acsUrl: "https://sp.example.com/new-acs",
      RelayState: "from-settings",
    });
    expect(res.status).toBe(302);
    expect(idp.state.settings).toMatchObject({
      issuer: "urn:changed:idp",
      signResponse: false,
      lifetimeInSeconds: 60,
      audience: "urn:changed:sp",
    });

    const { form, xml, doc } = await signIn(client);
    expect(form.action).toBe("https://sp.example.com/new-acs");
    expect(form.fields.RelayState).toBe("from-settings");
    expect(text("//saml:Issuer", doc)).toBe("urn:changed:idp");
    expect(text("//saml:Audience", doc)).toBe("urn:changed:sp");
    expect(nodes("/samlp:Response/ds:Signature", doc)).toHaveLength(0);
    verifySignature(xml, "//saml:Assertion", idpCert);

    const metadata = parse(await (await client.get("/metadata")).text());
    expect(text("/*/@entityID", metadata)).toBe("urn:changed:idp");

    idp.state.reset();
    expect(idp.state.settings.issuer).toBe("urn:example:idp");
  });

  it("ignores unknown settings", async () => {
    await client.post("/settings", { key: "garbage", cert: "garbage" });
    expect(idp.state.settings.key).toContain("PRIVATE KEY");
  });

  it("answers unknown routes with a 404 page", async () => {
    const res = await client.get("/nope");
    expect(res.status).toBe(404);
    expect(await res.text()).toContain("Route Not Found");
  });

  it("rejects an invalid _authnRequest", async () => {
    const res = await client.post("/signin", { userName: "a", _authnRequest: "%%%" });
    expect(res.status).toBe(400);
  });

  it("does not pollute the user with prototype keys", async () => {
    await client.post("/signin", { userName: "a@example.com", __proto__: "x", constructor: "y" });
    expect(Object.getPrototypeOf(idp.state.user)).toBe(Object.prototype);
    expect(({} as any).x).toBeUndefined();
  });
});

describe("sessions", () => {
  it("reuses the session between requests", async () => {
    const { client } = await setup();
    const first = elementText(await (await client.get("/")).text(), "sessionIndex");
    const second = elementText(await (await client.get("/")).text(), "sessionIndex");
    expect(first).toMatch(/^\d+$/);
    expect(second).toBe(first);
  });

  it("starts a new session for each authn request with rollSession", async () => {
    const { client } = await setup({ rollSession: true });
    const first = elementText(await (await client.get("/")).text(), "sessionIndex");
    const second = elementText(await (await client.get("/")).text(), "sessionIndex");
    expect(second).not.toBe(first);
  });

  it("rejects forged session cookies", async () => {
    const { idp } = await setup();
    const res = await idp.app.request("/", { headers: { cookie: "idp_sid=forged.value" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).not.toContain("forged");
  });

  it("destroys the session on sign out when SLO is disabled", async () => {
    const { client } = await setup();
    await client.get("/");
    const before = client.sessionCookie;
    const res = await client.get("/signout");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");
    await client.get("/");
    expect(client.sessionCookie).not.toBe(before);
  });
});

describe("single logout", () => {
  async function loggedIn() {
    const ctx = await setup({ sloUrl: SLO });
    const html = await (await ctx.client.get("/")).text();
    const sessionIndex = elementText(html, "sessionIndex")!;
    return { ...ctx, sessionIndex };
  }

  it("fails when no SLO URL is configured", async () => {
    const { client } = await setup();
    const res = await client.get("/saml/slo");
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Single Logout Service URL not defined");
  });

  it("IdP initiated: sends a signed LogoutRequest and finishes on the LogoutResponse", async () => {
    const { client, sessionIndex } = await loggedIn();

    const signout = await client.get("/signout");
    expect(signout.status).toBe(302);
    expect(signout.headers.get("location")).toBe("/saml/slo");

    const res = await client.get("/saml/slo");
    expect(res.status).toBe(200);
    const form = parseForm(await res.text());
    expect(form.action).toBe(SLO);

    const xml = Buffer.from(form.fields.SAMLRequest, "base64").toString();
    const doc = parse(xml);
    expect(doc.documentElement!.localName).toBe("LogoutRequest");
    expect(text("//saml:NameID", doc)).toBe("saml.jackson@example.com");
    expect(text("//samlp:SessionIndex", doc)).toBe(sessionIndex);
    expect(text("/samlp:LogoutRequest/@Destination", doc)).toBe(SLO);
    expect(form.fields.RelayState).toBeTruthy();
    verifySignature(xml, "/samlp:LogoutRequest", idpCert);

    // The SP answers with a LogoutResponse carrying our RelayState
    const sessionBefore = client.sessionCookie;
    const logoutResponse =
      `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
      `ID="_lr" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>${AUDIENCE}</saml:Issuer>` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>`;
    const done = await client.post("/saml/slo", {
      SAMLResponse: postEncode(logoutResponse),
      RelayState: form.fields.RelayState,
    });
    expect(done.status).toBe(200);
    expect(await done.text()).toBe("OK");

    // the IdP session is gone
    await client.get("/");
    expect(client.sessionCookie).not.toBe(sessionBefore);
  });

  it("IdP initiated: rejects a LogoutResponse with an unknown RelayState", async () => {
    const { client } = await loggedIn();
    const res = await client.post("/saml/slo", {
      SAMLResponse: postEncode(
        '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
      ),
      RelayState: "unknown",
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid RelayState");
  });

  const logoutRequest = (opts: { issuer: string; sessionIndex: string; nameId?: string }) =>
    `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="_logout-req-1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="http://localhost/saml/slo">` +
    `<saml:Issuer>${opts.issuer}</saml:Issuer><saml:NameID>${opts.nameId ?? "saml.jackson@example.com"}</saml:NameID>` +
    `<samlp:SessionIndex>${opts.sessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>`;

  it.each([
    ["HTTP-POST", (xml: string) => postEncode(xml)],
    ["HTTP-Redirect", (xml: string) => redirectEncode(xml)],
  ])(
    "SP initiated through %s: answers with a signed LogoutResponse and ends the session",
    async (name, encode) => {
      const { client, sessionIndex } = await loggedIn();
      const sessionBefore = client.sessionCookie;
      const xml = logoutRequest({ issuer: AUDIENCE, sessionIndex });

      const res =
        name === "HTTP-POST"
          ? await client.post("/saml/slo", { SAMLRequest: encode(xml), RelayState: "sp-relay" })
          : await client.get(
              `/saml/slo?SAMLRequest=${encodeURIComponent(encode(xml))}&RelayState=sp-relay`,
            );
      expect(res.status).toBe(200);

      const form = parseForm(await res.text());
      expect(form.action).toBe(SLO);
      expect(form.fields.RelayState).toBe("sp-relay");
      const responseXml = Buffer.from(form.fields.SAMLResponse, "base64").toString();
      const doc = parse(responseXml);
      expect(doc.documentElement!.localName).toBe("LogoutResponse");
      expect(text("/samlp:LogoutResponse/@InResponseTo", doc)).toBe("_logout-req-1");
      expect(text("//samlp:StatusCode/@Value", doc)).toBe(
        "urn:oasis:names:tc:SAML:2.0:status:Success",
      );
      expect(text("//saml:Issuer", doc)).toBe("urn:example:idp");
      verifySignature(responseXml, "/samlp:LogoutResponse", idpCert);

      await client.get("/");
      expect(client.sessionCookie).not.toBe(sessionBefore);
    },
  );

  it("SP initiated: rejects a LogoutRequest for another session", async () => {
    const { client } = await loggedIn();
    const res = await client.post("/saml/slo", {
      SAMLRequest: postEncode(logoutRequest({ issuer: AUDIENCE, sessionIndex: "not-my-session" })),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid Session Participant");
  });
});
