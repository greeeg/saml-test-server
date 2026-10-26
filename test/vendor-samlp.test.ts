import { describe, expect, it } from "vitest";
import {
  buildMetadata,
  createSamlResponse,
  parseRequest,
  passportProfileMapper,
} from "../src/vendor/samlp/index.js";
import { thumbprint } from "../src/vendor/samlp/encoders.js";
import {
  authnRequest,
  decryptAssertion,
  idpCert,
  idpKey,
  nodes,
  parse,
  postEncode,
  redirectEncode,
  sp1Cert,
  sp1Key,
  text,
  verifySignature,
} from "./helpers.js";

const user = {
  id: "user-1",
  displayName: "Saml Jackson",
  name: { givenName: "Saml", familyName: "Jackson" },
  emails: [{ value: "saml@example.com" }],
  extra: true,
};

const base = {
  issuer: "urn:test:idp",
  cert: idpCert,
  key: idpKey,
  audience: "https://sp.example.com",
  recipient: "https://sp.example.com/acs",
  destination: "https://sp.example.com/acs",
  profileMapper: passportProfileMapper,
};

describe("createSamlResponse", () => {
  it("builds a Response with a signed Assertion and signed Response", async () => {
    const xml = await createSamlResponse(
      { ...base, signResponse: true, inResponseTo: "_abc" },
      user,
    );
    const doc = parse(xml);

    expect(text("/samlp:Response/@InResponseTo", doc)).toBe("_abc");
    expect(text("/samlp:Response/@Destination", doc)).toBe(base.destination);
    expect(text("//samlp:StatusCode/@Value", doc)).toBe(
      "urn:oasis:names:tc:SAML:2.0:status:Success",
    );
    expect(text("//saml:Audience", doc)).toBe(base.audience);
    expect(text("//saml:NameID", doc)).toBe("user-1");
    expect(text("//saml:SubjectConfirmationData/@InResponseTo", doc)).toBe("_abc");

    verifySignature(xml, "/samlp:Response", idpCert);
    verifySignature(xml, "//saml:Assertion", idpCert);
  });

  it("omits the Response signature when signResponse is false", async () => {
    const xml = await createSamlResponse({ ...base, signResponse: false }, user);
    const doc = parse(xml);
    expect(nodes("/samlp:Response/ds:Signature", doc)).toHaveLength(0);
    verifySignature(xml, "//saml:Assertion", idpCert);
  });

  it("types attribute values and uses the right NameFormat", async () => {
    const xml = await createSamlResponse({ ...base }, user);
    const doc = parse(xml);
    const email = nodes(
      "//saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']",
      doc,
    )[0];
    expect(email.getAttribute("NameFormat")).toBe(
      "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
    );
    expect(text("./saml:AttributeValue", email)).toBe("saml@example.com");
    expect(
      text(
        "//saml:Attribute[@Name='http://schemas.passportjs.com/extra']/saml:AttributeValue/@xsi:type",
        doc,
      ),
    ).toBe("xs:boolean");
  });

  it("supports sha1 algorithms", async () => {
    const xml = await createSamlResponse(
      { ...base, signResponse: true, signatureAlgorithm: "rsa-sha1", digestAlgorithm: "sha1" },
      user,
    );
    expect(text("/samlp:Response/ds:Signature//ds:SignatureMethod/@Algorithm", parse(xml))).toBe(
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    );
    verifySignature(xml, "/samlp:Response", idpCert);
  });

  it("encrypts the assertion for the SP", async () => {
    const xml = await createSamlResponse(
      { ...base, signResponse: true, encryptionCert: sp1Cert },
      user,
    );
    const doc = parse(xml);
    expect(nodes("//saml:EncryptedAssertion", doc)).toHaveLength(1);
    expect(nodes("/samlp:Response/saml:Assertion", doc)).toHaveLength(0);
    verifySignature(xml, "/samlp:Response", idpCert);

    const decrypted = await decryptAssertion(xml, sp1Key);
    expect(parse(decrypted).documentElement!.localName).toBe("Assertion");
    verifySignature(decrypted, "/saml:Assertion", idpCert);
  });

  it("lets transformAssertion mutate the assertion before signing", async () => {
    const xml = await createSamlResponse(
      {
        ...base,
        transformAssertion: (doc) => {
          const el = doc.createElementNS("urn:test", "x:Custom");
          el.textContent = "hello";
          doc.documentElement!.appendChild(el);
        },
      },
      user,
    );
    expect(text('//*[local-name()="Custom"]', parse(xml))).toBe("hello");
    verifySignature(xml, "//saml:Assertion", idpCert);
  });

  it("fails when no name identifier can be derived", async () => {
    await expect(createSamlResponse({ ...base }, {})).rejects.toThrow(/nameIdentifier/);
  });
});

describe("parseRequest", () => {
  const xml = authnRequest({
    id: "_r1",
    issuer: "https://sp.example.com",
    acsUrl: "https://sp.example.com/acs",
    destination: "https://idp.example.com/sso",
    forceAuthn: true,
  });

  it("returns undefined without SAMLRequest", async () => {
    expect(await parseRequest({ query: {}, body: {} })).toBeUndefined();
  });

  it.each([
    ["HTTP-Redirect (deflated)", (x: string) => redirectEncode(x)],
    ["HTTP-POST (base64)", (x: string) => postEncode(x)],
  ])("parses an AuthnRequest from %s", async (_name, encode) => {
    const data = await parseRequest({ query: {}, body: { SAMLRequest: encode(xml) } });
    expect(data).toMatchObject({
      id: "_r1",
      issuer: "https://sp.example.com",
      assertionConsumerServiceURL: "https://sp.example.com/acs",
      destination: "https://idp.example.com/sso",
      forceAuthn: "true",
    });
  });

  it("rejects garbage", async () => {
    await expect(
      parseRequest({
        query: { SAMLRequest: Buffer.from("not xml at all").toString("base64") },
        body: {},
      }),
    ).rejects.toThrow();
  });

  it("requires a signature when a signing cert is configured", async () => {
    await expect(
      parseRequest({ query: {}, body: { SAMLRequest: postEncode(xml) } }, { signingCert: sp1Cert }),
    ).rejects.toThrow(/MUST be signed/);
  });
});

describe("buildMetadata", () => {
  it("describes endpoints and certificate", () => {
    const xml = buildMetadata(
      {
        ...base,
        postEndpointPath: "/saml/sso",
        redirectEndpointPath: "/saml/sso",
        logoutEndpointPaths: { redirect: "/saml/slo", post: "/saml/slo" },
      },
      "http://localhost:7000",
    );
    const doc = parse(xml);
    const md = (e: string) => e.replace(/\/(\w+)/g, '/*[local-name()="$1"]');
    expect(text("/*/@entityID", doc)).toBe("urn:test:idp");
    expect(nodes(md("//SingleSignOnService"), doc)).toHaveLength(2);
    expect(nodes(md("//SingleLogoutService"), doc)).toHaveLength(2);
    expect(text('//*[local-name()="SingleSignOnService"]/@Location', doc)).toBe(
      "http://localhost:7000/saml/sso",
    );
    expect(text('//*[local-name()="X509Certificate"]', doc)).toBe(
      idpCert.toString().replace(/-----[^-]+-----|\s/g, ""),
    );
  });
});

describe("thumbprint", () => {
  it("computes a SHA-1 thumbprint", () => {
    expect(thumbprint(idpCert)).toMatch(/^[0-9A-F]{40}$/);
  });
});
