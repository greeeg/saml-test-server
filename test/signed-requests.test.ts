import qs from "node:querystring";
import { describe, expect, it } from "vitest";
import { signXml, sign } from "../src/vendor/samlp/signers.js";
import {
  logout,
  parseRequest,
  SessionParticipants,
  type LogoutStore,
} from "../src/vendor/samlp/index.js";
import { thumbprint } from "../src/vendor/samlp/encoders.js";
import { createLogoutStore, Session, SessionStore } from "../src/session.js";
import {
  authnRequest,
  idpCert,
  idpKey,
  postEncode,
  redirectEncode,
  sp1Cert,
  sp1Key,
  sp2Cert,
  sp2Key,
} from "./helpers.js";

const ISSUER = "https://sp.example.com";
const request = authnRequest({ id: "_signed-1", issuer: ISSUER });
const signedRequest = signXml(
  { key: sp1Key, cert: sp1Cert, reference: "//*[local-name(.)='AuthnRequest']" },
  request,
);

describe("signed AuthnRequest (HTTP-POST, embedded signature)", () => {
  it("accepts a valid signature", async () => {
    const data = await parseRequest(
      { query: {}, body: { SAMLRequest: postEncode(signedRequest) } },
      { signingCert: sp1Cert },
    );
    expect(data?.id).toBe("_signed-1");
  });

  it("accepts a valid signature using the embedded certificate and its thumbprint", async () => {
    const data = await parseRequest(
      { query: {}, body: { SAMLRequest: postEncode(signedRequest) } },
      { thumbprints: [thumbprint(sp1Cert)] },
    );
    expect(data?.id).toBe("_signed-1");
  });

  it("rejects an unexpected thumbprint", async () => {
    await expect(
      parseRequest(
        { query: {}, body: { SAMLRequest: postEncode(signedRequest) } },
        { thumbprints: [thumbprint(sp2Cert)] },
      ),
    ).rejects.toThrow(/Invalid thumbprint/);
  });

  it("rejects a signature made with another key", async () => {
    await expect(
      parseRequest(
        { query: {}, body: { SAMLRequest: postEncode(signedRequest) } },
        { signingCert: sp2Cert },
      ),
    ).rejects.toThrow(/Signature check errors/);
  });

  it("rejects a tampered request", async () => {
    const tampered = signedRequest.replace("_signed-1", "_signed-2");
    await expect(
      parseRequest(
        { query: {}, body: { SAMLRequest: postEncode(tampered) } },
        { signingCert: sp1Cert },
      ),
    ).rejects.toThrow(/Signature check errors/);
  });

  it("rejects a signature that is not a direct child of the root (wrapping)", async () => {
    const evil = authnRequest({ id: "_evil", issuer: ISSUER }).replace(
      "</samlp:AuthnRequest>",
      `<samlp:Extensions>${signedRequest}</samlp:Extensions></samlp:AuthnRequest>`,
    );
    await expect(
      parseRequest(
        { query: {}, body: { SAMLRequest: postEncode(evil) } },
        { signingCert: sp1Cert },
      ),
    ).rejects.toThrow();
  });
});

describe("signed AuthnRequest (HTTP-Redirect, detached signature)", () => {
  const sigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const encoded = redirectEncode(request);

  function signedQuery(relayState?: string, key: Buffer = sp1Key) {
    const params: Record<string, string> = { SAMLRequest: encoded };
    if (relayState) params.RelayState = relayState;
    params.SigAlg = sigAlg;
    const Signature = sign({ key }, qs.stringify(params));
    return { ...params, Signature };
  }

  it("accepts a valid signature (with and without RelayState)", async () => {
    for (const relay of [undefined, "relay"]) {
      const query = signedQuery(relay);
      const data = await parseRequest({ query, body: {} }, { signingCert: sp1Cert });
      expect(data?.id).toBe("_signed-1");
    }
  });

  it("rejects an invalid signature", async () => {
    const query = signedQuery("relay", sp2Key);
    await expect(parseRequest({ query, body: {} }, { signingCert: sp1Cert })).rejects.toThrow();
    const wrongKey = signedQuery("relay");
    await expect(
      parseRequest(
        { query: { ...wrongKey, RelayState: "other" }, body: {} },
        { signingCert: sp1Cert },
      ),
    ).rejects.toThrow(/does not match/);
  });

  it("rejects a missing or unsupported SigAlg", async () => {
    const query = signedQuery("relay");
    await expect(
      parseRequest({ query: { ...query, SigAlg: undefined }, body: {} }, { signingCert: sp1Cert }),
    ).rejects.toThrow(/Signature Algorithm is missing/);
    await expect(
      parseRequest(
        { query: { ...query, SigAlg: "http://evil/alg#md5" }, body: {} },
        { signingCert: sp1Cert },
      ),
    ).rejects.toThrow(/Invalid signature algorithm/);
  });
});

describe("logout with session participants that sign their messages", () => {
  const nameId = "foo@example.com";
  const participant = (cert?: Buffer) => ({
    serviceProviderId: ISSUER,
    nameId,
    sessionIndex: "1",
    serviceProviderLogoutURL: `${ISSUER}/logout`,
    cert,
  });
  const logoutXml =
    `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="_l1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>${ISSUER}</saml:Issuer>` +
    `<saml:NameID>${nameId}</saml:NameID><samlp:SessionIndex>1</samlp:SessionIndex></samlp:LogoutRequest>`;
  const base = () => {
    const session = new Session("s", new SessionStore());
    return {
      issuer: "urn:idp",
      cert: idpCert,
      key: idpKey,
      store: createLogoutStore(session) as LogoutStore,
    };
  };

  it("validates the signature of the LogoutRequest", async () => {
    const signed = signXml(
      { key: sp1Key, cert: sp1Cert, reference: "//*[local-name(.)='LogoutRequest']" },
      logoutXml,
    );
    const result = await logout(
      { query: {}, body: { SAMLRequest: postEncode(signed) } },
      { ...base(), sessionParticipants: new SessionParticipants([participant(sp1Cert)]) },
    );
    expect(result.type).toBe("post");
    if (result.type === "post") expect(result.field).toBe("SAMLResponse");
  });

  it("rejects an unsigned LogoutRequest when the participant has a certificate", async () => {
    await expect(
      logout(
        { query: {}, body: { SAMLRequest: postEncode(logoutXml) } },
        { ...base(), sessionParticipants: new SessionParticipants([participant(sp1Cert)]) },
      ),
    ).rejects.toThrow(/MUST be signed/);
  });

  it("can use the HTTP-Redirect binding with deflate and a detached signature", async () => {
    const idpInitiated = await logout(
      { query: {}, body: {} },
      {
        ...base(),
        sessionParticipants: new SessionParticipants([participant()]),
        protocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        deflate: true,
      },
    );
    expect(idpInitiated.type).toBe("redirect");
    if (idpInitiated.type !== "redirect") return;
    const url = new URL(idpInitiated.url);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/logout`);
    expect(url.searchParams.get("SigAlg")).toBe(
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    );
    expect(url.searchParams.get("Signature")).toBeTruthy();
    expect(url.searchParams.get("SAMLRequest")).toBeTruthy();
  });
});
