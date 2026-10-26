import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpsRequest } from "node:https";
import { createPrivateKey, createSign, createVerify } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OptionsError, runServer, type RunningIdp } from "../src/index.js";
import { resolveOptions } from "../src/options.js";
import { idpCert, idpKey, parse, text } from "./helpers.js";

let running: RunningIdp | undefined;
afterEach(async () => {
  await running?.close();
  running = undefined;
});

const base = {
  acsUrl: "https://sp.example.com/acs",
  audience: "urn:sp",
  logLevel: "silent" as const,
  port: 0,
};

describe("runServer", () => {
  it("listens on a free port and serves requests", async () => {
    running = await runServer(base);
    expect(running.url).toMatch(/^http:\/\/localhost:\d+$/);

    const res = await fetch(running.metadataUrl);
    expect(res.status).toBe(200);
    expect(text("/*/@entityID", parse(await res.text()))).toBe("urn:example:idp");
  });

  it("runs a full SSO round trip over the network, with cookies", async () => {
    running = await runServer(base);
    const page = await fetch(running.url + "/");
    const cookie = page.headers.get("set-cookie")!.split(";")[0];
    const res = await fetch(running.url + "/signin", {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ userName: "net@example.com" }),
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('name="SAMLResponse"');
  });

  it("exposes the state so tests can override the user", async () => {
    running = await runServer(base);
    running.state.user.userName = "override@example.com";
    const res = await fetch(running.url + "/signin", { method: "POST" });
    const html = await res.text();
    const b64 = /name="SAMLResponse" value="([^"]+)"/.exec(html)![1];
    expect(text('//*[local-name()="NameID"]', parse(Buffer.from(b64, "base64").toString()))).toBe(
      "override@example.com",
    );
  });

  it("closes the server", async () => {
    running = await runServer(base);
    const { url } = running;
    await running.close();
    running = undefined;
    await expect(fetch(url + "/metadata")).rejects.toThrow();
  });

  it("serves HTTPS when enabled", async () => {
    running = await runServer({
      ...base,
      https: true,
      httpsPrivateKey: idpKey.toString(),
      httpsCert: idpCert.toString(),
    });
    expect(running.url).toMatch(/^https:\/\//);
    const body = await new Promise<string>((resolve, reject) => {
      httpsRequest(running!.metadataUrl, { rejectUnauthorized: false }, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data));
      })
        .on("error", reject)
        .end();
    });
    expect(body).toContain("EntityDescriptor");
  });

  it("fails when the port is in use", async () => {
    running = await runServer(base);
    const port = Number(new URL(running.url).port);
    await expect(runServer({ ...base, port })).rejects.toThrow(/EADDRINUSE/);
  });
});

describe("option validation", () => {
  it("requires acsUrl and audience", async () => {
    await expect(resolveOptions({ audience: "x" } as any)).rejects.toThrow(OptionsError);
    await expect(resolveOptions({ acsUrl: "x" } as any)).rejects.toThrow(/audience/);
  });

  it("requires an encryption certificate to encrypt", async () => {
    await expect(resolveOptions({ ...base, encryptAssertion: true })).rejects.toThrow(
      /encryptionCert/,
    );
  });

  it("requires TLS material for https", async () => {
    await expect(resolveOptions({ ...base, https: true })).rejects.toThrow(/httpsPrivateKey/);
  });

  it("rejects invalid certificates and unknown paths", async () => {
    await expect(resolveOptions({ ...base, cert: "not a cert" })).rejects.toThrow(
      /Invalid \/ missing/,
    );
    await expect(resolveOptions({ ...base, configFile: "./nope.js" })).rejects.toThrow(
      /not a valid path/,
    );
    await expect(resolveOptions({ ...base, authnContextDecl: "./nope.xml" })).rejects.toThrow(
      /not found/,
    );
  });

  it("applies the documented defaults", async () => {
    const options = await resolveOptions({ acsUrl: "a", audience: "b" });
    expect(options).toMatchObject({
      host: "localhost",
      port: 7000,
      issuer: "urn:example:idp",
      serviceProviderId: "b",
      signResponse: true,
      https: false,
      rollSession: false,
      disableRequestAcsUrl: false,
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    });
    expect(options.cert).toContain("BEGIN CERTIFICATE");
    expect(options.key).toContain("PRIVATE KEY");
  });

  it("loads files through relative paths and the saml-idp/ prefix", async () => {
    const options = await resolveOptions({
      acsUrl: "a",
      audience: "b",
      cert: "assets/idp-public-cert.pem",
      key: "saml-idp/assets/idp-private-key.pem",
    });
    expect(options.cert).toBe(idpCert.toString());
    expect(options.key).toBe(idpKey.toString());
  });

  it("loads user and metadata from .mjs and .json config files", async () => {
    const dir = mkdtempSync(join(tmpdir(), "saml-idp-"));
    const config = {
      user: { userName: "file@example.com" },
      metadata: [{ id: "email", displayName: "Email" }],
    };
    writeFileSync(join(dir, "config.mjs"), "export default " + JSON.stringify(config));
    writeFileSync(join(dir, "config.json"), JSON.stringify(config));
    for (const file of ["config.mjs", "config.json"]) {
      const options = await resolveOptions({
        acsUrl: "a",
        audience: "b",
        configFile: join(dir, file),
      });
      expect(options.config.user.userName).toBe("file@example.com");
      expect(options.config.metadata).toEqual(config.metadata);
      // defaults are kept for the fields the file does not set
      expect(options.config.user.nameIdFormat).toContain("nameid-format");
    }
  });

  it("accepts PKCS#8 private keys", async () => {
    const pkcs8 = createPrivateKey(idpKey).export({ type: "pkcs8", format: "pem" }).toString();
    expect(pkcs8).toContain("BEGIN PRIVATE KEY");
    const options = await resolveOptions({ acsUrl: "a", audience: "b", key: pkcs8 });
    const signature = createSign("RSA-SHA256").update("x").sign(options.key);
    expect(createVerify("RSA-SHA256").update("x").verify(idpCert, signature)).toBe(true);
  });
});

describe("logLevel", () => {
  const spyOnConsole = () => {
    const calls: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((...a) => void calls.push(a.join(" ")));
    const error = vi
      .spyOn(console, "error")
      .mockImplementation((...a) => void calls.push(a.join(" ")));
    return { calls, restore: () => (log.mockRestore(), error.mockRestore()) };
  };

  const run = async (options: Record<string, unknown>) => {
    const spy = spyOnConsole();
    try {
      running = await runServer({ ...base, logLevel: undefined, ...options } as any);
      await fetch(running.url + "/");
      // a sign in without a NameID is an unexpected (5xx) failure
      running.state.user.userName = "";
      await fetch(running.url + "/signin", { method: "POST" });
      return spy.calls.join("\n");
    } finally {
      spy.restore();
    }
  };

  it("logs banners and requests at info (default)", async () => {
    const output = await run({ logLevel: "info" });
    expect(output).toContain("IdP server ready at");
    expect(output).toContain("GET /");
    expect(output).toContain("nameIdentifier");
  });

  it("logs nothing at 'silent'", async () => {
    expect(await run({ logLevel: "silent" })).toBe("");
  });

  it("logs only unexpected errors at 'error'", async () => {
    const output = await run({ logLevel: "error" });
    expect(output).not.toContain("IdP server ready at");
    expect(output).not.toContain("GET /");
    expect(output).toContain("nameIdentifier");
  });

  it("keeps supporting the deprecated 'silent' flag and the env var", async () => {
    expect(await run({ silent: true })).toBe("");
    vi.stubEnv("SAML_IDP_LOG_LEVEL", "silent");
    try {
      expect(await run({})).toBe("");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("rejects unknown levels", async () => {
    await expect(resolveOptions({ ...base, logLevel: "verbose" as any })).rejects.toThrow(
      /Invalid logLevel/,
    );
  });
});
