// Replaces the EJS templates of mcguinness/node-samlp (MIT, see ./LICENSE)
// with typed template-literal functions. All interpolated values are escaped.
import { escapeXml as esc } from '../saml/utils.js';

export interface SamlResponseData {
  id: string;
  instant: string;
  destination?: string;
  inResponseTo?: string;
  issuer: string;
  samlStatusCode: string;
  samlStatusMessage?: string;
  /** Raw (already serialized) assertion XML. */
  assertion?: string;
}

export function samlResponse(data: SamlResponseData): string {
  return (
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${esc(data.id)}"` +
    (data.inResponseTo ? ` InResponseTo="${esc(data.inResponseTo)}"` : '') +
    ` Version="2.0" IssueInstant="${esc(data.instant)}"` +
    (data.destination ? ` Destination="${esc(data.destination)}"` : '') +
    `>` +
    `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${esc(data.issuer)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${esc(data.samlStatusCode)}"/>` +
    (data.samlStatusMessage
      ? `<samlp:StatusMessage Value="${esc(data.samlStatusMessage)}"/>`
      : '') +
    `</samlp:Status>` +
    (data.assertion ?? '') +
    `</samlp:Response>`
  );
}

export interface LogoutResponseData {
  id: string;
  instant: string;
  destination?: string;
  inResponseTo?: string;
  issuer: string;
  samlStatusCode: string;
  samlStatusMessage?: string;
}

export function logoutResponse(data: LogoutResponseData): string {
  return (
    `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${esc(data.id)}"` +
    (data.inResponseTo ? ` InResponseTo="${esc(data.inResponseTo)}"` : '') +
    ` Version="2.0" IssueInstant="${esc(data.instant)}"` +
    (data.destination ? ` Destination="${esc(data.destination)}"` : '') +
    `>` +
    `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${esc(data.issuer)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${esc(data.samlStatusCode)}"/>` +
    (data.samlStatusMessage
      ? `<samlp:StatusMessage>${esc(data.samlStatusMessage)}</samlp:StatusMessage>`
      : '') +
    `</samlp:Status></samlp:LogoutResponse>`
  );
}

export interface LogoutRequestData {
  ID: string;
  IssueInstant: string;
  Issuer: string;
  Destination?: string;
  NameID: {
    value?: string;
    Format?: string;
    NameQualifier?: string;
    SPNameQualifier?: string;
    SPProvidedID?: string;
  };
  SessionIndex?: string;
}

export function logoutRequest(data: LogoutRequestData): string {
  const nameId = data.NameID;
  return (
    `<samlp:LogoutRequest ID="_${esc(data.ID)}" Version="2.0" IssueInstant="${esc(data.IssueInstant)}"` +
    (data.Destination ? ` Destination="${esc(data.Destination)}"` : '') +
    ` Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"` +
    ` xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
    `<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">${esc(data.Issuer)}</Issuer>` +
    `<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"` +
    (nameId.NameQualifier ? ` NameQualifier="${esc(nameId.NameQualifier)}"` : '') +
    (nameId.SPNameQualifier ? ` SPNameQualifier="${esc(nameId.SPNameQualifier)}"` : '') +
    (nameId.Format ? ` Format="${esc(nameId.Format)}"` : '') +
    (nameId.SPProvidedID ? ` SPProvidedID="${esc(nameId.SPProvidedID)}"` : '') +
    `>${esc(nameId.value)}</NameID>` +
    (data.SessionIndex ? `<samlp:SessionIndex>${esc(data.SessionIndex)}</samlp:SessionIndex>` : '') +
    `</samlp:LogoutRequest>`
  );
}

export interface MetadataData {
  issuer: string;
  pem: string;
  redirectEndpoint: string;
  postEndpoint: string;
  logoutEndpoints: { redirect?: string; post?: string };
  claimTypes: Array<{ id: string; displayName: string }>;
}

export function metadata(data: MetadataData): string {
  const lines = [
    `<EntityDescriptor entityID="${esc(data.issuer)}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">`,
    `  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`,
    `    <KeyDescriptor use="signing">`,
    `      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`,
    `        <X509Data>`,
    `          <X509Certificate>${esc(data.pem)}</X509Certificate>`,
    `        </X509Data>`,
    `      </KeyInfo>`,
    `    </KeyDescriptor>`,
  ];
  if (data.logoutEndpoints.redirect) {
    lines.push(
      `    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${esc(data.logoutEndpoints.redirect)}"/>`,
    );
  }
  if (data.logoutEndpoints.post) {
    lines.push(
      `    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${esc(data.logoutEndpoints.post)}"/>`,
    );
  }
  lines.push(
    `    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>`,
    `    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>`,
    `    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>`,
    `    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${esc(data.redirectEndpoint)}"/>`,
    `    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${esc(data.postEndpoint)}"/>`,
  );
  for (const ct of data.claimTypes) {
    lines.push(
      `    <Attribute Name="${esc(ct.id)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="${esc(ct.displayName)}" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>`,
    );
  }
  lines.push(`  </IDPSSODescriptor>`, `</EntityDescriptor>`);
  return lines.join('\n');
}
