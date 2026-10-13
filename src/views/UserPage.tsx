import type { FC } from 'hono/jsx';
import type { UserProfile } from '../default-config.js';
import { IDP_PATHS, type IdpSettings } from '../state.js';
import type { ClaimMetadata } from '../vendor/samlp/index.js';
import { Layout } from './Layout.js';

export interface AuthnRequestInfo {
  relayState?: string;
  id?: string;
  issuer?: string;
  destination?: string;
  acsUrl?: string;
  forceAuthn?: boolean;
}

export interface UserPageProps {
  user: UserProfile;
  sessionIndex?: string;
  metadata: ClaimMetadata[];
  authnRequest?: AuthnRequestInfo;
  idp: IdpSettings;
}

const NAME_ID_FORMATS = [
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
];

const StaticRow: FC<{ id: string; label: string; value?: string | boolean }> = ({ id, label, value }) => (
  <div class="row">
    <span class="label">{label}</span>
    <div class="field">
      <p class="static" id={id}>
        {String(value)}
      </p>
    </div>
  </div>
);

const AuthnRequestPanel: FC<{ authnRequest: AuthnRequestInfo }> = ({ authnRequest }) => (
  <details class="panel primary" id="authn-request">
    <summary>SAML Authentication Request</summary>
    <div class="panel-body">
      <StaticRow id="requestId" label="Request ID" value={authnRequest.id} />
      <StaticRow id="issuer" label="Issuer" value={authnRequest.issuer} />
      {authnRequest.destination ? (
        <StaticRow id="destination" label="Destination" value={authnRequest.destination} />
      ) : null}
      {authnRequest.acsUrl ? <StaticRow id="acsUrl" label="ACS URL" value={authnRequest.acsUrl} /> : null}
      {authnRequest.forceAuthn ? (
        <StaticRow id="forceAuthn" label="ForceAuthn" value={authnRequest.forceAuthn} />
      ) : null}
      {authnRequest.relayState ? (
        <StaticRow id="relayState" label="Relay State" value={authnRequest.relayState} />
      ) : null}
    </div>
  </details>
);

const AttributeField: FC<{ entry: ClaimMetadata; value?: string }> = ({ entry, value }) => (
  <div class="row">
    <label for={entry.id}>{entry.displayName}</label>
    <div class="field">
      {entry.options ? (
        <select id={entry.id} name={entry.id}>
          {entry.options.map((option) => (
            <option value={option} selected={option === value}>
              {option}
            </option>
          ))}
        </select>
      ) : (
        <input id={entry.id} name={entry.id} type="text" placeholder="Attribute value" value={value ?? ''} />
      )}
      {entry.multiValue ? <p class="hint">Multiple values are separated by commas</p> : null}
    </div>
  </div>
);

export const UserPage: FC<UserPageProps> = ({ user, sessionIndex, metadata, authnRequest, idp }) => (
  <Layout issuer={idp.issuer}>
    {authnRequest?.id ? <AuthnRequestPanel authnRequest={authnRequest} /> : null}

    <form action={IDP_PATHS.SIGN_IN} method="post">
      <div class="panel primary">
        <h3>SAML Assertion</h3>
        <div class="panel-body">
          <div class="row">
            <label for="userName">Subject NameID</label>
            <div class="field">
              <input id="userName" name="userName" placeholder="user@example.com" required value={user.userName} />
            </div>
          </div>
          <details>
            <summary>More Options</summary>
            <div class="row">
              <label for="nameIdFormat">Name ID Format</label>
              <div class="field">
                <select id="nameIdFormat" name="nameIdFormat">
                  {NAME_ID_FORMATS.map((format) => (
                    <option value={format} selected={format === user.nameIdFormat}>
                      {format}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div class="row">
              <label for="nameIdNameQualifier">Name Qualifier</label>
              <div class="field">
                <input id="nameIdNameQualifier" name="nameIdNameQualifier" type="text" value={user.nameIdNameQualifier ?? ''} />
              </div>
            </div>
            <div class="row">
              <label for="nameIdSPNameQualifier">Service Provider Name Qualifier</label>
              <div class="field">
                <input id="nameIdSPNameQualifier" name="nameIdSPNameQualifier" type="text" value={user.nameIdSPNameQualifier ?? ''} />
              </div>
            </div>
            <div class="row">
              <label for="nameIdSPProvidedID">Service Provider Provided ID</label>
              <div class="field">
                <input id="nameIdSPProvidedID" name="nameIdSPProvidedID" type="text" value={user.nameIdSPProvidedID ?? ''} />
              </div>
            </div>
          </details>
        </div>
      </div>

      <details class="panel">
        <summary>Authentication Statement</summary>
        <div class="panel-body">
          <StaticRow id="sessionIndex" label="Session Index" value={sessionIndex} />
          <StaticRow id="authnContextClassRef" label="Authentication Context Class" value={idp.authnContextClassRef} />
        </div>
      </details>

      <div class="panel">
        <h3>Attribute Statements</h3>
        <div class="panel-body">
          {metadata.map((entry) => (
            <AttributeField entry={entry} value={user[entry.id]} />
          ))}
        </div>
      </div>

      {authnRequest?.id ? (
        <input
          name="_authnRequest"
          type="hidden"
          value={Buffer.from(JSON.stringify(authnRequest)).toString('base64')}
        />
      ) : null}

      <div class="actions">
        <a id="btn-sign-out" class="btn" href={IDP_PATHS.SIGN_OUT}>
          Sign out
        </a>
        <button id="btn-sign-in" class="btn primary" type="submit">
          Sign in
        </button>
      </div>
    </form>
  </Layout>
);
