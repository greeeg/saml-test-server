import type { FC, PropsWithChildren } from 'hono/jsx';
import type { IdpSettings } from '../state.js';
import { Layout } from './Layout.js';

const AUTHN_CONTEXT_CLASSES = [
  'InternetProtocol',
  'InternetProtocolPassword',
  'Kerberos',
  'MobileOneFactorUnregistered',
  'MobileTwoFactorUnregistered',
  'MobileOneFactorContract',
  'MobileTwoFactorContract',
  'Password',
  'PasswordProtectedTransport',
  'PreviousSession',
  'X509',
  'PGP',
  'SPKI',
  'XMLDSig',
  'Smartcard',
  'SmartcardPKI',
  'SoftwarePKI',
  'Telephony',
  'NomadTelephony',
  'PersonalTelephony',
  'AuthenticatedTelephony',
  'SecureRemotePassword',
  'TLSClient',
  'TimeSyncToken',
  'unspecified',
].map((name) => ({ value: `urn:oasis:names:tc:SAML:2.0:ac:classes:${name}`, label: name }));

const Row: FC<PropsWithChildren<{ id: string; label: string }>> = ({ id, label, children }) => (
  <div class="row">
    <label for={id}>{label}</label>
    <div class="field">{children}</div>
  </div>
);

const Select: FC<{
  id: string;
  name?: string;
  selected: unknown;
  options: Array<{ value: string; label: string }>;
}> = ({ id, name, selected, options }) => (
  <select id={id} name={name ?? id}>
    {options.map((o) => (
      <option value={o.value} selected={o.value === String(selected)}>
        {o.label}
      </option>
    ))}
  </select>
);

const YES_NO = [
  { value: 'true', label: 'Yes' },
  { value: 'false', label: 'No' },
];

export const SettingsPage: FC<{ idp: IdpSettings }> = ({ idp }) => (
  <Layout issuer={idp.issuer}>
    <form id="settings" method="post">
      <div class="panel">
        <h3>Identity Provider Settings</h3>
        <div class="panel-body">
          <Row id="issuer" label="Issuer">
            <input id="issuer" name="issuer" type="text" required value={idp.issuer} />
          </Row>
          <Row id="signatureAlgorithm" label="Signature Algorithm">
            <Select
              id="signatureAlgorithm"
              selected={idp.signatureAlgorithm}
              options={[
                { value: 'rsa-sha1', label: 'RSA-SHA1' },
                { value: 'rsa-sha256', label: 'RSA-SHA256' },
              ]}
            />
          </Row>
          <Row id="digestAlgorithm" label="Digest Algorithm">
            <Select
              id="digestAlgorithm"
              selected={idp.digestAlgorithm}
              options={[
                { value: 'sha1', label: 'SHA1' },
                { value: 'sha256', label: 'SHA256' },
              ]}
            />
          </Row>
          <Row id="signResponse" label="Sign Response">
            <Select id="signResponse" selected={idp.signResponse} options={YES_NO} />
          </Row>
          <Row id="lifetimeInSeconds" label="Assertion Lifetime Seconds">
            <input id="lifetimeInSeconds" name="lifetimeInSeconds" type="number" required value={idp.lifetimeInSeconds} />
          </Row>
          <Row id="authnContextClassRef" label="Authentication Context Class">
            <Select
              id="authnContextClassRef"
              selected={idp.authnContextClassRef}
              options={AUTHN_CONTEXT_CLASSES}
            />
          </Row>
          <Row id="allowRequestAcsUrl" label="Allow Dynamic Assertion Consumer Service URL">
            <Select id="allowRequestAcsUrl" selected={idp.allowRequestAcsUrl} options={YES_NO} />
          </Row>
        </div>
      </div>

      <div class="panel">
        <h3>Service Provider Settings</h3>
        <div class="panel-body">
          <Row id="serviceProviderId" label="Issuer URI">
            <input id="serviceProviderId" name="serviceProviderId" type="text" required value={idp.serviceProviderId} />
          </Row>
          <Row id="sloUrl" label="Single Logout URL">
            <input id="sloUrl" name="sloUrl" type="url" value={idp.sloUrl ?? ''} />
          </Row>
          <Row id="acsUrl" label="Assertion Consumer Service URL">
            <input id="acsUrl" name="acsUrl" type="url" required value={idp.acsUrl} />
          </Row>
          <Row id="destination" label="Destination">
            <input id="destination" name="destination" type="url" required value={idp.destination} />
          </Row>
          <Row id="recipient" label="Recipient">
            <input id="recipient" name="recipient" type="url" required value={idp.recipient} />
          </Row>
          <Row id="audience" label="Audience">
            <input id="audience" name="audience" type="text" required value={idp.audience} />
          </Row>
          <Row id="relayState" label="Default Relay State">
            <input id="relayState" name="RelayState" type="text" value={idp.RelayState ?? ''} />
          </Row>
        </div>
      </div>

      <div class="actions">
        <a href="/" class="btn">
          Cancel
        </a>
        <button type="submit" class="btn primary">
          Save
        </button>
      </div>
    </form>
  </Layout>
);
