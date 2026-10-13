// Ported from mcguinness/node-samlp (MIT, see ./LICENSE): claims/PassportProfileMapper.
import type { Attributes } from '../saml/saml20.js';

export interface ClaimMetadata {
  id: string;
  optional?: boolean;
  displayName: string;
  description?: string;
  multiValue?: boolean;
  options?: string[];
}

export interface NameIdentifier {
  nameIdentifier?: string;
  nameIdentifierFormat?: string;
  nameIdentifierNameQualifier?: string;
  nameIdentifierSPNameQualifier?: string;
  nameIdentifierSPProvidedID?: string;
}

/** Maps an application user profile to SAML claims and a NameID. */
export interface ProfileMapper<TUser = any> {
  /** Claims advertised in the IdP metadata. */
  metadata: ClaimMetadata[];
  getClaims(user: TUser): Attributes | undefined;
  getNameIdentifier(user: TUser): NameIdentifier;
}

const fm = {
  nameIdentifier: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
  email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  givenname: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  surname: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
};

interface PassportUser {
  id?: string;
  emails?: Array<{ value?: string }>;
  displayName?: string;
  name?: { givenName?: string; familyName?: string };
  [key: string]: unknown;
}

const DONT_REMAP = ['emails', 'displayName', 'name', 'id', '_json'];

/** Default mapper: maps a Passport.js user profile to WS-Federation style claims. */
export const passportProfileMapper: ProfileMapper<PassportUser> = {
  metadata: [
    { id: fm.email, optional: true, displayName: 'E-Mail Address', description: 'The e-mail address of the user' },
    { id: fm.givenname, optional: true, displayName: 'Given Name', description: 'The given name of the user' },
    { id: fm.name, optional: true, displayName: 'Name', description: 'The unique name of the user' },
    { id: fm.surname, optional: true, displayName: 'Surname', description: 'The surname of the user' },
    { id: fm.nameIdentifier, optional: true, displayName: 'Name ID', description: 'The SAML name identifier of the user' },
  ],

  getClaims(pu) {
    const claims: Attributes = {};
    claims[fm.nameIdentifier] = pu.id;
    claims[fm.email] = pu.emails?.[0]?.value;
    claims[fm.name] = pu.displayName;
    claims[fm.givenname] = pu.name?.givenName;
    claims[fm.surname] = pu.name?.familyName;

    for (const key of Object.keys(pu)) {
      if (!DONT_REMAP.includes(key)) {
        claims['http://schemas.passportjs.com/' + key] = pu[key] as Attributes[string];
      }
    }
    return claims;
  },

  getNameIdentifier(pu) {
    const claims = this.getClaims(pu) ?? {};
    return {
      nameIdentifier: (claims[fm.nameIdentifier] || claims[fm.name] || claims[fm.email]) as
        | string
        | undefined,
    };
  },
};
