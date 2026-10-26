// Ported from saml-idp/lib/simpleProfileMapper.js (MIT, see ../LICENSE).
import type { Attributes, ClaimMetadata, ProfileMapper } from "./vendor/samlp/index.js";

type User = Record<string, string | undefined>;

/**
 * Maps the flat user profile to SAML attributes using the attribute metadata:
 * each metadata entry is an attribute; multi-value attributes are comma separated.
 *
 * `getMetadata` is called on every use so edits to the metadata at runtime are honored.
 */
export function createSimpleProfileMapper(getMetadata: () => ClaimMetadata[]): ProfileMapper<User> {
  return {
    get metadata() {
      return getMetadata();
    },

    getClaims(user) {
      const claims: Attributes = {};
      for (const entry of getMetadata()) {
        const value = user[entry.id];
        claims[entry.id] = entry.multiValue
          ? (value ?? "")
              .split(",")
              .map((v) => v.trim())
              .filter((v) => v !== "")
          : value;
      }
      return Object.keys(claims).length ? claims : undefined;
    },

    getNameIdentifier(user) {
      return {
        nameIdentifier: user.userName,
        nameIdentifierFormat: user.nameIdFormat,
        nameIdentifierNameQualifier: user.nameIdNameQualifier || undefined,
        nameIdentifierSPNameQualifier: user.nameIdSPNameQualifier || undefined,
        nameIdentifierSPProvidedID: user.nameIdSPProvidedID || undefined,
      };
    },
  };
}
