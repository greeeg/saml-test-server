// Vendored and modernized copy of mcguinness/node-samlp (MIT, see ./LICENSE).
export {
  authenticate,
  buildSamlResponse,
  createErrorResponse,
  createSamlResponse,
  parseRequest,
  SamlpError,
} from './auth.js';
export type {
  AuthnRequestData,
  AuthOptions,
  AuthResult,
  ErrorResponseOptions,
  PostForm,
  ResponseOptions,
} from './auth.js';
export { logout, createLogoutError } from './logout.js';
export type { LogoutErrorOptions, LogoutOptions, LogoutResult, LogoutState, LogoutStore } from './logout.js';
export { buildMetadata } from './metadata.js';
export type { MetadataOptions } from './metadata.js';
export { SessionParticipants } from './session-participants.js';
export type { SessionParticipant } from './session-participants.js';
export { passportProfileMapper } from './profile-mapper.js';
export type { ClaimMetadata, NameIdentifier, ProfileMapper } from './profile-mapper.js';
export { BINDINGS, STATUS } from './constants.js';
export { thumbprint, removeHeaders } from './encoders.js';
export type { SamlHttpInput, ParseRequestOptions } from './utils.js';
export type { Attributes, AttributeValue } from '../saml/saml20.js';
