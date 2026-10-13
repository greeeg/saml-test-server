// Entry of `npm run dev` (Vite + @hono/vite-dev-server). Configure through env vars:
//   SAML_ACS_URL, SAML_AUDIENCE, SAML_SLO_URL
import { createIdp } from './index.js';

const { app } = await createIdp({
  acsUrl: process.env.SAML_ACS_URL ?? 'http://localhost:3000/auth/saml/callback',
  audience: process.env.SAML_AUDIENCE ?? 'urn:example:sp',
  sloUrl: process.env.SAML_SLO_URL,
});

export default app;
