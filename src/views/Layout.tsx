import { raw } from "hono/html";
import type { FC, PropsWithChildren } from "hono/jsx";
import { IDP_PATHS } from "../state.js";

const STYLES = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: "Lato", "Helvetica Neue", Helvetica, Arial, sans-serif; font-size: 14px; color: #2c3e50; background: #f5f7f9; }
  nav { background: #2d3f50; color: #ecf0f1; display: flex; align-items: center; justify-content: space-between; padding: 12px 24px; }
  nav a { color: #ecf0f1; text-decoration: none; margin-left: 20px; }
  nav a.brand { margin-left: 0; font-size: 16px; font-weight: 600; }
  main { max-width: 820px; margin: 24px auto; padding: 0 16px; }
  .panel { background: #fff; border: 1px solid #d9e0e6; border-radius: 4px; margin-bottom: 20px; }
  .panel > h3, .panel > summary { margin: 0; padding: 10px 16px; font-size: 15px; font-weight: 600; background: #eef2f5; border-bottom: 1px solid #d9e0e6; cursor: default; }
  .panel.primary > h3, .panel.primary > summary { background: #2d3f50; color: #ecf0f1; }
  .panel > summary { cursor: pointer; }
  .panel-body { padding: 16px; }
  .row { display: flex; align-items: flex-start; margin-bottom: 12px; gap: 12px; }
  .row > label, .row > .label { flex: 0 0 200px; padding-top: 7px; font-weight: 600; }
  .row > .field { flex: 1; min-width: 0; }
  .static { padding-top: 7px; overflow-wrap: anywhere; }
  input, select { width: 100%; padding: 6px 10px; border: 1px solid #c3ccd4; border-radius: 4px; font: inherit; }
  .hint { color: #7b8a97; font-size: 12px; margin: 4px 0 0; }
  .actions { display: flex; justify-content: flex-end; gap: 10px; }
  .btn { display: inline-block; padding: 7px 16px; border: 1px solid #c3ccd4; border-radius: 4px; background: #fff; color: #2c3e50; font: inherit; text-decoration: none; cursor: pointer; }
  .btn.primary { background: #2d3f50; border-color: #2d3f50; color: #fff; }
  pre { white-space: pre-wrap; word-break: break-word; }
`;

export const Layout: FC<PropsWithChildren<{ issuer?: string }>> = ({ issuer, children }) => (
  <>
    {raw("<!DOCTYPE html>")}
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Simple Identity Provider</title>
        <style>{raw(STYLES)}</style>
      </head>
      <body>
        <nav>
          <a class="brand" href={IDP_PATHS.METADATA}>
            Simple SAML Identity Provider{issuer ? ` (${issuer})` : ""}
          </a>
          <div>
            <a href={IDP_PATHS.METADATA}>IdP Metadata</a>
            <a href={IDP_PATHS.SIGN_OUT}>New Session</a>
            <a href={IDP_PATHS.SETTINGS}>Settings</a>
          </div>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  </>
);
