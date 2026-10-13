import { raw } from 'hono/html';
import type { FC } from 'hono/jsx';

export interface AutoPostFormProps {
  /** Form action (ACS / SLO URL of the Service Provider). */
  url: string;
  /** Name of the hidden field carrying the SAML message. */
  field: string;
  /** Base64 encoded SAML message. */
  value: string;
  relayState?: string;
}

/** Page that immediately POSTs a SAML message to the Service Provider (HTTP-POST binding). */
export const AutoPostForm: FC<AutoPostFormProps> = ({ url, field, value, relayState }) => (
  <>
    {raw('<!DOCTYPE html>')}
    <html>
      <head>
        <title>Keep Calm and Single Sign-On!</title>
      </head>
      <body>
        <form method="post" name="hiddenform" action={url}>
          <input type="hidden" name={field} value={value} />
          <input type="hidden" name="RelayState" value={relayState ?? ''} />
          <noscript>
            <p>JavaScript is disabled. Click Submit to continue.</p>
            <input type="submit" value="Submit" />
          </noscript>
        </form>
        <script>{raw('window.setTimeout(function(){document.forms[0].submit();}, 0);')}</script>
      </body>
    </html>
  </>
);
