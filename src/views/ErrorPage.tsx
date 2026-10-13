import type { FC } from 'hono/jsx';
import { Layout } from './Layout.js';

export interface ErrorPageProps {
  message: string;
  status?: number;
  stack?: string;
  issuer?: string;
}

export const ErrorPage: FC<ErrorPageProps> = ({ message, status, stack, issuer }) => (
  <Layout issuer={issuer}>
    <div id="container">
      <h1>{message}</h1>
      {status ? <h2>{status}</h2> : null}
      {stack ? <pre>{stack}</pre> : null}
      <div class="actions">
        <form action="/" method="get">
          <button id="btn-return" class="btn primary" type="submit">
            Restart
          </button>
        </form>
      </div>
    </div>
  </Layout>
);
