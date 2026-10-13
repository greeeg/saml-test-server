import { randomBytes } from 'node:crypto';
import type { MiddlewareHandler } from 'hono';
import { deleteCookie, getSignedCookie, setSignedCookie } from 'hono/cookie';
import type { LogoutStore } from './vendor/samlp/index.js';

export const SESSION_COOKIE = 'idp_sid';
const MAX_AGE_SECONDS = 60 * 60;

/** Server-side session of the browser (identified by a signed cookie). */
export class Session {
  id: string;
  /** Arbitrary per-session data. */
  data: Record<string, any> = {};
  destroyed = false;

  constructor(
    id: string,
    private readonly store: SessionStore,
  ) {
    this.id = id;
  }

  /** Destroys the session. The cookie is cleared at the end of the request. */
  destroy(): void {
    this.destroyed = true;
    this.store.delete(this.id);
  }

  /** Replaces the session id (and drops the data), like express-session's `regenerate()`. */
  regenerate(): void {
    this.store.delete(this.id);
    this.id = randomBytes(24).toString('hex');
    this.data = {};
    this.destroyed = false;
    this.store.set(this);
  }
}

interface Entry {
  session: Session;
  expires: number;
}

/** In-memory session store with a sliding 1 hour TTL. */
export class SessionStore {
  private readonly entries = new Map<string, Entry>();

  create(): Session {
    const session = new Session(randomBytes(24).toString('hex'), this);
    this.set(session);
    return session;
  }

  get(id: string): Session | undefined {
    const entry = this.entries.get(id);
    if (!entry) return undefined;
    if (entry.expires < Date.now()) {
      this.entries.delete(id);
      return undefined;
    }
    return entry.session;
  }

  set(session: Session): void {
    this.entries.set(session.id, { session, expires: Date.now() + MAX_AGE_SECONDS * 1000 });
  }

  delete(id: string): void {
    this.entries.delete(id);
  }

  clear(): void {
    this.entries.clear();
  }
}

export interface SessionVariables {
  session: Session;
}

/** Hono middleware that attaches a `session` to the context (cookie: `idp_sid`). */
export function sessionMiddleware(
  store: SessionStore,
  secret: string,
): MiddlewareHandler<{ Variables: SessionVariables }> {
  return async (c, next) => {
    const cookieId = await getSignedCookie(c, secret, SESSION_COOKIE);
    const session = (cookieId ? store.get(cookieId) : undefined) ?? store.create();
    c.set('session', session);

    await next();

    if (session.destroyed) {
      deleteCookie(c, SESSION_COOKIE, { path: '/' });
      return;
    }
    store.set(session); // sliding expiration
    await setSignedCookie(c, SESSION_COOKIE, session.id, secret, {
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
      maxAge: MAX_AGE_SECONDS,
    });
  };
}

/** Same session index derivation as the original saml-idp. */
export function getSessionIndex(session: Session): string {
  let hash = 0;
  for (let i = 0; i < session.id.length; i++) {
    hash = (hash << 5) - hash + session.id.charCodeAt(i);
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString();
}

/** Keeps the state of in-flight Single Logout transactions in the session. */
export function createLogoutStore(session: Session): LogoutStore {
  const bag = (): Record<string, any> => (session.data._logoutState ??= {});
  return {
    save(state) {
      const handle = randomBytes(16).toString('hex');
      bag()[handle] = state;
      return handle;
    },
    load(handle, options) {
      if (!handle) return undefined;
      const state = bag()[handle];
      if (state && options?.destroy) delete bag()[handle];
      return state;
    },
    update(handle, state) {
      bag()[handle] = state;
    },
  };
}
