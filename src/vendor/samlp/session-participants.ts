// Ported from mcguinness/node-samlp (MIT, see ./LICENSE).

export interface SessionParticipant {
  serviceProviderId?: string;
  sessionIndex?: string;
  nameId?: string;
  nameIdFormat?: string;
  serviceProviderLogoutURL?: string;
  /** Certificate used to validate signed messages from the participant. */
  cert?: string | Buffer;
  thumbprint?: string;
}

function matchingIndex(issuer?: string, sessionIndex?: string | string[], nameId?: string) {
  return (session: SessionParticipant) => {
    // If we had the issuer in session and it is provided, they should match
    if (session.serviceProviderId && issuer && session.serviceProviderId !== issuer) {
      return false;
    }

    const hasMatchingSessionIndex = Array.isArray(sessionIndex)
      ? sessionIndex.some((si) => si === session.sessionIndex)
      : sessionIndex === session.sessionIndex;

    // SessionIndex and NameID should match
    return hasMatchingSessionIndex && session.nameId === nameId;
  };
}

/** In-memory list of the Service Providers that take part in a user's session. */
export class SessionParticipants {
  private participants: SessionParticipant[];

  constructor(sessions: SessionParticipant[] = []) {
    this.participants = sessions;
  }

  /** Finds a participant by issuer (optional), session index and NameID. */
  get(
    issuer: string | undefined,
    sessionIndices: string | string[] | undefined,
    nameId: string | undefined,
  ): SessionParticipant | undefined {
    return this.participants.find(matchingIndex(issuer, sessionIndices, nameId));
  }

  hasElements(): boolean {
    return this.participants.length > 0;
  }

  /** Returns the first participant without removing it. */
  getFirst(): SessionParticipant | undefined {
    return this.participants[0];
  }

  /** Removes and returns the matching participant (if any). */
  remove(
    issuer: string | undefined,
    sessionIndex: string | undefined,
    nameId: string | undefined,
  ): SessionParticipant | null {
    if (this.participants.length === 0 || !issuer) return null;
    const index = this.participants.findIndex(matchingIndex(issuer, sessionIndex, nameId));
    if (index === -1) return null;
    return this.participants.splice(index, 1)[0];
  }
}
