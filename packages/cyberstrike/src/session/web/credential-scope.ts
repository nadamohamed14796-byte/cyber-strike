/**
 * Return a credential only when it belongs to the active session.
 *
 * Credential IDs are database-global identifiers; possessing an ID is not
 * authorization to use the credential in another session.
 */
export function credentialForSession<T extends { session_id: string }>(
  credential: T | undefined | null,
  sessionID: string,
): T | undefined {
  if (!sessionID || !credential || credential.session_id !== sessionID) return undefined
  return credential
}
