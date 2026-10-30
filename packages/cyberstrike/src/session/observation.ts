import { Database } from "../storage/db"
import { RequestObservationTable } from "./session.sql"
import { Identifier } from "../id/id"
import { eq, and } from "../storage/db"
import { RequestTable } from "./session.sql"

// Per-credential observed-value accumulation (Faz 3).
//
// Each ingested request — whether it creates a new endpoint row or is a dedup
// skip — records WHICH concrete values WHICH credential used on this operation.
// This is the deterministic, LLM-free substrate for access-control testing:
// horizontal/IDOR (same op, different identity's object id), vertical/BFLA (op
// reached only by a privileged credential), mass-assignment (extra body shape per
// credential). The actual differential test is the tester-agent's job later; here
// we only accumulate evidence, cheaply and append-only.
export namespace Observation {
  export interface Slot {
    loc: string
    name: string
    value: string
    retained?: boolean
  }

  // No extractable values ⇒ still record reachability (which credential hit this
  // shape) under a sentinel value-set, so BFLA "only admin reached it" is visible.
  const EMPTY_VALUE_SET = "none"

  /**
   * Append-only upsert. One row per (session, key_hash, credential, value_hash);
   * the unique index drops exact repeats (ON CONFLICT DO NOTHING), so concurrent
   * bursts and re-hits are idempotent with no read-modify-write race. Returns true
   * when a NEW observation was recorded (new value-set or new credential).
   */
  export function observe(input: {
    sessionID: string
    keyHash: string
    opGroupHash: string
    requestID?: string
    credentialID?: string
    valueHash?: string
    slots?: Slot[]
  }): boolean {
    const id = Identifier.ascending("request_observation")
    const now = Date.now()
    const inserted = Database.use((db) =>
      db
        .insert(RequestObservationTable)
        .values({
          id,
          session_id: input.sessionID,
          op_group_hash: input.opGroupHash,
          key_hash: input.keyHash,
          request_id: input.requestID ?? null,
          credential_id: input.credentialID ?? null,
          value_hash: input.valueHash ?? EMPTY_VALUE_SET,
          slots: input.slots ?? null,
          time_created: now,
          time_updated: now,
        })
        .onConflictDoNothing({
          target: [
            RequestObservationTable.session_id,
            RequestObservationTable.key_hash,
            RequestObservationTable.credential_id,
            RequestObservationTable.value_hash,
          ],
        })
        .returning({ id: RequestObservationTable.id })
        .all(),
    )
    return inserted.length > 0
  }

  /** All observations for an endpoint shape (key_hash) — used by tests/aggregation. */
  export function listByKeyHash(sessionID: string, keyHash: string) {
    return Database.use((db) =>
      db
        .select()
        .from(RequestObservationTable)
        .where(and(eq(RequestObservationTable.session_id, sessionID), eq(RequestObservationTable.key_hash, keyHash)))
        .all(),
    )
  }

  /** All observations in a session — used by tests. */
  export function listBySession(sessionID: string) {
    return Database.use((db) =>
      db.select().from(RequestObservationTable).where(eq(RequestObservationTable.session_id, sessionID)).all(),
    )
  }

  export interface EndpointTree {
    keyHash: string
    credentials: (string | null)[] // distinct credential_ids that hit this endpoint shape
    params: {
      name: string
      loc: string
      byCredential: { credentialID: string | null; values: string[]; redacted: boolean }[]
    }[]
  }

  /**
   * Per-endpoint observed values, aggregated for the UI tree: which credential used
   * which concrete values for each param. RAW FACTS ONLY — no idLike/reference/owner
   * judgment (the agent does that). Redacted values surface as a `redacted` flag with
   * no concrete value.
   */
  export function endpointTree(sessionID: string, keyHash: string): EndpointTree {
    const obs = listByKeyHash(sessionID, keyHash)
    const credentials = [...new Set(obs.map((o) => o.credential_id))]
    const byParam = new Map<
      string,
      { loc: string; byCred: Map<string | null, { values: Set<string>; redacted: boolean }> }
    >()
    for (const o of obs) {
      const slots = (o.slots ?? []) as { loc: string; name: string; value: string; retained?: boolean }[]
      for (const s of slots) {
        const p = byParam.get(s.name) ?? { loc: s.loc, byCred: new Map() }
        const cred = p.byCred.get(o.credential_id) ?? { values: new Set<string>(), redacted: false }
        if (s.retained === false) cred.redacted = true
        else if (s.value) cred.values.add(s.value)
        p.byCred.set(o.credential_id, cred)
        byParam.set(s.name, p)
      }
    }
    const params = [...byParam.entries()].map(([name, p]) => ({
      name,
      loc: p.loc,
      byCredential: [...p.byCred.entries()].map(([credentialID, v]) => ({
        credentialID,
        values: [...v.values],
        redacted: v.redacted,
      })),
    }))
    return { keyHash, credentials, params }
  }

  export interface OperationTree {
    opGroupHash: string
    keyHashes: string[]
    credentials: (string | null)[]
    params: {
      name: string
      loc: string
      byCredential: { credentialID: string | null; values: string[]; redacted: boolean }[]
    }[]
  }

  /** Aggregate observed values across every structural body shape for one operation. */
  export function operationTree(sessionID: string, opGroupHash: string): OperationTree {
    const obs = Database.use((db) =>
      db.select().from(RequestObservationTable).where(and(
        eq(RequestObservationTable.session_id, sessionID),
        eq(RequestObservationTable.op_group_hash, opGroupHash),
      )).all(),
    )
    const keyHashes = [...new Set(obs.map((o) => o.key_hash))].sort()
    const credentials = [...new Set(obs.map((o) => o.credential_id))]
      .sort((a, b) => (a ?? "").localeCompare(b ?? ""))
    const byParam = new Map<
      string,
      { loc: string; byCred: Map<string | null, { values: Set<string>; redacted: boolean }> }
    >()
    for (const observation of obs) {
      const slots = (observation.slots ?? []) as Slot[]
      for (const slot of slots) {
        const param = byParam.get(slot.name) ?? { loc: slot.loc, byCred: new Map() }
        const credential = param.byCred.get(observation.credential_id) ?? { values: new Set<string>(), redacted: false }
        if (slot.retained === false) credential.redacted = true
        else if (slot.value) credential.values.add(slot.value)
        param.byCred.set(observation.credential_id, credential)
        byParam.set(slot.name, param)
      }
    }
    const params = [...byParam.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, param]) => ({
      name,
      loc: param.loc,
      byCredential: [...param.byCred.entries()]
        .sort(([a], [b]) => (a ?? "").localeCompare(b ?? ""))
        .map(([credentialID, value]) => ({
          credentialID,
          values: [...value.values].sort(),
          redacted: value.redacted,
        })),
    }))
    return { opGroupHash, keyHashes, credentials, params }
  }

  /**
   * Resolve the operation-level observation group from the request row itself.
   * This also works when an identical observation was upserted earlier and its
   * request_id still points at the first capture.
   */
  export function operationTreeForRequest(sessionID: string, requestID: string): OperationTree | undefined {
    const request = Database.use((db) =>
      db.select({ key_hash: RequestTable.key_hash })
        .from(RequestTable)
        .where(and(
          eq(RequestTable.session_id, sessionID),
          eq(RequestTable.id, requestID),
        ))
        .get(),
    )
    if (!request?.key_hash) return undefined

    // Resolve the group from the persisted observation, not by duplicating
    // Normalize's hash formula. Repeated observations may still point at the
    // first request ID, so key_hash is the stable lookup anchor here.
    const group = Database.use((db) =>
      db.select({ op_group_hash: RequestObservationTable.op_group_hash })
        .from(RequestObservationTable)
        .where(and(
          eq(RequestObservationTable.session_id, sessionID),
          eq(RequestObservationTable.key_hash, request.key_hash!),
        ))
        .get(),
    )
    if (!group) return undefined
    return operationTree(sessionID, group.op_group_hash)
  }

  export interface EndpointObsSummary {
    keyHash: string
    credentialIDs: (string | null)[] // distinct credentials that hit this endpoint shape
    paramNames: string[] // distinct param names observed (no values — summary only)
  }

  /**
   * Session-wide rollup, one entry per endpoint shape (key_hash): which credentials
   * hit it and which param names carry values. Cheap, value-free — the orchestrator
   * uses it to spot multi-credential endpoints (the access-control shortlist) and
   * then pulls full values via web_get_request_detail. RAW FACTS ONLY (no verdict).
   */
  export function sessionSummary(sessionID: string): EndpointObsSummary[] {
    const obs = listBySession(sessionID)
    const byKey = new Map<string, { creds: Set<string | null>; params: Set<string> }>()
    for (const o of obs) {
      const e = byKey.get(o.key_hash) ?? { creds: new Set<string | null>(), params: new Set<string>() }
      e.creds.add(o.credential_id)
      for (const s of (o.slots ?? []) as { name: string }[]) e.params.add(s.name)
      byKey.set(o.key_hash, e)
    }
    return [...byKey.entries()].map(([keyHash, e]) => ({
      keyHash,
      credentialIDs: [...e.creds],
      paramNames: [...e.params],
    }))
  }
}
