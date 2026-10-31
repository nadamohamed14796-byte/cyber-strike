import { createHash } from "node:crypto"
import type {
  JavaScriptApplicationHint,
  JavaScriptRequestCandidate,
  JavaScriptRoleHint,
  JavaScriptRiskSignal,
  JavaScriptSecretCandidate,
  JavaScriptWorkflowSignal,
  JavaScriptDataExposureSignal,
} from "./javascript-analysis"

export interface JavaScriptScenarioSignal {
  evidenceType: "workflow" | "application" | "role" | "risk" | "secret" | "data-exposure"
  kind: string
  value: string
  line: number
  sourceFunction: string | null
}

export interface JavaScriptScenarioCandidate {
  id: string
  category: string
  title: string
  hypothesis: string
  sourceFile: string
  sourceSHA256: string
  sourceFunction: string | null
  sourceLines: number[]
  signals: JavaScriptScenarioSignal[]
  relatedEndpointIDs: string[]
  relatedRequestCandidateIDs: string[]
  observedRequestIDs: string[]
  riskSignalIDs: string[]
  prerequisites: string[]
  recommendedChecks: string[]
  confidence: "candidate"
  status: "candidate"
}

type ScenarioRequest = JavaScriptRequestCandidate & {
  sourceFile: string
  observedRequestIDs: string[]
}
type ScenarioEndpoint = {
  id: string
  path: string
  method?: string | null
  sourceFiles: string[]
  observedRequestIDs: string[]
}
type ScenarioSourceFile = { relativePath: string; sha256: string }

const sharedPrerequisites = [
  "Recheck the exact target, origin, path, and every request against the persisted scope before any active test.",
  "Use captured baselines and test-owned accounts/resources only; preserve a meaningful negative control.",
  "This is a static review scenario, not a finding. Do not run it automatically during recon or without explicit testing intent.",
]

const plans: Record<string, { title: string; hypothesis: string; checks: string[] }> = {
  "identity-session": {
    title: "Identity, verification, recovery, and MFA flow review",
    hypothesis: "Client code exposes an identity flow whose token binding, expiry, replay, or rate-limit behavior merits review.",
    checks: [
      "Map initiation, delivery, verification, completion, and refresh requests with account and function context.",
      "With two controlled accounts, verify tokens/codes are bound to the intended account and cannot be replayed across accounts or completed twice.",
      "Check expiry, one-time use, invalidation after password/session changes, and server-side rate limiting using low-volume controlled cases.",
      "Check for account-existence disclosure and incorrect email/phone ownership transitions.",
    ],
  },
  "token-lifecycle": {
    title: "Token creation, parsing, validation, and lifetime review",
    hypothesis: "Client code references token handling; verify the authoritative server-side verifier and lifecycle controls.",
    checks: [
      "Identify token issuing and consuming endpoints and the authoritative server-side verifier.",
      "Review issuer, audience, signature/key selection, expiry, not-before, algorithm restrictions, and refresh-token rotation.",
      "Using test-owned sessions only, confirm revoked, expired, wrong-audience, and malformed tokens are rejected.",
    ],
  },
  "email-workflow": {
    title: "Email delivery and address-ownership workflow review",
    hypothesis: "Client code exposes an email workflow; verify recipient control, address ownership, and state transitions.",
    checks: [
      "Trace recipient and template parameters to the server-side mail operation without sending mail to real users.",
      "Use test mailboxes to verify address ownership, token binding, one-time completion, and resend/rate-limit behavior.",
      "Check whether changing an email or invitation identifier can cross account or tenant boundaries.",
    ],
  },
  "data-layer-review": {
    title: "Server data-layer and query-construction review",
    hypothesis: "A SQL/data-layer marker appears in the bundle; locate the server handler and trace input to query construction.",
    checks: [
      "Locate the server handler, query builder, validation schema, and parameter-binding implementation.",
      "Do not infer SQL injection from a keyword or frontend library call; first prove input reachability and unsafe server-side query construction.",
      "Only after explicit authorization, use a harmless bounded variation with a controlled fixture.",
    ],
  },
  "transactional-business-logic": {
    title: "Transactional business-logic and state-transition review",
    hypothesis: "The client exposes a payment, order, billing, wallet, refund, or subscription workflow; verify server-side invariants.",
    checks: [
      "Map workflow states and identify which server request is authoritative for price, quantity, owner, status, and entitlement.",
      "With sandbox/test-owned fixtures only, verify client-supplied prices/statuses are not trusted and state transitions enforce ownership and order.",
      "Review duplicate submissions/idempotency with reversible non-financial operations; never trigger real charges or transfers.",
    ],
  },
  "file-transfer": {
    title: "File upload, download, import, and export review",
    hypothesis: "The application exposes file/data transfer operations whose ownership, validation, and storage visibility need review.",
    checks: [
      "Identify upload, download, import, export, and metadata endpoints with their object IDs and parameter locations.",
      "Use benign test-owned files only; verify server-side ownership for read, replace, delete, and export operations.",
      "Review filename/path normalization, content-type validation, archive handling, and private-storage access without reading real user files.",
    ],
  },
  "multi-tenant-authorization": {
    title: "Role, tenant, workspace, and object-authorization review",
    hypothesis: "Role, permission, tenant, workspace, invitation, or impersonation clues warrant a server-side authorization review.",
    checks: [
      "Map each identifier to its owning account/tenant and record the required role for the operation.",
      "Compare the same harmless request across two authorized test identities and test-owned objects, preserving expected-denied controls.",
      "Verify server handlers enforce object ownership and role checks independently of hidden UI controls or feature flags.",
    ],
  },
  "internal-feature-boundary": {
    title: "Internal feature and feature-flag boundary review",
    hypothesis: "A debug/internal/feature-flag branch may expose an operation that must remain protected server-side.",
    checks: [
      "Trace the feature flag or client-side role branch to its API operation and server authorization check.",
      "Confirm changing a client flag does not grant access to a protected action.",
      "Use test-owned accounts and a harmless read-only operation; retain the expected-denied control.",
    ],
  },
  "graphql-api": {
    title: "GraphQL operation and resolver-authorization review",
    hypothesis: "GraphQL operations or introspection markers are present; review resolver-level authorization and object boundaries.",
    checks: [
      "Inventory operation names, variables, aliases, mutations, and captured GraphQL request IDs.",
      "Verify authorization at each resolver/object boundary with controlled identities; schema visibility alone is not access.",
      "Review mutation ownership and bounded query-cost controls using safe, low-cost operations.",
    ],
  },
  "realtime-api": {
    title: "WebSocket and cross-context messaging trust review",
    hypothesis: "WebSocket/EventSource/postMessage channels are present; verify origin, identity, and message-level authorization.",
    checks: [
      "Identify connection URL, handshake authentication, origin policy, channel/topic IDs, and message schema.",
      "Verify messages/subscriptions are authorized per account/object, not only at initial connection.",
      "Review source-origin and schema validation for postMessage handlers before controlled testing.",
    ],
  },
  "client-side-storage": {
    title: "Browser storage and client-side credential exposure review",
    hypothesis: "Browser persistence or token storage is present; determine whether sensitive credentials are stored and exposed.",
    checks: [
      "Classify values as public identifiers, ephemeral state, session credentials, refresh tokens, or secrets; do not print values.",
      "Trace reads/writes and clearing behavior across logout, expiry, and account switching.",
      "Only assess exploitability after a separate, evidence-backed script-injection path is established.",
    ],
  },
  "service-worker-cache": {
    title: "Service-worker and cache-boundary review",
    hypothesis: "A service worker is registered; review its scope, cache contents, update lifecycle, and authenticated-response handling.",
    checks: [
      "Inspect registration scope, update flow, cache keys, and whether personalized responses can enter shared caches.",
      "Verify cached private responses are not served across accounts or after logout using test-owned sessions.",
      "Review message handlers and cache invalidation without disrupting production users.",
    ],
  },
  "api-protocol-review": {
    title: "RPC and API protocol authorization review",
    hypothesis: "A non-REST RPC/integration client is present; review operation shape and authorization at the server boundary.",
    checks: [
      "Identify protocol endpoint, method/operation name, input schema, and captured request IDs.",
      "Verify object ownership and role checks at the server procedure/handler, not in the client wrapper.",
      "Compare an authorized baseline with a controlled denied case using test-owned identities.",
    ],
  },
  "sensitive-data-exposure": {
    title: "Sensitive data and hard-coded personal-data exposure review",
    hypothesis: "The bundle contains sensitive data-field names or an embedded email-address literal; determine whether it is a schema reference, public contact, synthetic fixture, or actual private data included in a client-delivered asset.",
    checks: [
      "Inspect only the source location and surrounding local code; do not copy, display, or transmit matched personal values.",
      "Classify whether the field is a type/schema, a request input, a response mapping, or a hard-coded record; distinguish public contact addresses from personal data.",
      "If a real private record appears embedded in a client asset, confirm ownership and exposure with the program owner or a test-owned fixture, then document the minimum necessary proof with values redacted.",
      "Trace any related endpoint and authorization boundary; do not infer a server-side data leak from a field name or client-side model alone.",
    ],
  },
  "credential-exposure-review": {
    title: "Secret-like client assignment review",
    hypothesis: "A secret-like assignment was fingerprinted; classify it without using or disclosing the value.",
    checks: [
      "Inspect the exact source location locally and classify the value without copying it into prompts, reports, or requests.",
      "Use provider documentation or owner-approved metadata to distinguish public client IDs from server-side credentials.",
      "Do not exchange, validate, enumerate, or use the candidate credential; escalate plausible exposure for owner-side review.",
    ],
  },
  "dom-xss-review": {
    title: "DOM HTML-sink and source-to-sink review",
    hypothesis: "A DOM HTML insertion sink is present; establish whether attacker-controlled data reaches it without contextual sanitization.",
    checks: [
      "Trace the actual source, transformations, sanitizer, sink, and execution context in one reachable code path.",
      "Use a harmless marker and test-owned content only after reachability is established; distinguish inert reflection from script execution.",
    ],
  },
  "dynamic-code-review": {
    title: "Dynamic code execution review",
    hypothesis: "A dynamic-code/string-timer sink is present; determine whether untrusted input controls evaluated code.",
    checks: [
      "Trace arguments and data sources to the sink; a static eval-like call is not proof of injection.",
      "Prefer source review and non-executing tests; do not run untrusted code or payloads against production data.",
    ],
  },
  "redirect-validation": {
    title: "Redirect and navigation target validation review",
    hypothesis: "A navigation/redirect sink is present; determine whether an untrusted parameter controls the destination.",
    checks: [
      "Trace the destination source and validate canonicalization, allowlists, and same-origin restrictions.",
      "Use only a benign controlled destination on an authorized test flow; distinguish client navigation from server redirects.",
    ],
  },
  "postmessage-trust": {
    title: "postMessage origin and message authorization review",
    hypothesis: "A cross-window message handler is present; verify origin checks, message schema, and authorization of sensitive actions.",
    checks: [
      "Check targetOrigin values and event.origin/source validation in handlers.",
      "Trace message fields to privileged operations and validate the schema before controlled testing.",
    ],
  },
  "csrf-review": {
    title: "Credentialed state-changing request CSRF review",
    hypothesis: "A state-changing browser request has cookie/credential clues; verify server-side anti-CSRF controls.",
    checks: [
      "Capture an ordinary browser baseline and inspect token, Origin, Referer, SameSite, and Fetch Metadata behavior.",
      "Use a harmless test-owned transition and expected-denied cross-site control; frontend hints alone do not prove missing protections.",
    ],
  },
  "regex-safety": {
    title: "Dynamic regular-expression safety review",
    hypothesis: "A dynamic regular expression is built from a value; determine whether untrusted input can cause pathological matching.",
    checks: [
      "Trace pattern and input control and identify whether catastrophic backtracking is possible.",
      "Use static analysis or a bounded offline harness; never send denial-of-service inputs to a live service.",
    ],
  },
  "prototype-safety": {
    title: "Prototype mutation and merge-safety review",
    hypothesis: "Prototype-sensitive property mutation is present; trace whether untrusted keys reach the mutation.",
    checks: [
      "Trace object construction, key filtering, and merge depth; verify dangerous keys are rejected at the trust boundary.",
      "Use a benign test-owned object and harmless property marker only; do not alter shared production state.",
    ],
  },
  "debug-feature-exposure": {
    title: "Debug and internal-route exposure review",
    hypothesis: "Debug/internal route clues are present; verify matching operations remain protected server-side.",
    checks: [
      "Identify the route and server-side guard; UI visibility or a debug flag is not an access-control boundary.",
      "Use a test-owned low-privilege identity and a harmless read-only operation to check expected denial.",
    ],
  },
  "business-workflow-review": {
    title: "Application workflow and business-state review",
    hypothesis: "The client exposes a business operation; map state transitions and authorization before selecting a security test.",
    checks: [
      "Identify operation inputs, authoritative server state, owner, role, and expected transitions.",
      "Use reversible test-owned fixtures and compare normal, omitted, and controlled alternate inputs.",
    ],
  },
}

function pathShape(value: string): string {
  return value.split(/[?#]/, 1)[0]!.replace(/\/{2,}/g, "/").split("/").map((segment) =>
    /^\{[^}]+\}$/.test(segment) ? "{}" : segment,
  ).join("/").replace(/\/+$/, "") || "/"
}

function categoryForApplicationHint(item: JavaScriptApplicationHint): string | undefined {
  const value = item.value.toLowerCase()
  if (item.kind === "graphql-operation" || item.kind === "graphql-introspection") return "graphql-api"
  if (item.kind === "identity-session-flow") return "identity-session"
  if (item.kind === "crypto-token-library") return "token-lifecycle"
  if (item.kind === "authorization-feature-boundary") return /debug|internal/.test(value) ? "debug-feature-exposure" : "multi-tenant-authorization"
  if (item.kind === "business-workflow") {
    if (/upload|download|export|import|attachment|file/.test(value)) return "file-transfer"
    if (/payment|billing|checkout|invoice|refund|payout|wallet|coupon|discount|order|cart|shipment|subscription/.test(value)) return "transactional-business-logic"
    if (/tenant|organization|workspace|invite|invitation|impersonat|moderation/.test(value)) return "multi-tenant-authorization"
    if (/webhook|integration/.test(value)) return "api-protocol-review"
    return "business-workflow-review"
  }
  if (item.kind === "websocket-client" || item.kind === "cross-context-messaging") return "realtime-api"
  if (item.kind === "browser-persistence") return "client-side-storage"
  if (item.kind === "service-worker") return "service-worker-cache"
  if (item.kind === "api-client-or-rpc" && /trpc|grpc|connectrpc/i.test(item.value)) return "api-protocol-review"
  return undefined
}

const riskCategories: Record<string, string> = {
  "dom-html-sink": "dom-xss-review",
  "html-fragment-insertion": "dom-xss-review",
  "document-write-sink": "dom-xss-review",
  "dynamic-code-execution": "dynamic-code-review",
  "string-timer-execution": "dynamic-code-review",
  "navigation-or-redirect-sink": "redirect-validation",
  "cross-window-message": "postmessage-trust",
  "wildcard-postmessage-origin": "postmessage-trust",
  "message-event-handler": "postmessage-trust",
  "client-side-token-storage": "client-side-storage",
  "document-cookie-write": "token-lifecycle",
  "csrf-review-state-changing-cookie-request": "csrf-review",
  "dynamic-regexp": "regex-safety",
  "prototype-mutation": "prototype-safety",
}

/** Build source-linked scenario candidates without sending requests or changing findings. */
export function createJavaScriptScenarioCandidates(input: {
  sourceFiles: ScenarioSourceFile[]
  requestCandidates: ScenarioRequest[]
  endpoints: ScenarioEndpoint[]
  workflowSignals: Array<JavaScriptWorkflowSignal & { sourceFile: string }>
  applicationHints: Array<JavaScriptApplicationHint & { sourceFile: string }>
  roleHints: Array<JavaScriptRoleHint & { sourceFile: string }>
  riskSignals: Array<JavaScriptRiskSignal & { sourceFile: string }>
  secretCandidates: Array<JavaScriptSecretCandidate & { sourceFile: string }>
  dataExposureSignals?: Array<JavaScriptDataExposureSignal & { sourceFile: string }>
}): JavaScriptScenarioCandidate[] {
  type Group = {
    category: string
    sourceFile: string
    sourceFunction: string | null
    signals: JavaScriptScenarioSignal[]
    riskSignalIDs: string[]
  }
  const groups = new Map<string, Group>()
  const add = (
    sourceFile: string,
    category: string,
    signal: JavaScriptScenarioSignal,
    sourceFunction: string | null = signal.sourceFunction,
    riskSignalID?: string,
  ) => {
    const key = [sourceFile, category, sourceFunction ?? ""].join("\0")
    const group = groups.get(key) ?? { category, sourceFile, sourceFunction, signals: [], riskSignalIDs: [] }
    group.signals.push(signal)
    if (riskSignalID) group.riskSignalIDs.push(riskSignalID)
    groups.set(key, group)
  }

  for (const item of input.workflowSignals) {
    let category: string | undefined
    if (/email-verification-flow|account-recovery-flow|one-time-code-or-mfa-flow/.test(item.kind)) category = "identity-session"
    else if (/token-creation-or-signing|token-decode-or-parse|token-verification-or-validation|token-expiry-or-lifetime/.test(item.kind)) category = "token-lifecycle"
    else if (/sql-statement-candidate|data-layer-operation-candidate/.test(item.kind)) category = "data-layer-review"
    else if (item.kind === "email-delivery-flow") category = "email-workflow"
    if (!category) continue
    add(item.sourceFile, category, { evidenceType: "workflow", kind: item.kind, value: item.value, line: item.line, sourceFunction: item.functionName }, item.functionName)
  }
  for (const item of input.applicationHints) {
    const category = categoryForApplicationHint(item)
    if (!category) continue
    add(item.sourceFile, category, { evidenceType: "application", kind: item.kind, value: item.value, line: item.line, sourceFunction: null }, null)
  }
  for (const item of input.roleHints) {
    const category = /debug|internal/.test(item.kind) ? "debug-feature-exposure" : "multi-tenant-authorization"
    add(item.sourceFile, category, { evidenceType: "role", kind: item.kind, value: item.value, line: item.line, sourceFunction: null }, null)
  }
  for (const item of input.riskSignals) {
    const category = riskCategories[item.kind]
    if (!category) continue
    add(item.sourceFile, category, { evidenceType: "risk", kind: item.kind, value: item.kind, line: item.line, sourceFunction: item.functionName }, item.functionName, item.id)
  }
  for (const item of input.dataExposureSignals ?? []) {
    add(item.sourceFile, "sensitive-data-exposure", {
      evidenceType: "data-exposure",
      kind: item.kind,
      value: item.field ?? "embedded email literal; raw value omitted",
      line: item.line,
      sourceFunction: item.functionName,
    }, item.functionName)
  }
  for (const item of input.secretCandidates) {
    add(item.sourceFile, "credential-exposure-review", {
      evidenceType: "secret",
      kind: item.kind,
      value: "sha256:" + item.fingerprint,
      line: item.line,
      sourceFunction: null,
    }, null)
  }

  const output: JavaScriptScenarioCandidate[] = []
  for (const group of groups.values()) {
    const requestCandidates = input.requestCandidates.filter((request) =>
      request.sourceFile === group.sourceFile && (!group.sourceFunction || request.sourceFunction === group.sourceFunction),
    )
    const endpoints = input.endpoints.filter((endpoint) =>
      endpoint.sourceFiles.includes(group.sourceFile) &&
      (!group.sourceFunction || requestCandidates.some((request) =>
        pathShape(request.path) === pathShape(endpoint.path) &&
        (!endpoint.method || !request.method || endpoint.method.toUpperCase() === request.method.toUpperCase()),
      )),
    )
    const source = input.sourceFiles.find((file) => file.relativePath === group.sourceFile)
    const plan = plans[group.category] ?? plans["business-workflow-review"]!
    const signalsByKey = new Map<string, JavaScriptScenarioSignal>()
    for (const signal of group.signals) {
      signalsByKey.set([signal.evidenceType, signal.kind, signal.value, signal.line, signal.sourceFunction ?? ""].join("\0"), signal)
    }
    const signals = [...signalsByKey.values()].sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind))
    const identity = [group.sourceFile, group.category, group.sourceFunction ?? ""].join("\0")
    const requestIDs = [...new Set(requestCandidates.flatMap((request) => request.observedRequestIDs))]
    output.push({
      id: "js-scenario:" + createHash("sha256").update(identity).digest("hex").slice(0, 20),
      category: group.category,
      title: plan.title,
      hypothesis: plan.hypothesis,
      sourceFile: group.sourceFile,
      sourceSHA256: source?.sha256 ?? "",
      sourceFunction: group.sourceFunction,
      sourceLines: [...new Set(signals.map((signal) => signal.line))].sort((a, b) => a - b),
      signals,
      relatedEndpointIDs: [...new Set(endpoints.map((endpoint) => endpoint.id))],
      relatedRequestCandidateIDs: [...new Set(requestCandidates.map((request) => request.id))],
      observedRequestIDs: [...new Set([...requestIDs, ...endpoints.flatMap((endpoint) => endpoint.observedRequestIDs)])],
      riskSignalIDs: [...new Set(group.riskSignalIDs)],
      prerequisites: [...sharedPrerequisites],
      recommendedChecks: [...plan.checks],
      confidence: "candidate",
      status: "candidate",
    })
  }
  return output.sort((a, b) =>
    a.sourceFile.localeCompare(b.sourceFile) || a.category.localeCompare(b.category) ||
    (a.sourceFunction ?? "").localeCompare(b.sourceFunction ?? ""),
  )
}
