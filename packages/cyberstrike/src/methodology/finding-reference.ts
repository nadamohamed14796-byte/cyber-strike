import { Session } from "../session"
import { Vulnerability } from "../session/vulnerability"
import { TargetMemory, type Workspace } from "../target"
import { redactTargetNoteSecrets } from "../target/redact"

export type FindingReferenceValidationState =
  | "pending"
  | "confirmed"
  | "false_positive"
  | "inconclusive"
  | "duplicate"
  | "legacy"

function cleanEndpointPath(value: string): string {
  try {
    if (value.startsWith("http://") || value.startsWith("https://")) {
      const url = new URL(value)
      return url.pathname || "/"
    }
  } catch {}
  const pathOnly = value.split(/[?#]/, 1)[0]?.trim() ?? ""
  return pathOnly.startsWith("/") ? pathOnly : "/" + pathOnly
}

function reportEndpointPath(endpoint: string | undefined): string | undefined {
  if (!endpoint?.trim()) return undefined
  const value = endpoint.trim().replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i, "")
  return cleanEndpointPath(value)
}

function safeFindingText(value?: string, maxLength = 3000): string | undefined {
  if (!value?.trim()) return undefined
  return redactTargetNoteSecrets(value.trim()).slice(0, maxLength)
}

function localFindingText(value?: string, maxLength = 3000): string | undefined {
  if (!value?.trim()) return undefined
  return value.trim().slice(0, maxLength)
}

/**
 * Keep the target-local pointer synchronized with the real finding lifecycle.
 * A row with status=new is a candidate only; it is not reportable until the
 * ten-check validator confirms it and triage explicitly approves it.
 */
export async function persistTargetFindingLink(input: {
  workspace: Workspace
  vulnerability: Vulnerability.Info
  sessionID: string
  validationState?: FindingReferenceValidationState
}): Promise<{ noteID: string; filePath: string; workspace: Workspace }> {
  const v = input.vulnerability
  const endpoint = reportEndpointPath(v.endpoint)
  const reportable = ["approved", "open", "fixed", "ignored"].includes(v.status)
  const disposition = v.status === "false_positive"
    ? "rejected"
    : v.status === "duplicate"
      ? "duplicate"
      : reportable
        ? "reportable"
        : "candidate"
  const recordType = v.status === "false_positive"
    ? "finding-rejected-reference"
    : v.status === "duplicate"
      ? "finding-duplicate-reference"
      : reportable
        ? "finding-reference"
        : "finding-candidate-reference"
  const validationState = input.validationState ??
    (v.status === "approved" ? "confirmed" : v.status === "false_positive" ? "false_positive" : v.status === "duplicate" ? "duplicate" : reportable ? "legacy" : "pending")
  const lifecycleDescription = reportable
    ? "This is an approved reportable finding."
    : v.status === "false_positive"
      ? "This hypothesis was rejected as a false positive and is not reportable."
      : v.status === "duplicate"
        ? "This candidate was linked to an existing finding as a duplicate and is not a separate reportable issue."
        : "This is only a candidate/lead, NOT a confirmed or reportable vulnerability. It must resolve all ten evidence-based validation checks and receive explicit triage approval before it can enter confirmed findings or a security report."

  const note = await TargetMemory.addNote(input.workspace.targetURL, {
    kind: "finding",
    title: "Finding " + v.id + ": " + v.title,
    content: [
      "Finding ID: " + v.id + ". Lifecycle: " + disposition + ". " + lifecycleDescription + " " +
        (reportable ? "Accepted severity: " + v.severity + ". " : "Claimed severity: " + v.severity + " (unvalidated; not an accepted severity). ") +
        "Endpoint: " + (endpoint ?? "not uniquely identified") + ". Workflow status: " + v.status + ".",
      localFindingText(v.description, 3500),
      v.steps_to_reproduce ? "The reporter's reproduction path (which still needs independent verification unless approved) is: " + localFindingText(v.steps_to_reproduce, 2500) : undefined,
      v.business_impact ? "The claimed impact is: " + localFindingText(v.business_impact, 1800) + (reportable ? "" : " This is a claim, not yet accepted as demonstrated impact.") : undefined,
      v.poc ? "Submitted PoC/comparison details: " + localFindingText(v.poc, 2500) : undefined,
      v.cwe_id ? "Possible weakness classification: " + v.cwe_id + "." : undefined,
      v.attack_vector ? "Reported attack surface: " + v.attack_vector + "." : undefined,
      v.file ? "Reported code location: " + localFindingText(v.file, 500) + (v.line_start !== undefined ? ":" + v.line_start + (v.line_end !== undefined ? "-" + v.line_end : "") : "") + "." : undefined,
      v.recommendation ? "Suggested remediation: " + localFindingText(v.recommendation, 1500) : undefined,
      "A scanner signal, role-dependent UI option, endpoint existence, or unusual response alone is not proof. Preserve the actual baseline, negative control, valid identity context, endpoint reachability, security impact, benign explanations, and independently reviewable evidence. The ten-check validator and explicit triage approval govern reportability. Session " + Session.root(input.sessionID) + " is the source; canonical request/response evidence remains in the request store when available.",
    ].filter(Boolean).join("\n"),
    source: "report_vulnerability",
    status: reportable ? "confirmed" : v.status === "false_positive" ? "disproven" : "unverified",
    tags: [reportable ? "finding" : "finding-candidate", disposition, v.severity, "ten-check-validation", ...(v.candidate ? ["execution-candidate"] : [])],
    upsertByIdentity: true,
    identityKey: "finding:" + v.id,
  })

  const filePath = "findings/" + v.id + ".json"
  await TargetMemory.writeWorkspaceFile(note.workspace, filePath, JSON.stringify({
    schemaVersion: 2,
    recordType,
    vulnerabilityID: v.id,
    targetID: note.workspace.id,
    targetURL: note.workspace.targetURL,
    sessionID: Session.root(input.sessionID),
    status: v.status,
    lifecycleState: disposition,
    reportable,
    severity: reportable ? v.severity : null,
    claimedSeverity: v.severity,
    severityState: reportable ? (v.status === "approved" ? "triaged" : "legacy") : "unvalidated",
    candidate: v.candidate ?? null,
    cweID: v.cwe_id ?? null,
    endpoint,
    attackVector: v.attack_vector ?? null,
    description: safeFindingText(v.description, 3500) ?? null,
    stepsToReproduce: safeFindingText(v.steps_to_reproduce, 2500) ?? null,
    claimedBusinessImpact: safeFindingText(v.business_impact, 1800) ?? null,
    redactedPoC: safeFindingText(v.poc, 2500) ?? null,
    recommendation: safeFindingText(v.recommendation, 1500) ?? null,
    validationState,
    validationChecksRequired: 10,
    noteID: note.note.id,
    recordedAt: new Date(v.time?.updated ?? v.time?.created ?? Date.now()).toISOString(),
  }, null, 2) + "\n")

  return { noteID: note.note.id, filePath, workspace: note.workspace }
}
