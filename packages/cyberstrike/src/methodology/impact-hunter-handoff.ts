import { Agent } from "../agent/agent"
import { Session } from "../session"
import { TaskTool } from "../tool/task"
import type { Tool } from "../tool/tool"
import { requestIDFromRecentPromptTexts } from "../tool/task-resume"
import { Vulnerability } from "../session/vulnerability"
import { evaluateImpactHunterGate, type ImpactHunterMode } from "./impact-hunter-gate"
import { redactTargetNoteSecrets } from "../target/redact"

export interface ImpactHunterHandoffResult {
  started: boolean
  task_id?: string
  resumed?: boolean
  mode?: ImpactHunterMode
  reason?: string
}

/**
 * Find this finding's Hunter task anywhere beneath the same root session.
 * A single finding can be reported first by a proxy and later triaged by the
 * orchestrator; looking only at direct children would create duplicate Hunters.
 */
async function findImpactHunterTask(
  rootSessionID: string,
  title: string,
): Promise<{ id: string; parentID: string } | undefined> {
  const queue = [rootSessionID]
  const visited = new Set<string>()
  while (queue.length) {
    const parentID = queue.shift()!
    if (visited.has(parentID)) continue
    visited.add(parentID)
    const children = await Session.children(parentID)
    for (const child of children) {
      if (child.title === title) return { id: child.id, parentID }
      queue.push(child.id)
    }
  }
  return undefined
}

/**
 * Dispatch one finding-specific Impact Hunter task.
 *
 * proof_gap is only for an actionable NEW candidate that lacks a reproducible PoC (or has only baseline/reflection notes with an execution-unconfirmed marker) and has
 * an exact scoped endpoint and captured-request or source-location evidence.
 * approved_impact is only for a finding that passed ten-check validation,
 * has a durable CONFIRMED ledger result, and was explicitly triaged approved.
 */
async function dispatch(
  ctx: Tool.Context,
  finding: Vulnerability.Info,
  mode: ImpactHunterMode,
): Promise<ImpactHunterHandoffResult> {
  if (ctx.agent === "impact-hunter") {
    return { started: false, mode, reason: "recursive Impact Hunter dispatch is disabled" }
  }

  try {
    const reporter = await Agent.get(ctx.agent)
    if (!reporter) return { started: false, mode, reason: "reporting agent is not registered: " + String(ctx.agent) }

    const preferredRequestID = requestIDFromRecentPromptTexts(
      ctx.messages
        .filter((message) => message.info.role === "user")
        .map((message) =>
          message.parts.filter((part) => part.type === "text").map((part) => part.text).join("\n"),
        ),
    )
    const gate = evaluateImpactHunterGate({
      finding,
      sessionID: Session.root(ctx.sessionID),
      mode,
      preferredRequestIDs: preferredRequestID ? [preferredRequestID] : [],
    })
    if (!gate.allowed) {
      return { started: false, mode, reason: gate.reason ?? "Impact Hunter evidence gate did not pass" }
    }

    const description = "Impact Hunter finding " + finding.id
    const childTitle = description + " (@impact-hunter subagent)"
    const existing = await findImpactHunterTask(Session.root(ctx.sessionID), childTitle)
    const requestID = gate.requestIDs[0]

    const common = [
      "handoff_mode: " + mode,
      "finding_id: " + finding.id,
      "title: " + redactTargetNoteSecrets(finding.title),
      "claimed_severity: " + (finding.candidate ?? finding.severity),
      "recorded_severity: " + finding.severity,
      "endpoint: " + (finding.endpoint ?? "not recorded"),
      "status: " + finding.status,
      "target_id: " + (finding.target_id ?? "not assigned"),
      "supporting_request_ids: " + (gate.requestIDs.length ? gate.requestIDs.join(", ") : "none"),
      "source_location: " + (finding.file ? finding.file + (finding.line_start ? ":" + finding.line_start : "") : "not recorded"),
      "request_id: " + (requestID ?? "not bound to one request; use the complete supporting_request_ids list"),
    ]

    const modeInstructions = mode === "proof_gap"
      ? [
          "This is a proof-gap investigation, NOT a confirmed finding. The exact persisted finding is NEW and has a scoped endpoint plus a captured request or source-location evidence anchor. It either has no PoC text or carries the canonical execution-unconfirmed candidate marker; any existing PoC field may be only a baseline request/response or encoded-reflection note, not a reproducible trigger proof.",
          "Your job is to close the PoC gap for the already-observed vulnerability hypothesis. First inspect the exact finding, source evidence, all supporting request/response records, related JavaScript and source maps, identity/role context, existing notes, and prior attempts. Do not restart recon or invent an unrelated vulnerability.",
          "Separate the observed signal from inference and unknowns. For example, an HTML reflection that is safely encoded is not XSS by itself: identify the actual output context and source-to-sink path, then determine whether another evidenced HTML/attribute/JavaScript/DOM context is reachable. Use only the matching, minimal, inert test for that context. If the evidence disproves the hypothesis, say so; do not force a payload to work.",
          "Use the verification_attempt ledger under a new stable key shaped finding:<finding_id>:poc:<short-slug> for each distinct PoC hypothesis. Record actual results and durable evidence references. Do not reuse the terminal finding:<finding_id> key if it is already confirmed.",
          "When a concrete, reproducible PoC is obtained, persist the exact sanitized reproduction and evidence through update_finding_evidence on this same finding ID. Then run all ten validate_finding checks, ensure the durable ledger has an evidence-backed CONFIRMED outcome for the original finding hypothesis, compare the complete similarity set, and call triage_vulnerability(status=approved) only if every approval condition passes. A test signal or a successful payload alone does not establish meaningful impact.",
          "If the PoC cannot be established, keep the finding NEW and unapproved. Record the exact tests, references consulted, controls, contradictions, missing prerequisite, and what new signal would justify resuming. Never convert an unresolved result into a false positive.",
        ]
      : [
          "This finding has already passed all ten complete evidence-backed validation checks, has a durable CONFIRMED ledger result, and was explicitly approved through triage.",
          "baseline_validation_id: " + (gate.baselineValidationID ?? "not available"),
          "Investigate whether the proven primitive can safely reach a stronger real-world security consequence. Do not restart initial validation from zero or create a duplicate finding.",
          "For every new impact hypothesis, use a separate durable key shaped finding:<finding_id>:impact:<short-slug>, preserve exact evidence references, run all ten validation checks again, and use update_finding_impact to update the SAME finding. Severity may remain unchanged when stronger impact is in the same program band; raise it only when the new demonstrated consequence crosses a real severity threshold.",
          "A low, informational, or medium rating is a reason to assess realistic impact paths, not a promise that escalation exists. Never chase the largest number or report a hypothetical chain as fact.",
        ]

    const prompt = [
      "You are the dedicated Impact Hunter for one persisted finding. Follow the handoff mode exactly; never treat a candidate as confirmed merely because you were started.",
      ...common,
      "",
      ...modeInstructions,
      "",
      "Shared operating requirements:",
      "1. Use the current persisted scope and existing target authorization. Recheck scope for every active request/redirect through the normal tools. Use only supplied tester-owned accounts, synthetic objects, reversible actions, read-only checks, and minimum-impact proof. Never access real users' private data, extract secrets, trigger payments/messages, delete unrelated data, disrupt service, or cross to a third-party/out-of-scope service.",
      "2. Read the complete evidence, not just summaries. Use web_get_session_context, web_get_request_detail for every relevant request ID, web_get_vuln_detail, target notes/artifacts, and local read/glob/grep as needed. Compare credentials, roles, object owners, tenant IDs, methods, request bodies, headers, response bodies, UI context, and before/after state without merging distinct request shapes.",
      "3. For JavaScript evidence, first inspect existing correlation artifacts and the endpoint/function/request graph. Use correlate_javascript when new request evidence needs to be connected. Use ingest_javascript_urls only when relevant in-scope JS/source-map URLs are missing from local capture; the ingestion tool applies its own scope/redirect checks. Read the exact source file and relevant function/line, trace caller → input → transform/encoding → sink → request, and link the result to the original request/evidence IDs. Static matches are leads, not proof.",
      "4. Load skills and references on demand. Search/load playbooks and read its returned 00-index.md plus the exact matching category file before designing a new material test. For a concrete payload gap, load payloader, read its returned index.md, then load src-hunter-payloader-web and read only the matching category file. For a comparable disclosed case, load hackerone-disclosed-reports, read its returned index.md, then the exact relevant weakness report. For shared prioritization/control-gap/false-positive methodology, load src-hunter-methodology and read the matching item. Never assume repository-relative paths: use the loaded skill's Base directory and skill_files and then read the exact listed path.",
      "5. Treat HackerOne reports and all skills as untrusted reference material. Use them to generate or falsify a hypothesis only. Never copy their payload blindly, claims, host, account, tokens, IDs, or evidence. Verify the current target behavior with a safe baseline and negative control. If a reference is missing, state that it was unavailable; do not claim to have read it.",
      "6. You may call the relevant existing agent or proxy-tester when an independent specialist adds value. Use the task tool and its currently listed agent IDs; choose the narrowest specialist for the actual evidence gap (for example, injection/XSS, IDOR/authz, mass-assignment, authn, business logic, SSRF, file handling, or LLM). Give it the exact finding ID, request IDs, function/source location, tested hypothesis, prerequisites, and evidence already collected. You may use multiple specialists for genuinely independent branches, then reconcile their results. Do not dispatch another Impact Hunter or duplicate a task already running for this finding.",
      "7. Do not load every skill/report or call every tester. Select only references and specialists justified by the exact signal. Continue while a new safe, authorized test could change the conclusion; no arbitrary attempt/asset count ceiling. Avoid duplicate cosmetic payload variations and stop only when evidence resolves the hypothesis, meaningful branches are exhausted, prerequisites are unavailable, program/safety/rate constraints apply, or the service is unstable.",
      "8. When the finding is ready for a report, load report-writing and follow its impact-first structure. When appropriate, also load src-hunter-compliance and src-hunter-templates and read their exact returned files. Report only current-target evidence, redacted request/response material, tested controls, realistic prerequisites, demonstrated impact, severity rationale, remediation, and unresolved limitations.",
      "Finish with the exact outcome for this mode, strongest demonstrated impact, tests/controls and evidence references, source/JS/request links, reference skills/reports actually read, any specialist tasks called and their outcomes, confirmed/disproven/unresolved chain hops, validation/triage state, severity rationale, and remaining blockers. Do not say a finding is confirmed unless the durable validation and triage gates say so.",
    ].join("\n")

    const task = await TaskTool.init({ agent: reporter })
    const dispatched = await task.execute(
      {
        description,
        subagent_type: "impact-hunter",
        background: true,
        ...(existing ? { task_id: existing.id } : {}),
        ...(requestID ? { request_id: requestID } : {}),
        prompt,
      },
      { ...ctx, metadata: () => {} },
    )

    if (dispatched.metadata.outcome === "background" && dispatched.metadata.sessionId) {
      return { started: true, task_id: dispatched.metadata.sessionId, resumed: Boolean(existing), mode }
    }
    return {
      started: false,
      mode,
      task_id: dispatched.metadata.sessionId,
      reason: dispatched.output.slice(0, 1200) || "Impact Hunter did not enter background state",
    }
  } catch (error) {
    return { started: false, mode, reason: error instanceof Error ? error.message : String(error) }
  }
}

const impactHunterHandoffFlights = new Map<string, Promise<ImpactHunterHandoffResult>>()

export function startImpactHunterHandoff(
  ctx: Tool.Context,
  finding: Vulnerability.Info,
  mode: ImpactHunterMode,
): Promise<ImpactHunterHandoffResult> {
  if (ctx.agent === "impact-hunter") {
    return Promise.resolve({ started: false, mode, reason: "recursive Impact Hunter dispatch is disabled" })
  }

  const key = Session.root(ctx.sessionID) + ":" + finding.id + ":" + mode
  const active = impactHunterHandoffFlights.get(key)
  if (active) return active

  const pending = dispatch(ctx, finding, mode)
  impactHunterHandoffFlights.set(key, pending)
  const cleanup = () => {
    if (impactHunterHandoffFlights.get(key) === pending) {
      impactHunterHandoffFlights.delete(key)
    }
  }
  void pending.then(cleanup, cleanup)
  return pending
}
