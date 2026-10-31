import { Agent } from "../agent/agent"
import { Session } from "../session"
import { TaskTool } from "../tool/task"
import type { Tool } from "../tool/tool"
import { requestIDFromRecentPromptTexts } from "../tool/task-resume"
import { Vulnerability } from "../session/vulnerability"
import { FindingValidation, hasCompleteConfirmedValidation } from "./finding-validation"
import { redactTargetNoteSecrets } from "../target/redact"

export interface ImpactHunterHandoffResult {
  started: boolean
  task_id?: string
  resumed?: boolean
  reason?: string
}

/**
 * Dispatch one independent Impact Hunter task only for a finding that has
 * already passed ten-check validation and explicit triage approval.
 *
 * The Hunter's purpose is to investigate whether the proven primitive can
 * reach a stronger real-world impact, not to inflate severity or re-test an
 * unvalidated scanner lead.
 */
async function dispatch(
  ctx: Tool.Context,
  finding: Vulnerability.Info,
): Promise<ImpactHunterHandoffResult> {
  if (ctx.agent === "impact-hunter") {
    return { started: false, reason: "recursive Impact Hunter dispatch is disabled" }
  }

  try {
    const reporter = await Agent.get(ctx.agent)
    if (!reporter) return { started: false, reason: `reporting agent "${ctx.agent}" is not registered` }

    const baselineValidation = FindingValidation.history({
      sessionID: Session.root(ctx.sessionID),
      vulnerabilityID: finding.id!,
      limit: 1,
    })[0]
    if (!hasCompleteConfirmedValidation(baselineValidation)) {
      return { started: false, reason: "latest validation does not contain ten complete evidence-backed checks; Impact Hunter dispatch is blocked" }
    }

    const description = `Impact Hunter finding ${finding.id}`
    const childTitle = description + " (@impact-hunter subagent)"
    const existing = (await Session.children(ctx.sessionID)).find((child) => child.title === childTitle)
    const requestID = requestIDFromRecentPromptTexts(
      ctx.messages
        .filter((message) => message.info.role === "user")
        .map((message) =>
          message.parts.filter((part) => part.type === "text").map((part) => part.text).join("\n"),
        ),
    )

    const task = await TaskTool.init({ agent: reporter })
    const dispatched = await task.execute(
      {
        description,
        subagent_type: "impact-hunter",
        background: true,
        ...(existing ? { task_id: existing.id } : {}),
        ...(requestID ? { request_id: requestID } : {}),
        prompt: [
          "A finding has passed all ten evidence-based validation checks, has an evidence-backed CONFIRMED outcome in the durable verification ledger, and has been explicitly approved by triage. Investigate whether this proven primitive can reach a stronger real-world security impact. Do not restart the initial validation from zero or create a duplicate finding.",
          `finding_id: ${finding.id}`,
          `title: ${redactTargetNoteSecrets(finding.title)}`,
          `approved_severity: ${finding.severity}`,
          `endpoint: ${finding.endpoint ?? "not recorded"}`,
          `status: ${finding.status}`,
          `request_id: ${requestID ?? "not bound to a single captured request"}`,
          `baseline_validation_id: ${baselineValidation.id}`,
          `baseline_validation_time: ${new Date(baselineValidation.time_created).toISOString()}`,
          "",
          "Load this exact finding and inspect its latest confirmed validation, durable verification attempts, complete request/response evidence, role/account context, and linked artifacts. Use the already-proven weakness as the starting point. The original hypothesis key finding:<finding_id> is already terminal CONFIRMED; do not try to append more attempts to it.",
          "Your objective is to test evidence-supported adjacent impact and chains: identify the next meaningful boundary, prerequisite, reachable operation, controlled fixture, expected secure behavior, vulnerable signal, and disconfirming control. Explore the strongest safe hypothesis first; do not try unrelated classes or arbitrary payloads.",
          "Use only authorized scope, tester-owned accounts, synthetic records, reversible actions, and minimum-impact proof. Never access real users' private data, extract secrets, perform destructive actions, trigger real payments/messages, or cross into a third-party/out-of-scope service.",
          "A low, informational, or medium rating is a reason to assess realistic impact paths, not a promise that escalation exists. Do not chase the highest numeric severity. Raise severity only when additional confidentiality, integrity, availability, privilege, or business impact is independently demonstrated and reproducible; otherwise preserve the current rating.",
          "For each new impact-escalation hypothesis, record durable verification_attempt evidence under a distinct stable key shaped like finding:<finding_id>:impact:<short-hypothesis-slug>; the original finding:<finding_id> key is terminal and must not be reused. After an impact hypothesis is confirmed, run validate_finding again with all ten checks using the new evidence. Use update_finding_impact only after that newer validation is confirmed; provide baseline_validation_id from this task handoff, the exact impact hypothesis key, exact evidence references, and a rationale tied to the demonstrated consequence. Update the same finding, never create a second row for the same root cause.",
          "If a meaningful escalation path is disproven, record which check/test and observed evidence disproved it. If it is blocked or untested, record the missing prerequisite and why. Keep the original finding valid and its existing severity when no stronger impact is proven.",
          "Finish with the strongest demonstrated impact, tests/controls and evidence references, any verified chain hops, final severity rationale, and exact unresolved blockers. Do not report speculative downstream impact as fact.",
        ].join("\n"),
      },
      { ...ctx, metadata: () => {} },
    )

    if (dispatched.metadata.outcome === "background" && dispatched.metadata.sessionId) {
      return { started: true, task_id: dispatched.metadata.sessionId, resumed: Boolean(existing) }
    }
    return {
      started: false,
      reason: dispatched.output.slice(0, 1200) || `Hunter ended with outcome "${dispatched.metadata.outcome}"`,
    }
  } catch (error) {
    return { started: false, reason: error instanceof Error ? error.message : String(error) }
  }
}

const impactHunterHandoffFlights = new Map<string, Promise<ImpactHunterHandoffResult>>()

export function startImpactHunterHandoff(
  ctx: Tool.Context,
  finding: Vulnerability.Info,
): Promise<ImpactHunterHandoffResult> {
  if (ctx.agent === "impact-hunter") {
    return Promise.resolve({ started: false, reason: "recursive Impact Hunter dispatch is disabled" })
  }
  if (finding.status !== "approved") {
    return Promise.resolve({ started: false, reason: "finding must be explicitly approved before Impact Hunter dispatch" })
  }

  const key = Session.root(ctx.sessionID) + ":" + finding.id
  const active = impactHunterHandoffFlights.get(key)
  if (active) return active

  const pending = dispatch(ctx, finding)
  impactHunterHandoffFlights.set(key, pending)
  const cleanup = () => {
    if (impactHunterHandoffFlights.get(key) === pending) {
      impactHunterHandoffFlights.delete(key)
    }
  }
  void pending.then(cleanup, cleanup)
  return pending
}
