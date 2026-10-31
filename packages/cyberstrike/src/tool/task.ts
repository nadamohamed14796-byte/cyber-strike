import { Tool } from "./tool"
import { AgentTaskConcurrency } from "./task-concurrency"
import DESCRIPTION from "./task.txt"
import z from "zod"
import { Session } from "../session"
import { MessageV2 } from "../session/message-v2"
import { Identifier } from "../id/id"
import { Agent } from "../agent/agent"
import { SessionPrompt } from "../session/prompt"
import { iife } from "@/util/iife"
import { defer } from "@/util/defer"
import { Config } from "../config/config"
import { PermissionNext } from "@/permission/next"
import { Request } from "../session/request"
import { Vulnerability } from "../session/vulnerability"
import { CoverageNote } from "../session/coverage-note"
import { WebCredential } from "../session/web/web-credential"
import { Observation } from "../session/observation"
import { evaluateImpactHunterGate, type ImpactHunterMode } from "../methodology/impact-hunter-gate"
import { renderAccessContextLines, resolveVisitedBy } from "../server/routes/session"
import { Truncate } from "./truncation"
import { dispatchScopeViolation, dispatchOffLaneMessage } from "./vuln-scope"
import {
  assertTaskResumeScope,
  isInternalImpactHandoff,
  requestIDFromRecentPromptTexts,
  requestIDsFromTaskPrompt,
  shouldInferSessionRequestID,
  selectTaskRequestContext,
} from "./task-resume"

// Per-field byte cap for raw request/response prepended into a subagent prompt.
// Raised 16KB→48KB: validation showed weak models (o4-mini) do NOT follow the
// "call web_get_request_detail" hint when content is truncated — they proceed on
// the head and MISS anything past the cap (e.g. a secret leaked at byte 30k). The
// cap is now large enough that most responses fit in-context (structural fix:
// don't depend on the model following a hint), affordable since prompt caching
// makes the extra tokens cheap. The full content stays retrievable via
// web_get_request_detail for the rare response that still exceeds this.
const MAX_PREPEND_BYTES = 48 * 1024

// A persistent Proxy Agent broker handles many captured requests in one child
// session. Resolve the latest trusted request identity in the current conversation,
// rather than binding every future Task call to the first capture in session history.

// Impact Hunter is the single designated internal background escalation path;
// unrelated task spawning still follows normal permission and dispatch guards.
const parameters = z.object({
  description: z.string().describe("A short (3-5 words) description of the task"),
  prompt: z.string().describe("The task for the agent to perform"),
  subagent_type: z.string().describe("The type of specialized agent to use for this task"),
  task_id: z
    .string()
    .describe(
      "This should only be set if you mean to resume a previous task (you can pass a prior task_id and the task will continue the same subagent session as before instead of creating a fresh one)",
    )
    .optional(),
  command: z.string().describe("The command that triggered this task").optional(),
  request_id: z.string().describe("Request ID to use as current request context (parent session).").optional(),
  request_context: z.string().describe("Optional text to prepend before the task (e.g. extra context).").optional(),
  background: z.boolean().describe("Start the subagent in the background and return its task_id immediately; use only when the caller can safely continue without the result.").optional(),
})

type TaskToolMetadata = {
  sessionId: string
  model: { modelID: string; providerID: string }
  outcome: "background" | "clean" | "aborted" | "errored" | "capped" | "stuck"
}

export const TaskTool = Tool.define<typeof parameters, TaskToolMetadata>("task", async (ctx) => {
  const registry = await Agent.entries()
  const agents = registry

  // Permission patterns and task arguments use stable registry keys, never
  // configurable display names. Keep the same key from discovery through Agent.get().
  const caller = ctx?.agent
  const callerID = await Agent.resolveID(caller)
  const accessibleAgents = caller
    ? agents.filter((entry) => entry.id === "impact-hunter" || PermissionNext.evaluate("task", entry.id, caller.permission).action !== "deny")
    : agents

  const description = DESCRIPTION.replace(
    "{agents}",
    accessibleAgents
      .map((entry) => `- ${entry.id}: ${entry.info.description ?? "This subagent should only be called manually by the user."}`)
      .join("\n"),
  )
  return {
    description,
    parameters,
    async execute(params: z.infer<typeof parameters>, ctx) {
      const config = await Config.get()
      const agent = await Agent.get(params.subagent_type)
      if (!agent) throw new Error(`Unknown agent type: ${params.subagent_type} is not a valid agent type`)

      // Impact Hunter is a designated escalation path. A task handoff is
      // permitted only for an existing finding that passes the independent
      // approval/validation/ledger gate below; ordinary task-spawning privileges
      // and scope/request enforcement remain separate.
      const impactHandoff = isInternalImpactHandoff({
        subagentType: params.subagent_type,
        background: params.background,
        caller: callerID,
        callerMode: caller?.mode,
      })

      // Every Impact Hunter launch is evidence-gated, including explicit
      // @-invocations that bypass ordinary task permissions.
      if (params.subagent_type === "impact-hunter") {
        const promptLines = params.prompt.split("\n").map((line) => line.trim())
        const promptField = (name: string) => promptLines
          .find((line) => line.startsWith(name + ":"))
          ?.slice(name.length + 1)
          .trim()
        const findingID = promptField("finding_id")
        if (!findingID) {
          throw new Error("Impact Hunter dispatch requires an exact finding_id in the task prompt.")
        }
        const modeValue = promptField("handoff_mode")
        if (modeValue !== "proof_gap" && modeValue !== "approved_impact") {
          throw new Error("Impact Hunter dispatch requires handoff_mode=proof_gap or handoff_mode=approved_impact.")
        }
        const mode: ImpactHunterMode = modeValue
        const rootSessionID = Session.root(ctx.sessionID)
        const finding = Vulnerability.get(rootSessionID).find((item) => item.id === findingID)
        if (!finding) {
          throw new Error("Impact Hunter dispatch is blocked: finding " + findingID + " was not found in the current session.")
        }

        const requestIDsInPrompt = (promptField("supporting_request_ids") ?? "")
          .split(",")
          .map((item) => item.trim())
          .filter((item) => item && item.toLowerCase() !== "none")
        const preferredRequestIDs = [...new Set([
          ...(params.request_id ? [params.request_id] : []),
          ...requestIDsInPrompt,
        ])]
        const gate = evaluateImpactHunterGate({
          finding,
          sessionID: rootSessionID,
          mode,
          preferredRequestIDs,
        })
        if (!gate.allowed) {
          throw new Error("Impact Hunter dispatch is blocked (" + mode + "): " + (gate.reason ?? "evidence gate did not pass") + ".")
        }

        if (mode === "approved_impact") {
          const baselineValidationID = promptField("baseline_validation_id")
          if (!baselineValidationID || baselineValidationID !== gate.baselineValidationID) {
            throw new Error("Impact Hunter dispatch is blocked: the prompt baseline_validation_id does not match the latest confirmed ten-check validation.")
          }
        }
      }

      // Skip permission check when user explicitly invoked via @ or command subtask,
      // or for the narrowly-scoped internal Impact Hunter handoff above.
      if (!ctx.extra?.bypassAgentCheck && !impactHandoff) {
        // Dispatch lane guard (Phase 4): the orchestrator must route each test to
        // the specialist whose lane owns it. Bounce a confidently mis-routed
        // proxy-tester dispatch (e.g. a rate-limiting task sent to business-logic)
        // with a re-dispatch hint instead of spawning a wasted subagent. Domain
        // logic lives in vuln-scope; here we only enforce. Only autonomous dispatch
        // is constrained — explicit user @-invocation is bypassAgentCheck and skips.
        const violation = dispatchScopeViolation(params.subagent_type, `${params.description}\n${params.prompt}`)
        if (violation) {
          return {
            title: `Dispatch rejected — ${params.subagent_type} out of lane`,
            output: dispatchOffLaneMessage(violation.cls, violation.inferred),
            // Match the success return's metadata shape so the tool's inferred
            // Metadata type stays consistent (no subtask was created here).
            metadata: { sessionId: "", model: { providerID: "", modelID: "" }, outcome: "clean" as const },
          }
        }

        await ctx.ask({
          permission: "task",
          patterns: [params.subagent_type],
          always: ["*"],
          metadata: {
            description: params.description,
            subagent_type: params.subagent_type,
          },
        })
      }

      // Ordinary primary-agent tasks have no session-bound captured request;
      // avoid scanning the main transcript unless a subagent is delegating.
      const sessionRequestID = shouldInferSessionRequestID({ name: callerID, mode: caller?.mode })
        ? requestIDFromRecentPromptTexts(
            ctx.messages
              .filter((message) => message.info.role === "user")
              .map((message) =>
                message.parts
                  .filter((part) => part.type === "text")
                  .map((part) => part.text)
                  .join("\n"),
              ),
          )
        : undefined
      // The primary orchestrator often writes the captured Request ID into the
      // delegated prompt but omits the dedicated request_id argument. Recover the
      // exact structured field for request-aware agents; never infer from arbitrary
      // prose, and reject multiple/conflicting identities instead of cross-binding.
      const promptRequestIDs = agent.prependRequestContext
        ? [...new Set([
            ...requestIDsFromTaskPrompt(params.prompt),
            ...requestIDsFromTaskPrompt(params.request_context ?? ""),
          ])]
        : []
      if (promptRequestIDs.length > 1) {
        throw new Error(
          "Task prompt contains multiple request IDs. Supply the single intended request_id explicitly to prevent cross-request context mixing.",
        )
      }
      const promptRequestID = promptRequestIDs[0]
      const requestedIDs = new Set(
        [params.request_id, promptRequestID, sessionRequestID].filter((value): value is string => Boolean(value)),
      )
      if (requestedIDs.size > 1) {
        throw new Error(
          "Request context mismatch: the supplied request_id, task prompt, and session-bound request identity do not agree. Use the exact current request ID.",
        )
      }
      // Prefer the explicit tool argument, then the structured task prompt, and
      // finally the persistent Proxy Agent transcript for follow-up delegation.
      const requestID = params.request_id ?? promptRequestID ?? sessionRequestID
      if (requestID && !Request.get(Session.root(ctx.sessionID)).some((request) => request.id === requestID)) {
        throw new Error(
          `Request context ${requestID} does not exist in the current root session. Refusing to start a subagent with unrelated or stale request evidence.`,
        )
      }

      const hasTaskPermission = PermissionNext.evaluate("task", "*", agent.permission).action !== "deny"

      const session = await iife(async () => {
        if (params.task_id) {
          const found = await Session.get(params.task_id).catch(() => {})
          if (!found) {
            // Never silently replace a requested resume with a fresh subtask: that
            // can repeat expensive testing and lose the checkpoint the caller meant to continue.
            throw new Error("Cannot resume task " + params.task_id + ": session not found; refusing to start a duplicate task.")
          }
          // Ordinary task IDs stay bound to their exact parent. The one
          // finding-specific Impact Hunter session may be resumed by another
          // agent under the SAME root session, but only when its title embeds
          // the exact finding ID carried by the independently checked handoff.
          const promptFindingID = params.prompt
            .split("\n")
            .map((line) => line.trim())
            .find((line) => line.startsWith("finding_id:"))
            ?.slice("finding_id:".length)
            .trim()
          const sameRootImpactHunter = params.subagent_type === "impact-hunter" &&
            Boolean(found.parentID) &&
            Session.root(found.parentID!) === Session.root(ctx.sessionID) &&
            Boolean(promptFindingID) &&
            found.title === "Impact Hunter finding " + promptFindingID + " (@impact-hunter subagent)"
          if (found.parentID !== ctx.sessionID && !sameRootImpactHunter) {
            assertTaskResumeScope(found, ctx.sessionID)
          }
          return found
        }

        return await Session.create({
          parentID: ctx.sessionID,
          title: params.description + ` (@${agent.name} subagent)`,
          permission: [
            {
              permission: "todowrite",
              pattern: "*",
              action: "deny",
            },
            {
              permission: "todoread",
              pattern: "*",
              action: "deny",
            },
            ...(hasTaskPermission
              ? []
              : [
                  {
                    permission: "task" as const,
                    pattern: "*" as const,
                    action: "deny" as const,
                  },
                ]),
            ...(config.experimental?.primary_tools?.map((t) => ({
              pattern: "*",
              action: "allow" as const,
              permission: t,
            })) ?? []),
          ],
        })
      })
      const msg = await MessageV2.get({ sessionID: ctx.sessionID, messageID: ctx.messageID })
      if (msg.info.role !== "assistant") throw new Error("Not an assistant message")

      // Inherit the caller's INTENDED model — its user-message model, NOT the
      // assistant message's model. The assistant model reflects the model actually
      // run, which for a useSmallModel caller (orchestrator/analyzer) is already
      // downgraded; inheriting it would force every dispatched tester onto the
      // small tier too. The user message keeps the original tier. The subagent's
      // own useSmallModel downgrade (if any) is applied at run time in the
      // SessionPrompt loop — never here.
      const model = agent.model ?? (await SessionPrompt.lastModel(ctx.sessionID))

      ctx.metadata({
        title: params.description,
        metadata: {
          sessionId: session.id,
          model,
        },
      })

      const messageID = Identifier.ascending("message")

      function cancel() {
        SessionPrompt.cancel(session.id)
      }
      ctx.abort.addEventListener("abort", cancel)
      using _ = defer(() => ctx.abort.removeEventListener("abort", cancel))

      let prompt = params.prompt
      // Cross-cutting handoff contract: every subagent receives the same routing
      // rule, regardless of which specialized prompt it was loaded from.
      if (params.subagent_type !== "impact-hunter") {
        prompt =
          "## Automatic Impact Hunter dispatch\n" +
          "report_vulnerability automatically starts one dedicated background Impact Hunter in proof_gap mode when the persisted finding is NEW and has an exact target-attributed endpoint plus a matching captured request or source file/line evidence anchor, and either (a) it is a candidate with a missing/incomplete class-appropriate PoC (execution-dependent classes also need an observed trigger), or (b) it is an INFO observation requiring chain investigation even if its own PoC is complete. For (a), investigate the missing PoC only and keep the finding NEW/unapproved. For (b), investigate evidence-backed chains only; never approve or report the INFO item alone. If a non-INFO candidate already has a complete PoC, complete all ten evidence-backed validation checks, record a durable CONFIRMED finding:<id> ledger outcome, compare the full similarity set, and call triage_vulnerability(status=\"approved\"). Only successful approval starts or resumes the same finding-specific Hunter in approved_impact mode. Do not manually create duplicate Hunter tasks. The Hunter may call other relevant specialist testers but must never dispatch another Impact Hunter. A started task is not a PoC, confirmation, triage, or impact verdict. Informational findings are chain precursors only: do not approve or report an INFO item by itself; seek evidence-backed complementary findings, test each chain hop, and report only a separately validated combined finding with demonstrated terminal impact. If no chain is proven, preserve the observation as a note/candidate.\n\n" +
          prompt
      }
      if (agent.prependRequestContext) {
        // Request records live on the root session; this also works when one
        // subagent delegates to another nested subagent.
        const requests = Request.get(Session.root(ctx.sessionID))
        const selection = selectTaskRequestContext(requests, requestID)
        const current = selection.request
        const lines: string[] = []
        if (params.request_context?.trim()) lines.push(params.request_context.trim())
        if (selection.reason === "request_not_found") {
          lines.push(
            "## Request Context Warning",
            `The requested request_id "${requestID ?? "missing"}" does not exist in the current root session.`,
            "No other request was substituted. Resolve the exact request ID before relying on request-specific context.",
          )
        } else if (selection.reason === "ambiguous_processing_requests") {
          lines.push(
            "## Request Context Warning",
            "Multiple requests are marked processing, so the current request is ambiguous.",
            "No request was substituted. Pass the exact request_id to attach the correct evidence.",
          )
        }
        if (current) {
          lines.push(
            "## Current request",
            `- request_id: ${current.id}`,
            `- session_id: ${current.session_id}`,
            `- method: ${current.method}`,
            `- normalized_path: ${current.normalized_path}`,
            `- origin: ${current.origin ?? "—"}`,
            `- status: ${current.status}`,
          )

          // App-wide coverage already recorded for this origin — reuse the verdict /
          // forged artifacts and do NOT re-test these deployment-wide classes here.
          const coverage = CoverageNote.wideBlock(Session.root(ctx.sessionID), current.origin ?? "")
          if (coverage) {
            lines.push("")
            lines.push(coverage)
          }

          // Credential context
          if (current.credential_id) {
            const cred = WebCredential.getById(current.credential_id)
            if (cred) {
              lines.push("")
              lines.push("## Credential Context")
              lines.push(`- credential_id: ${cred.id}`)
              lines.push(`- label: ${cred.label}`)
              if (cred.container_id) {
                lines.push(`- container_id: ${cred.container_id}`)
              }
              if (Object.keys(cred.headers).length > 0) {
                lines.push("- headers:")
                for (const [key, value] of Object.entries(cred.headers)) {
                  const displayValue = value.length > 80 ? value.slice(0, 80) + "..." : value
                  lines.push(`  - ${key}: ${displayValue}`)
                }
              }
              if (cred.role_id) {
                lines.push(`- role_id: ${cred.role_id}`)
              }
            }
          } else {
            lines.push("")
            lines.push("## Credential Context")
            lines.push("UNAUTHENTICATED (no credential associated with this request)")
          }

          // Access Context — derive visited_by from observed values so Firefox
          // traffic gains the legitimacy signal and hackbrowser gains full multi-cred set.
          const visitedBy = resolveVisitedBy({
            sessionID: Session.root(ctx.sessionID),
            keyHash: current.key_hash,
            captureVisitedBy: current.page_visited_by,
          })
          lines.push(
            ...renderAccessContextLines({
              triggerElement: current.trigger_element,
              elementRoles: current.element_roles,
              pageUrl: current.page_url,
              pageVisitedBy: visitedBy,
              uiContext: current.ui_context,
            }),
          )

          // Cap raw request/response before prepending. These can be up to
          // ~100KB each (and this path bypasses the tool-output truncation that
          // web_get_request_detail goes through), so without a cap a single big
          // request fans out into every dispatched subagent's prompt. The full
          // request/response stays available on demand via web_get_request_detail.
          const reqHint = (shown: number, total: number) =>
            `\n\n⚠️ TRUNCATED: only the first ${shown} of ${total} bytes are shown above. ` +
            `The rest (including anything past this point — params, headers, leaked data, sinks) is NOT visible here. ` +
            `You MUST call web_get_request_detail with request_id "${current.id}" to read the FULL request/response ` +
            `before you conclude anything about this endpoint — do NOT decide based only on this truncated head.`
          if (current.raw_request) {
            lines.push(
              "",
              "## Raw HTTP Request",
              "```",
              Truncate.cap(current.raw_request, MAX_PREPEND_BYTES, reqHint),
              "```",
            )
          }

          // Response
          if (current.processed_response) {
            lines.push(
              "",
              "## Response",
              "```",
              Truncate.cap(current.processed_response, MAX_PREPEND_BYTES, reqHint),
              "```",
            )
          }
        }
        if (lines.length > 0) prompt = lines.join("\n") + "\n\n" + prompt
      }

      // Methodology prompt context is disabled centrally for all agents.
      // Task creation and resumption do not consult methodology phase state.
      const promptParts = await SessionPrompt.resolvePromptParts(prompt)

      const promptInput = {
        messageID,
        sessionID: session.id,
        model: {
          modelID: model.modelID,
          providerID: model.providerID,
        },
        agent: params.subagent_type,
        tools: {
          todowrite: false,
          todoread: false,
          ...Object.fromEntries((config.experimental?.primary_tools ?? []).map((t) => [t, false])),
        },
        parts: promptParts,
      }

      // Keep Main Recon and Extension Proxy as independent execution lanes.
      // Each lane may run two sibling specialists; the process-wide scheduler
      // admits at most three agent loops so a fan-out cannot exhaust WSL memory.
      const taskLane = `${Session.root(ctx.sessionID)}:${params.subagent_type === "impact-hunter" ? "impact" : callerID === "proxy-agent" ? "extension" : "main"}`

      if (params.background) {
        // Persist the child prompt immediately, then queue its detached loop through
        // the same bounded scheduler. Queued work is retained and starts when a
        // slot opens; it is never silently dropped.
        await SessionPrompt.prompt({ ...promptInput, noReply: true })
        const schedule = AgentTaskConcurrency.enqueue(
          taskLane,
          async () => {
            await SessionPrompt.loop({ sessionID: session.id })
          },
          (error) => {
            console.error("[task] background subagent failed", {
              sessionID: session.id,
              agent: agent.name,
              error: error instanceof Error ? error.message : String(error),
            })
          },
        )
        return {
          title: params.description,
          metadata: {
            sessionId: session.id,
            model,
            outcome: "background" as const,
          },
          output: [
            schedule === "started"
              ? `Background task started: ${params.description}`
              : `Background task queued: ${params.description} (waiting for an agent slot)`,
            `task_id: ${session.id} (resume this exact task_id to inspect or continue its results)`,
            schedule === "started"
              ? "The subagent is still running; this is not a completion or success verdict."
              : "The subagent prompt is saved and will start automatically when a slot opens; this is not a completion or success verdict.",
          ].join("\n"),
        }
      }

      // Orchestrator-level fan-out is bounded, while nested subagent delegation
      // remains re-entrant so a parent waiting on a child cannot deadlock the pool.
      // Proxy Agent runs directly inside the persistent Broker rather than
      // through TaskTool, so its sibling specialists must acquire scheduler slots.
      // Other subagents already occupy a parent slot; their nested foreground
      // delegation stays re-entrant to avoid parent/child pool deadlocks.
      const isManagedSubagent = caller?.mode === "subagent" && callerID !== "proxy-agent"
      const result = isManagedSubagent
        ? await SessionPrompt.prompt(promptInput)
        : await AgentTaskConcurrency.run(taskLane, () => SessionPrompt.prompt(promptInput))

      const text = result.parts.findLast((x) => x.type === "text")?.text ?? ""

      // Classify the subagent's ACTUAL outcome from its final assistant message so
      // the parent's recording gate (session/prompt.ts) doesn't count an aborted /
      // errored / step-capped run as a successful mission. The child loop swallows
      // aborts/errors into info.error and still returns a result, and a step-capped
      // run looks like a clean finish:"stop" — both previously recorded success:true.
      const childInfo = result.info
      const childError = childInfo.role === "assistant" ? childInfo.error : undefined
      const outcome: "clean" | "aborted" | "errored" | "capped" | "stuck" = childError
        ? MessageV2.AbortedError.isInstance(childError)
          ? "aborted"
          : "errored"
        : childInfo.role === "assistant" && (childInfo.stuckAborted || childInfo.stuckNudged)
          ? "stuck"
          : childInfo.role === "assistant" && childInfo.stepCapped
            ? "capped"
            : "clean"

      const statusBanner =
        outcome === "clean"
          ? null
          : outcome === "aborted"
            ? "INCOMPLETE: this subagent was ABORTED before finishing. Its results are partial and were NOT credited as tested."
            : outcome === "errored"
              ? `INCOMPLETE: this subagent ERRORED before finishing (${(childError as { name?: string })?.name ?? "error"}). Its results are partial and were NOT credited as tested.`
              : outcome === "stuck"
                ? "INCOMPLETE: this subagent repeated actions or status checks without completing its assigned work. Its results are partial and were NOT credited as tested."
                : "INCOMPLETE: this subagent hit its step limit and was forced to wrap up before finishing. Its results may be partial and were NOT credited as tested."

      const output = [
        ...(statusBanner ? [`<task_status>${statusBanner}</task_status>`, ""] : []),
        `task_id: ${session.id} (for resuming to continue this task if needed)`,
        "",
        "<task_result>",
        text,
        "</task_result>",
      ].join("\n")

      return {
        title: params.description,
        metadata: {
          sessionId: session.id,
          model,
          outcome,
        },
        output,
      }
    },
  }
})
