import { Tool } from "./tool"
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
import { CoverageNote } from "../session/coverage-note"
import { WebCredential } from "../session/web/web-credential"
import { Observation } from "../session/observation"
import { renderAccessContextLines, resolveVisitedBy } from "../server/routes/session"
import { Truncate } from "./truncation"
import { dispatchScopeViolation, dispatchOffLaneMessage } from "./vuln-scope"
import {
  assertTaskResumeScope,
  isInternalImpactHandoff,
  requestIDFromRecentPromptTexts,
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
  const agents = await Agent.entries().then((x) => x.filter((entry) => entry.info.mode !== "primary"))

  // Permission patterns and task arguments use stable registry keys, never
  // configurable display names. Keep the same key from discovery through Agent.get().
  const caller = ctx?.agent
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

      // Impact Hunter is a designated internal escalation path. Any subagent may
      // hand off an evidence-backed finding to it in background mode without
      // gaining general task-spawning privileges. Scope and request tools remain
      // enforced inside Impact Hunter.
      const impactHandoff = isInternalImpactHandoff({
        subagentType: params.subagent_type,
        background: params.background,
        caller: caller?.name,
        callerMode: caller?.mode,
      })

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

      const agent = await Agent.get(params.subagent_type)
      if (!agent) throw new Error(`Unknown agent type: ${params.subagent_type} is not a valid agent type`)

      // Ordinary primary-agent tasks have no session-bound captured request;
      // avoid scanning the main transcript unless a subagent is delegating.
      const sessionRequestID = shouldInferSessionRequestID(caller)
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
      if (sessionRequestID && params.request_id && params.request_id !== sessionRequestID) {
        throw new Error(
          `Request context mismatch: this subagent session is bound to request ${sessionRequestID}, but task request_id ${params.request_id} was supplied. Use the current session's request ID to avoid cross-request context mixing.`,
        )
      }
      // Prefer the session-bound request ID automatically when the model omits
      // the optional argument. An explicit conflicting ID is rejected above.
      const requestID = params.request_id ?? sessionRequestID

      const hasTaskPermission = agent.permission.some((rule) => rule.permission === "task")

      const session = await iife(async () => {
        if (params.task_id) {
          const found = await Session.get(params.task_id).catch(() => {})
          if (!found) {
            // Never silently replace a requested resume with a fresh subtask: that
            // can repeat expensive testing and lose the checkpoint the caller meant to continue.
            throw new Error("Cannot resume task " + params.task_id + ": session not found; refusing to start a duplicate task.")
          }
          // Task IDs are model-supplied input. Only resume a child owned by this
          // exact parent session; otherwise a stale/arbitrary ID could attach
          // another session's private history to the current agent's task.
          assertTaskResumeScope(found, ctx.sessionID)
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
      if (agent.name !== "impact-hunter") {
        prompt =
          "## Automatic Impact Hunter dispatch\n" +
          "Every successful report_vulnerability call automatically starts or resumes one dedicated background Impact Hunter task for that persisted finding. The report tool returns its task_id and status. Do NOT manually start a second Hunter task for the same finding. Continue your assigned work independently; a started Hunter task is not a confirmation verdict.\n\n" +
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

      // NOTE: methodology context is NOT injected here. The subagent's own run loop
      // (session/prompt.ts) pushes MethodologyContext.generate(root, testerClass(agent))
      // into the system prompt on EVERY turn (lane-scoped identically), and that prefix
      // is prompt-cached. Prepending it here too only duplicated it into turn-1's user
      // message. The system-prompt path covers all subagent sessions, so this is the
      // single source.
      const promptParts = await SessionPrompt.resolvePromptParts(prompt)

      const promptInput = {
        messageID,
        sessionID: session.id,
        model: {
          modelID: model.modelID,
          providerID: model.providerID,
        },
        agent: agent.name,
        tools: {
          todowrite: false,
          todoread: false,
          ...Object.fromEntries((config.experimental?.primary_tools ?? []).map((t) => [t, false])),
        },
        parts: promptParts,
      }

      if (params.background) {
        // Persist the child prompt first, then run its normal session loop without
        // awaiting completion. The child session is already linked to this parent,
        // so the caller can continue recon and resume the child later by task_id.
        await SessionPrompt.prompt({ ...promptInput, noReply: true })
        void SessionPrompt.loop({ sessionID: session.id }).catch((error) => {
          console.error("[task] background subagent failed", {
            sessionID: session.id,
            agent: agent.name,
            error: error instanceof Error ? error.message : String(error),
          })
        })
        return {
          title: params.description,
          metadata: {
            sessionId: session.id,
            model,
            outcome: "background" as const,
          },
          output: [
            `Background task started: ${params.description}`,
            `task_id: ${session.id} (resume this exact task_id to inspect or continue its results)`,
            "The subagent is still running; this is not a completion or success verdict.",
          ].join("\n"),
        }
      }

      const result = await SessionPrompt.prompt(promptInput)

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
