// Hackbrowser tool — agent-callable wrapper around the hackbrowser library.
// All cyberstrike→hackbrowser plumbing (Provider, Server URL, log bridge,
// re-entrance) lives in hackbrowser-launcher.ts; this file is just the
// Tool.define surface (parameters, permission gate, output shape).
//
// Surface is shared with the /hackbrowser slash command and the
// `cyberstrike hackbrowser` CLI subcommand — same fields, same semantics
// across all three entry points.

import z from "zod"
import { Tool } from "./tool"
import { launchHackbrowser } from "./hackbrowser-launcher"
import { AuthVault, normalizeAuthOrigin } from "../auth-vault"
import { GmailService } from "../gmail-service"
import { TargetMemory } from "../target"

const DESCRIPTION = `Crawl a web application autonomously and capture HTTP requests with UI context.

Use this when you have a target URL but no captured requests yet — hackbrowser will navigate the app, fill forms, click buttons, and stream every HTTP request into the current session for later vulnerability analysis. After captures arrive, the proxy-analyzer ingest pipeline analyzes them automatically.

This tool runs ASYNCHRONOUSLY: it returns immediately after starting the background crawl. Captures stream into the session over the next 30s–2min. Do NOT call this tool again to "wait" for results — use web_get_session_context to inspect captured endpoints when you actually need them. The hackbrowser status (running / completed / failed) appears in the TUI sidebar.

Defaults to anonymous headless mode. To crawl as authenticated user(s), pass \`credentials\` — the browser opens visibly and the user must log in manually before the crawl begins. Each credential ID in the array triggers its own login + crawl cycle, so multiple IDs run a sequence (role-based access tests). A saved login profile may be supplied via auth_profile_id; CyberStrike decrypts it locally, checks the exact origin and target binding, and fills the login form in a visible browser. CAPTCHA, passkeys, MFA, and unusual login forms may still need human interaction. Never put passwords in tool arguments or target notes.`

export const HackbrowserTool = Tool.define("hackbrowser", {
  description: DESCRIPTION,
  parameters: z.object({
    target: z
      .string()
      .url()
      .describe(
        "Target URL to crawl. Used both as the start of navigation and as the basis for the auto-derived network scope (*.{eTLD+1}).",
      ),
    credentials: z
      .array(z.string())
      .optional()
      .describe(
        "Credential IDs to crawl as. Omit (or empty) for anonymous crawl. " +
          "One ID: opens the browser visibly, waits for the user to log in manually, then crawls — captures are tagged with this credential. " +
          "Two or more IDs: repeats the manual-login + crawl cycle once per credential, tagging captures per identity (role-based access tests). " +
          "Forces headless: false. Only use when a human is present to complete each login.",
      ),
    auth_profile_id: z.string().optional().describe("Optional profile ID saved with auth_manager. Never pass a password here."),
    auth_purpose: z.enum(["research", "target"]).optional().describe("Purpose for auth_profile_id; defaults to target. Target profiles also require auth_target_id."),
    auth_target_id: z.string().optional().describe("Stable target workspace ID bound to a target-purpose saved profile."),
    use_gmail_otp: z.boolean().optional().describe("When true, ask permission to read Gmail and try a recent matching OTP automatically; unmatched challenges fall back to human input."),
    scope: z
      .array(z.string())
      .optional()
      .describe(
        'Optional network scope override. Hostname patterns ("*.example.com") that bound which requests get captured. Replaces the auto-derived default.',
      ),
    exclude: z
      .array(z.string())
      .optional()
      .describe(
        'Optional UI labels the planner must skip (e.g. "Delete Account", "Cancel Subscription"). Semantic match.',
      ),
    steps: z.number().int().min(1).max(200).optional().describe("Maximum number of pages to crawl. Defaults to 50."),
    headless: z
      .boolean()
      .optional()
      .describe(
        "Open the browser with a visible window when false. Defaults to true; saved profiles and manual credential IDs force a visible browser.",
      ),
  }),
  async execute(args, ctx) {
    if (args.use_gmail_otp && !args.auth_profile_id) {
      return { title: "Saved login profile required", output: "Gmail OTP assistance can only be enabled together with auth_profile_id.", metadata: { started: false, reason: "profile_required" } }
    }
    if (args.auth_profile_id && args.credentials?.length) {
      return { title: "Conflicting authentication options", output: "Use either auth_profile_id for a saved login or credentials for manual identity-tagged login, not both.", metadata: { started: false, reason: "conflicting_auth" } }
    }

    // Permission gate — opening a browser + outbound network is high-risk;
    // require explicit consent. Pattern is the target URL so the user can
    // grant blanket permission for a host on first use.
    await ctx.ask({
      permission: "hackbrowser",
      patterns: [args.target],
      always: [args.target],
      metadata: { scope: args.scope, exclude: args.exclude },
    })

    let savedLogin: { username: string; password: string; origin: string; useGmailOtp?: boolean } | undefined
    if (args.auth_profile_id) {
      const purpose = args.auth_purpose ?? "target"
      const origin = normalizeAuthOrigin(args.target)
      if (purpose === "target") {
        if (!args.auth_target_id?.trim()) return { title: "Target ID required", output: "Target-purpose saved logins require auth_target_id. No credential was read.", metadata: { started: false, reason: "target_id_required" } }
        const workspace = TargetMemory.list().find((item) => item.id === args.auth_target_id && normalizeAuthOrigin(item.targetURL) === origin)
        if (!workspace) return { title: "Target binding mismatch", output: "No existing target workspace with this ID matches the exact site origin. No credential was read.", metadata: { started: false, reason: "target_binding_mismatch" } }
      }
      if (args.use_gmail_otp) {
        if (!GmailService.status().configured) return { title: "Gmail is not configured", output: "Configure the Gmail OAuth environment variables before enabling browser OTP assistance. No website credential was read.", metadata: { started: false, reason: "gmail_not_configured" } }
        await ctx.ask({ permission: "gmail-read", patterns: [origin], always: [], metadata: { purpose, targetID: args.auth_target_id, source: "hackbrowser-mfa" } })
      }
      await ctx.ask({ permission: "auth-credential-use", patterns: [origin], always: [], metadata: { profileID: args.auth_profile_id, purpose, targetID: args.auth_target_id } })
      const profile = await AuthVault.getSecret({ id: args.auth_profile_id, origin, purpose, targetID: purpose === "target" ? args.auth_target_id : undefined })
      if (!profile) return { title: "Saved login not found", output: "No saved profile matched the exact origin, purpose, and target binding. No credentials were sent to the browser.", metadata: { started: false, reason: "profile_not_found" } }
      savedLogin = { username: profile.username, password: profile.password, origin: profile.origin, useGmailOtp: !!args.use_gmail_otp }
    }

    // Fire and forget — launchHackbrowser returns immediately after sync
    // prep (Provider resolve, Server URL, log sink). The actual runCrawl
    // runs in a background IIFE so the chat session prompt loop unblocks
    // and ingest queue tasks (proxy-analyzer dispatches) can run in
    // parallel (INTEGRATION.md §10.9 / §13.6).
    const kickOff = await launchHackbrowser({
      target: args.target,
      sessionID: ctx.sessionID,
      scope: args.scope,
      exclude: args.exclude,
      credentials: args.credentials,
      savedLogin,
      steps: args.steps,
      headless: savedLogin ? false : args.headless,
      // Intentionally NOT passing signal: ctx.abort. ctx.abort is the agent
      // TURN's abort — it fires on every normal turn-end (cancel → match.abort),
      // which would forward an abort to the worker and kill the still-running
      // background crawl. The crawl is stopped only via stopHackbrowser (Esc /
      // session-delete / /hackbrowser-stop), never the turn lifecycle.
    }).finally(() => { if (savedLogin) savedLogin.password = "" })

    // Output is intentionally a "started" notice, NOT a result summary.
    // Spell-out is for weak LLMs — see feedback_weak_llm_baseline:
    // explicit "do NOT poll" + "use web_get_session_context when you
    // need them" prevents looped re-invocation.
    const output = [
      `Hackbrowser crawl started for ${args.target}.`,
      ...(savedLogin ? ["Saved login profile was supplied to the visible browser. Credentials are not included in this response."] : []),
      ...(savedLogin?.useGmailOtp ? ["Gmail OTP assistance is enabled for matching recent verification emails; if none is found, the browser will request human input."] : []),
      `Captures stream into this session as the crawl progresses (typically 30s–2min).`,
      ``,
      `Do NOT call this tool again to wait for results — it is already running.`,
      `Use web_get_session_context to inspect captured endpoints when you need them.`,
      `Live progress (running / completed / failed) appears in the TUI sidebar.`,
    ].join("\n")

    return {
      title: `hackbrowser ${args.target}`,
      output,
      metadata: {
        sessionID: kickOff.sessionID,
        started: kickOff.started,
      },
    }
  },
})
