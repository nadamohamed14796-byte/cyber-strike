import z from "zod"
import { AuthVault } from "../auth-vault"
import { GmailService } from "../gmail-service"
import { Tool } from "./tool"

export const AuthManagerTool = Tool.define("auth_manager", {
  description: [
    "Manage locally saved website login profiles shared by CyberStrike agents. Use this when a site presents a login wall or an authenticated session expires.",
    "Profiles are matched by exact URL origin (scheme + hostname + port), never by substring. Research accounts are separate from target accounts; target accounts require the current explicit targetID.",
    "Passwords are encrypted at rest with AES-256-GCM. Set CYBERSTRIKE_CREDENTIALS_KEY to a private secret of at least 32 characters before using this tool. The key is not stored by CyberStrike.",
    "Actions: save a profile, list matching profiles (metadata only), or forget a profile. Passwords are never returned by this agent-facing tool. This tool stores credentials; it does not itself bypass login challenges or automate browser form submission. CAPTCHA, MFA, and consent screens require the supported human flow.",
    "For save, provide the password only through CYBERSTRIKE_AUTH_PASSWORD in the CyberStrike process environment; the tool never accepts a password argument, so secrets do not enter model tool-call history. The variable is cleared after use. Never save Google account passwords here for mailbox access. Gmail OTP integration must use a separate explicit Google OAuth grant with minimum scopes.",
  ].join("\n"),
  parameters: z.object({
    action: z.enum(["save", "list", "forget", "gmail_otp"]),
    site_url: z.string().url().describe("Site URL; only its exact origin is used for matching."),
    purpose: z.enum(["research", "target"]),
    target_id: z.string().optional().describe("Required for target-purpose profiles; use the stable current target identifier."),
    profile_id: z.string().optional().describe("Profile ID for forget."),
    after: z.number().int().positive().optional().describe("Optional Unix timestamp in milliseconds; only consider OTP messages received after this time."),
    account: z.string().optional().describe("Human-readable account label, e.g. researcher-main."),
    username: z.string().optional().describe("Login username/email."),
  }),
  async execute(params, ctx) {
    if (params.purpose === "target" && !params.target_id?.trim()) {
      return { title: "Target ID required", output: "Target credentials must be bound to an explicit target_id. No credentials were read or written.", metadata: { ok: false } }
    }
    if (params.action === "gmail_otp") {
      await ctx.ask({ permission: "gmail-otp-read", patterns: [params.site_url], always: [], metadata: { purpose: params.purpose, targetID: params.target_id } })
      const result = await GmailService.latestOtp({ siteUrl: params.site_url, after: params.after })
      if (!result) return { title: "No matching OTP email", output: "No recent verification code was found from the site's exact hostname or a subdomain. Third-party senders are intentionally ignored.", metadata: { found: false } }
      return {
        title: "Verification code found",
        output: `Found a recent verification email from ${result.from} (subject: ${result.subject}). Code: ${result.code}. Received: ${result.date}. Use it only to continue the login flow you initiated.`,
        metadata: { found: true, messageID: result.id, receivedAt: result.receivedAt },
      }
    }
    if (params.action === "save") {
      if (!params.account?.trim() || !params.username?.trim()) {
        return { title: "Missing account details", output: "Saving requires account and username.", metadata: { ok: false } }
      }
      const password = process.env.CYBERSTRIKE_AUTH_PASSWORD
      if (!password) {
        return { title: "Password not provided securely", output: "Set CYBERSTRIKE_AUTH_PASSWORD in the CyberStrike process environment, then retry. The password is intentionally not accepted as a tool argument because tool arguments may be stored in conversation history.", metadata: { ok: false, reason: "secure_password_missing" } }
      }
      delete process.env.CYBERSTRIKE_AUTH_PASSWORD
      await ctx.ask({ permission: "auth-credential-save", patterns: [params.site_url], always: [], metadata: { purpose: params.purpose, targetID: params.target_id, account: params.account } })
      const saved = await AuthVault.save({
        origin: params.site_url, purpose: params.purpose, account: params.account,
        username: params.username, password, targetID: params.target_id,
      })
      return { title: "Login profile saved", output: `Saved encrypted profile "${saved.account}" for ${saved.origin} (${saved.purpose}). Profile ID: ${saved.id}. Secret is not included in this response.`, metadata: { ok: true, profileID: saved.id, origin: saved.origin, purpose: saved.purpose } }
    }
    if (params.action === "list") {
      const profiles = await AuthVault.list({ origin: params.site_url, purpose: params.purpose, targetID: params.target_id })
      return { title: "Saved login profiles", output: profiles.length ? profiles.map((p) => `- ${p.account} | ${p.username} | id=${p.id} | ${p.origin} | ${p.purpose} | updated=${new Date(p.updatedAt).toISOString()}`).join("\n") : "No saved profile matches this exact origin and purpose.", metadata: { count: profiles.length } }
    }
    if (!params.profile_id) return { title: "Profile ID required", output: "Provide profile_id to forget a saved login profile.", metadata: { ok: false } }
    await ctx.ask({ permission: "auth-credential-delete", patterns: [params.site_url], always: [], metadata: { purpose: params.purpose, targetID: params.target_id, profileID: params.profile_id } })
    const removed = await AuthVault.remove({ id: params.profile_id, origin: params.site_url, purpose: params.purpose, targetID: params.target_id })
    return { title: removed ? "Login profile forgotten" : "Profile not found", output: removed ? "The matching saved profile was deleted." : "No profile matched that ID, exact origin, purpose, and target binding.", metadata: { ok: removed } }
  },
})
