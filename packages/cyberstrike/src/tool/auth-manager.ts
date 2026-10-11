import z from "zod"
import fs from "node:fs/promises"
import { randomBytes } from "node:crypto"
import path from "node:path"
import { AuthVault, normalizeAuthOrigin } from "../auth-vault"
import { GmailService } from "../gmail-service"
import { TargetMemory } from "../target"
import { redactTargetNoteLine } from "../target/redact"
import { Tool } from "./tool"

/**
 * Keep a human-readable index of saved account references inside the target
 * workspace. Passwords remain only in AuthVault's encrypted local store.
 */
async function syncTargetProfileIndex(siteURL: string, targetID: string): Promise<void> {
  const origin = normalizeAuthOrigin(siteURL)
  const listedWorkspace = TargetMemory.list().find((item) => item.id === targetID && normalizeAuthOrigin(item.targetURL) === origin)
  if (!listedWorkspace) {
    throw new Error("Target account reference was not written: target_id must identify an existing workspace with the same exact origin.")
  }

  // list() is metadata-only. Re-open through TargetMemory.get() so the
  // workspace's on-disk path is checked for symlink escapes before any write.
  const workspace = await TargetMemory.get(listedWorkspace.targetURL)
  if (!workspace || workspace.id !== targetID) {
    throw new Error("Target account reference was not written: the workspace path could not be safely verified.")
  }

  const profiles = await AuthVault.list({ purpose: "target", targetID })
  const lines = [
    "# Saved account references",
    "",
    "> This file contains references only. Passwords are stored encrypted in CyberStrike's local auth vault and must never be copied here.",
    "",
    ...profiles.flatMap((profile) => [
      `## ${redactTargetNoteLine(profile.account, 120).replace(/#/g, " ")}`,
      "",
      `- Profile ID: ${profile.id}`,
      `- Origin: ${profile.origin}`,
      `- Updated: ${new Date(profile.updatedAt).toISOString()}`,
      "- Password: stored encrypted in the local AuthVault; not present in this file",
      "",
    ]),
  ]
  const file = path.join(workspace.workspacePath, "auth-profiles.md")
  try {
    const info = await fs.lstat(file)
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error("Saved-account index path is unsafe; refusing to follow a symbolic link or non-regular file.")
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
  }

  // Atomic replacement avoids following a pre-existing file symlink and
  // prevents readers from seeing a partially written index.
  const temp = file + "." + process.pid + "." + randomBytes(6).toString("hex") + ".tmp"
  try {
    await fs.writeFile(temp, lines.join("\n") + "\n", { encoding: "utf8", mode: 0o600, flag: "wx" })
    await fs.rename(temp, file)
    await fs.chmod(file, 0o600)
  } finally {
    await fs.rm(temp, { force: true }).catch(() => undefined)
  }
}
export const AuthManagerTool = Tool.define("auth_manager", {
  description: [
    "Manage locally saved website login profiles shared by CyberStrike agents. Use this when a site presents a login wall or an authenticated session expires.",
    "Profiles are matched by exact URL origin (scheme + hostname + port), never by substring. Research accounts are separate from target accounts; target accounts require the current explicit targetID.",
    "Passwords are encrypted at rest with AES-256-GCM. Set CYBERSTRIKE_CREDENTIALS_KEY to a private secret of at least 32 characters before using this tool. The key is not stored by CyberStrike.",
    "Actions: save, list, or forget a website login profile, or request a site-specific OTP through the shared Gmail service. Passwords are never returned by this agent-facing tool. Hackbrowser can use a saved profile for visible, exact-origin login autofill; CAPTCHA, passkeys, MFA, and consent screens may still require human interaction.",
    "For save, provide the password only through CYBERSTRIKE_AUTH_PASSWORD in the CyberStrike process environment; the tool never accepts a password argument, so secrets do not enter model tool-call history. The variable is cleared after use. Never save Google account passwords here. Gmail access uses the shared read-only gmail service and a separate OAuth grant.",
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
    let permissionOrigin: string
    try {
      permissionOrigin = normalizeAuthOrigin(params.site_url)
    } catch {
      return { title: "Invalid site URL", output: "Only a valid HTTP(S) site URL can be used for saved profiles or Gmail OTP.", metadata: { ok: false, reason: "invalid_site_url" } }
    }
    if (params.purpose === "target") {
      const workspaceMatches = TargetMemory.list().some(
        (item) => item.id === params.target_id && normalizeAuthOrigin(item.targetURL) === permissionOrigin,
      )
      if (!workspaceMatches) {
        return {
          title: "Target workspace mismatch",
          output: "Every target-purpose operation requires an existing workspace whose stable ID and exact origin match site_url. No password, profile, or Gmail message was accessed.",
          metadata: { ok: false, reason: "target_workspace_mismatch" },
        }
      }
    }
    if (params.action === "gmail_otp") {
      await ctx.ask({ permission: "gmail-read", patterns: [permissionOrigin], always: [], metadata: { purpose: params.purpose, targetID: params.target_id } })
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
      // Move the one-shot secret out of process.env before any permission
      // prompt can suspend the tool and allow other child processes to start.
      let password: string | undefined = process.env.CYBERSTRIKE_AUTH_PASSWORD
      if (!password) {
        return { title: "Password not provided securely", output: "Set CYBERSTRIKE_AUTH_PASSWORD in the CyberStrike process environment, then retry. The password is intentionally not accepted as a tool argument because tool arguments may be stored in conversation history.", metadata: { ok: false, reason: "secure_password_missing" } }
      }
      delete process.env.CYBERSTRIKE_AUTH_PASSWORD
      try {
        await ctx.ask({ permission: "auth-credential-save", patterns: [permissionOrigin], always: [], metadata: { purpose: params.purpose, targetID: params.target_id, account: params.account } })
        const saved = await AuthVault.save({
          origin: params.site_url, purpose: params.purpose, account: params.account,
          username: params.username, password, targetID: params.target_id,
        })
        let indexSynced = false
        if (saved.purpose === "target" && saved.targetID) {
          try {
            await syncTargetProfileIndex(params.site_url, saved.targetID)
            indexSynced = true
          } catch {
            // The encrypted vault save is authoritative; a human-readable index is secondary.
          }
        }
        return { title: "Login profile saved", output: `Saved encrypted profile "${saved.account}" for ${saved.origin} (${saved.purpose}). Profile ID: ${saved.id}.${saved.purpose === "target" ? (indexSynced ? " A password-free reference was written to auth-profiles.md." : " The encrypted save succeeded, but the target reference index could not be refreshed.") : " Secret is not included in this response."}`, metadata: { ok: true, profileID: saved.id, origin: saved.origin, purpose: saved.purpose, targetIndexSynced: saved.purpose === "target" ? indexSynced : undefined } }
      } finally {
        // Best-effort removal of the local reference on every exit path.
        password = undefined
      }
    }
    if (params.action === "list") {
      const profiles = await AuthVault.list({ origin: params.site_url, purpose: params.purpose, targetID: params.target_id })
      return { title: "Saved login profiles", output: profiles.length ? profiles.map((p) => `- ${p.account} | ${p.username} | id=${p.id} | ${p.origin} | ${p.purpose} | updated=${new Date(p.updatedAt).toISOString()}`).join("\n") : "No saved profile matches this exact origin and purpose.", metadata: { count: profiles.length } }
    }
    if (!params.profile_id) return { title: "Profile ID required", output: "Provide profile_id to forget a saved login profile.", metadata: { ok: false } }
    await ctx.ask({ permission: "auth-credential-delete", patterns: [permissionOrigin], always: [], metadata: { purpose: params.purpose, targetID: params.target_id, profileID: params.profile_id } })
    const removed = await AuthVault.remove({ id: params.profile_id, origin: params.site_url, purpose: params.purpose, targetID: params.target_id })
    let indexSynced = false
    if (removed && params.purpose === "target" && params.target_id) {
      try {
        await syncTargetProfileIndex(params.site_url, params.target_id)
        indexSynced = true
      } catch {
        // Deletion from the encrypted vault remains authoritative.
      }
    }
    return { title: removed ? "Login profile forgotten" : "Profile not found", output: removed ? (params.purpose === "target" ? (indexSynced ? "The encrypted profile was deleted and auth-profiles.md refreshed." : "The encrypted profile was deleted, but auth-profiles.md could not be refreshed.") : "The matching saved profile was deleted.") : "No profile matched that ID, exact origin, purpose, and target binding.", metadata: { ok: removed, targetIndexSynced: removed && params.purpose === "target" ? indexSynced : undefined } }
  },
})
