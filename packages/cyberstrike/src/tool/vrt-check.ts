import z from "zod"
import { Tool } from "./tool"
import { Intel } from "../methodology/intel"
import { Session } from "../session"
import { vrtScopeViolation, offLaneMessage } from "./vuln-scope"
import { VerificationLedger } from "../session/verification-ledger"
import { VerificationAttempts as Policy } from "../methodology/verification-attempts"

const VRT_CLASS_TERMS: Record<string, string[]> = {
  idor: ["idor", "bola", "insecure direct object"],
  authz: ["privilege escalation", "auth bypass", "broken access control", "access control", "bfla", "cors", "forbidden", "authorization"],
  authn: ["authentication", "session", "jwt", "rate limit", "brute", "password", "mfa", "2fa", "credential", "token", "auth bypass"],
  injection: ["sqli", "sql injection", "nosqli", "xss", "cross-site scripting", "ssti", "xxe", "command injection", "ldap", "injection"],
  ssrf: ["ssrf", "server-side request"],
  "file-attacks": ["path traversal", "directory traversal", "lfi", "rfi", "file upload", "file inclusion", "zip slip"],
  "mass-assignment": ["mass assignment", "over-post", "overpost"],
  "business-logic": ["race condition", "business logic", "workflow", "negative amount", "captcha", "chain"],
}

function categoryMatchesClass(vulnerabilityClass: string, category: string) {
  const cls = vulnerabilityClass.toLowerCase().trim()
  const cat = category.toLowerCase().trim()
  if (!cls || !cat) return false
  const terms = VRT_CLASS_TERMS[cls]
  return terms ? terms.some((term) => cat.includes(term)) || terms.includes(cat) : cls === cat
}

type VrtCheckMetadata = {
  entryID: string
  category: string
  status: string
  attemptsUsed?: number
  outcome?: string
}

const Parameters = z.object({
    entry_id: z.string().describe("The intel entry ID to update the VRT check for"),
    vrt_category: z.string().trim().min(1).describe("The VRT category being tested (e.g., IDOR, XSS, SQLi, SSRF, Auth Bypass)"),
    status: z.enum(["tested_vulnerable", "tested_not_vulnerable", "not_applicable"]).describe("Result of the test"),
    verification_hypothesis_key: z.string().optional().describe("Required when marking tested_not_vulnerable; must match a ledger hypothesis whose evidence-backed outcome is disproven."),
    technique: z
      .string()
      .optional()
      .describe("Testing technique used (e.g., 'parameter tampering', 'reflected input test')"),
    evidence: z
      .object({
        requestSent: z.string().optional().describe("The HTTP request sent (must contain HTTP verb or curl command)"),
        responseCode: z.number().optional().describe("HTTP response status code"),
        responseSummary: z
          .string()
          .optional()
          .describe(
            "Summary of the response (min 50 chars for vulnerable findings). Include actual data if exploited.",
          ),
        reasoning: z
          .string()
          .optional()
          .describe("Explanation of why this is/isn't vulnerable (min 100 chars for vulnerable findings)"),
        requestCount: z
          .number()
          .optional()
          .describe("Number of HTTP requests made during testing (min 1 for valid testing)"),
        findingRef: z.string().optional().describe("Reference to a report_vulnerability call if applicable"),
      })
      .optional()
      .describe("Evidence supporting the test result. Required for 'tested_vulnerable' status."),
  })

export const UpdateVrtCheckTool = Tool.define<typeof Parameters, VrtCheckMetadata>("update_vrt_check", {
  description:
    "Update a VRT (Vulnerability Rating Taxonomy) check for an intel entry. After testing an endpoint/parameter for a specific vulnerability category, record the result here. A tested_not_vulnerable verdict is blocked unless verification_hypothesis_key points to a durable ledger outcome of DISPROVEN after 20 distinct valid attempts, with direct evidence. Inconclusive attempts must remain unresolved, not clean. This feeds coverage tracking. Every check moved from 'pending' to a tested state improves coverage.",
  parameters: Parameters,
  async execute(params, ctx) {
    // Lane discipline: a proxy-tester may only record VRT checks in its own
    // vulnerability class. Off-class checks are rejected (not written) with a
    // hand-off hint — structural, capability-agnostic (Phase 2).
    const violation = vrtScopeViolation(ctx.agent, params.vrt_category)
    if (violation) {
      return {
        title: `VRT rejected — ${params.vrt_category} out of ${violation.cls} scope`,
        output: offLaneMessage(violation.cls, violation.allowed, params.vrt_category),
        metadata: { entryID: params.entry_id, category: params.vrt_category, status: params.status },
      }
    }

    const sessionID = Session.root(ctx.sessionID)
    const entry = Intel.get(sessionID).find((item) => item.id === params.entry_id)
    if (!entry) {
      return {
        title: "VRT update rejected — intel entry not in this session",
        output: "The entry_id does not resolve to an intel entry in the current session. No VRT check was written.",
        metadata: { entryID: params.entry_id, category: params.vrt_category, status: "blocked_invalid_entry" },
      }
    }

    if (params.status === "tested_vulnerable") {
      const evidence = params.evidence
      if (
        !evidence?.requestSent?.trim() ||
        !evidence.responseSummary?.trim() ||
        evidence.responseSummary.trim().length < 50 ||
        !evidence.reasoning?.trim() ||
        evidence.reasoning.trim().length < 100 ||
        !Number.isInteger(evidence.requestCount) ||
        evidence.requestCount! < 1
      ) {
        return {
          title: `VRT vulnerable verdict blocked — insufficient evidence`,
          output: "Cannot mark this category tested_vulnerable without a sent request, an observed response summary (at least 50 characters), reasoning (at least 100 characters), and requestCount >= 1. No VRT check was written.",
          metadata: { entryID: params.entry_id, category: params.vrt_category, status: "blocked_missing_evidence" },
        }
      }
    }

    let verificationEvidenceRef: string | undefined
    if (params.status === "tested_not_vulnerable") {
      if (!params.verification_hypothesis_key?.trim()) {
        return {
          title: `VRT clean verdict blocked — ${params.vrt_category}`,
          output: "Cannot mark this category tested_not_vulnerable without verification_hypothesis_key. Record adaptive attempts in verification_attempt first; failed probes or exhausted budget are not proof of absence.",
          metadata: { entryID: params.entry_id, category: params.vrt_category, status: "blocked_missing_verification" },
        }
      }
      const attempts = VerificationLedger.list({
        sessionID,
        hypothesisKey: params.verification_hypothesis_key,
      })
      const identityMismatch = attempts.some((attempt) =>
        attempt.asset.trim().toLowerCase() !== entry.asset.trim().toLowerCase() ||
        !categoryMatchesClass(attempt.vulnerabilityClass, params.vrt_category),
      )
      if (identityMismatch) {
        return {
          title: `VRT clean verdict blocked — mismatched verification identity`,
          output: "The verification ledger belongs to a different asset or vulnerability class than this VRT check. Use a hypothesis_key bound to this entry and category; no clean verdict was written.",
          metadata: { entryID: params.entry_id, category: params.vrt_category, status: "blocked_identity_mismatch", attemptsUsed: attempts.filter((attempt) => attempt.validConditions).length },
        }
      }
      const decisiveAttempt = attempts[attempts.length - 1]
      const outcome = decisiveAttempt?.outcome
      const validAttemptsUsed = attempts.filter((attempt) => attempt.validConditions).length
      if (outcome !== "disproven" || validAttemptsUsed < Policy.MAX_ATTEMPTS || !decisiveAttempt?.validConditions || !decisiveAttempt?.evidenceRef?.trim()) {
        return {
          title: `VRT clean verdict blocked — ${params.vrt_category}`,
          output: `Cannot mark this category tested_not_vulnerable: a DISPROVEN outcome after 20 distinct valid attempts with direct evidence is required (valid attempts: ${validAttemptsUsed}, current outcome: ${outcome ?? "unrecorded"}). Continue adaptive verification or preserve it as INCONCLUSIVE / NEEDS REVIEW.`,
          metadata: { entryID: params.entry_id, category: params.vrt_category, status: "blocked_unproven", attemptsUsed: validAttemptsUsed, outcome: outcome ?? "unrecorded" },
        }
      }
      verificationEvidenceRef = decisiveAttempt.evidenceRef.trim()
    }

    Intel.updateVrtCheck(sessionID, params.entry_id, params.vrt_category, {
      status: params.status,
      technique: params.technique,
      testedBy: ctx.agent,
      evidence: {
        ...((params.evidence ?? {}) as Record<string, unknown>),
        ...(params.status === "tested_not_vulnerable"
          ? {
              verificationHypothesisKey: params.verification_hypothesis_key,
              verificationEvidenceRef,
            }
          : {}),
      },
    })

    const icon =
      params.status === "tested_vulnerable"
        ? "VULNERABLE"
        : params.status === "tested_not_vulnerable"
          ? "NOT VULNERABLE"
          : "N/A"

    return {
      title: `VRT: ${params.vrt_category} — ${icon}`,
      output: `Updated VRT check for entry ${params.entry_id}: ${params.vrt_category} = ${icon}${params.technique ? ` (technique: ${params.technique})` : ""}`,
      metadata: { entryID: params.entry_id, category: params.vrt_category, status: params.status },
    }
  },
})
