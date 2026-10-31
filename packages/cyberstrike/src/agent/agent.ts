import { Config } from "../config/config"
import z from "zod"
import { Provider } from "../provider/provider"
import { generateObject, streamObject, type ModelMessage } from "ai"
import { SystemPrompt } from "../session/system"
import { Instance } from "../project/instance"
import { Truncate } from "../tool/truncation"
import { Auth } from "../auth"
import { ProviderTransform } from "../provider/transform"

import PROMPT_GENERATE from "./generate.txt"
import PROMPT_COMPACTION from "./prompt/compaction.txt"
import PROMPT_EXPLORE from "./prompt/explore.txt"
import PROMPT_SUMMARY from "./prompt/summary.txt"
import PROMPT_TITLE from "./prompt/title.txt"
import PROMPT_WEB_APPLICATION from "./prompt/web-application.txt"
import PROMPT_CLOUD_SECURITY from "./prompt/cloud-security.txt"
import PROMPT_INTERNAL_NETWORK from "./prompt/internal-network.txt"
import PROMPT_MOBILE_APPLICATION from "./prompt/mobile-application.txt"
import PROMPT_NORMALIZE_REQUEST from "./prompt/normalize-request.txt"
import PROMPT_CYBERSTRIKE from "./prompt/cyberstrike.txt"
import PROMPT_GENERAL from "./prompt/general.txt"
import PROMPT_PROXY_TESTER_LLM from "./prompt/vuln/llm/prompt.txt"
import DESC_PROXY_TESTER_LLM from "./prompt/vuln/llm/description.txt"

// New folder-based agent imports
import PROMPT_VULN_COMMON from "./prompt/vuln/common-prompt.txt"
import PROMPT_WEB_PROXY_AGENT from "./prompt/orchestrator/web-proxy-agent/prompt.txt"
import DESC_WEB_PROXY_AGENT from "./prompt/orchestrator/web-proxy-agent/description.txt"
import PROMPT_PROXY_ANALYZER from "./prompt/analyzer/proxy-analyzer/prompt.txt"
import DESC_PROXY_ANALYZER from "./prompt/analyzer/proxy-analyzer/description.txt"
import PROMPT_IMPACT_HUNTER from "./prompt/impact-hunter/prompt.txt"
import DESC_IMPACT_HUNTER from "./prompt/impact-hunter/description.txt"
import PROMPT_PROXY_TESTER_IDOR from "./prompt/vuln/idor/prompt.txt"
import DESC_PROXY_TESTER_IDOR from "./prompt/vuln/idor/description.txt"
import PROMPT_PROXY_TESTER_AUTHZ from "./prompt/vuln/authz/prompt.txt"
import DESC_PROXY_TESTER_AUTHZ from "./prompt/vuln/authz/description.txt"
import PROMPT_PROXY_TESTER_MASS_ASSIGNMENT from "./prompt/vuln/mass-assignment/prompt.txt"
import DESC_PROXY_TESTER_MASS_ASSIGNMENT from "./prompt/vuln/mass-assignment/description.txt"
import PROMPT_PROXY_TESTER_INJECTION from "./prompt/vuln/injection/prompt.txt"
import DESC_PROXY_TESTER_INJECTION from "./prompt/vuln/injection/description.txt"
import PROMPT_PROXY_TESTER_AUTHN from "./prompt/vuln/authn/prompt.txt"
import DESC_PROXY_TESTER_AUTHN from "./prompt/vuln/authn/description.txt"
import PROMPT_PROXY_TESTER_BUSINESS_LOGIC from "./prompt/vuln/business-logic/prompt.txt"
import DESC_PROXY_TESTER_BUSINESS_LOGIC from "./prompt/vuln/business-logic/description.txt"
import PROMPT_PROXY_TESTER_SSRF from "./prompt/vuln/ssrf/prompt.txt"
import DESC_PROXY_TESTER_SSRF from "./prompt/vuln/ssrf/description.txt"
import PROMPT_PROXY_TESTER_FILE_ATTACKS from "./prompt/vuln/file-attacks/prompt.txt"
import DESC_PROXY_TESTER_FILE_ATTACKS from "./prompt/vuln/file-attacks/description.txt"

// Methodology Engine prompts — intelligence logging, coverage tracking, forced continuation
import PROMPT_METHODOLOGY_COMMON from "./prompt/methodology/common-methodology.txt"
import PROMPT_METHODOLOGY_CONTINUATION from "./prompt/methodology/forced-continuation.txt"
import PROMPT_RUNTIME_DISCOVERY from "./prompt/runtime-discovery.txt"

import { PermissionNext } from "@/permission/next"
import { mergeDeep, pipe } from "remeda"
import path from "path"
import { Plugin } from "@/plugin"
import { Skill } from "../skill"
import { SkillIndex } from "../skill/index-engine"
import { Log } from "../util/log"

// ============================================================================
// Skill injection for vulnerability testing sub-agents
//
// Two layers: (1) static WSTG skills embedded at startup via loadVulnAgent()
// as baseline methodology, and (2) dynamic skill tool access at runtime so
// agents can discover tech-specific or CWE-specific skills when they detect
// the target's stack or need deeper methodology.
// ============================================================================

// Strip defensive sections (Remediation, Risk Assessment, CWE Categories,
// References, Checklist) from skill content. Vuln testers are offensive —
// they only need attack techniques, not fix recommendations.
// Note: YAML frontmatter is already stripped by Skill.get() (.content field).
function stripDefensiveSections(content: string): string {
  if (!content) return ""
  let result = content
  for (const heading of ["Remediation", "Risk Assessment", "CWE Categories", "References", "Checklist"]) {
    const re = new RegExp(`(^|\\n)## ${heading}[\\s\\S]*?(?=\\n## (?!${heading})|$)`, "g")
    result = result.replace(re, "")
  }
  return result.trim()
}

// Strict production guard for required embedded methodology skills. Kept separate
// so missing-reference behavior can be tested without loading the full built-in catalog.
export function assertEmbeddedSkillAvailable(
  description: string,
  skillName: string,
  skill: Skill.Info | undefined,
): asserts skill is Skill.Info {
  if (!skill) {
    throw new Error(
      `Agent "${description.split("\n")[0].trim()}" references unavailable skill "${skillName}". Check the skill catalog and metadata aliases.`,
    )
  }
}

// Helper function to load vulnerability agent with common prompt prepended
// and (optionally) statically-embedded WSTG skill content.
async function loadVulnAgent(
  prompt: string,
  description: string,
  skillNames: string[] = [],
): Promise<{ prompt: string; description: string }> {
  // First line of description for agent.ts, full description for future use
  const shortDesc = description.split("\n")[0].trim()

  if (skillNames.length > 0) await SkillIndex.ensureBuilt()
  // Build against one current catalog snapshot. Directory aliases must resolve even
  // if a concurrent catalog rebuild makes the secondary search index temporarily stale.
  const availableSkills = await Skill.all()
  const skills = await Promise.all(
    skillNames.map(async (name) => {
      const direct = availableSkills.find((skill) => skill.name.toLocaleLowerCase("en-US") === name.trim().toLocaleLowerCase("en-US"))
      if (direct) return Skill.get(direct.name)
      const canonical = SkillIndex.resolveReference(name)
      const indexed = canonical ? availableSkills.find((skill) => skill.name === canonical) : undefined
      if (indexed) return Skill.get(indexed.name)
      // A directory slug is a supported exact alias for catalog entries whose human-
      // readable frontmatter name differs. Resolve through the lightweight catalog,
      // then hydrate the selected body instead of retaining every body at startup.
      const aliases = availableSkills.filter((skill) =>
        path.basename(path.dirname(skill.location)).toLocaleLowerCase("en-US") === name.trim().toLocaleLowerCase("en-US"),
      )
      return aliases.length === 1 ? Skill.get(aliases[0].name) : undefined
    }),
  )
  const skillBlocks: string[] = []
  const unavailableSkillNames: string[] = []
  for (let i = 0; i < skillNames.length; i++) {
    const skill = skills[i]
    // A missing packaged/catalog skill must not make the entire CLI fail to start.
    // Keep the specialized agent available and let its base prompt plus runtime skill
    // discovery handle the task. Collect missing references so one warning can point
    // maintainers to the packaging/catalog problem without crashing startup.
    if (!skill) {
      if (!Skill.isCatalogIsolationContext()) unavailableSkillNames.push(skillNames[i])
      continue
    }
    const content = stripDefensiveSections(skill.content)
    if (content) skillBlocks.push(`<skill name="${skillNames[i]}">\n${content}\n</skill>`)
  }

  if (unavailableSkillNames.length > 0) {
    Log.create({ service: "agent" }).warn("vulnerability agent started without some embedded skills; check the installed skill catalog", {
      agent: shortDesc,
      missing: [...new Set(unavailableSkillNames)],
    })
  }

  const skillSection =
    skillBlocks.length > 0
      ? [
          "",
          "",
          "## Embedded Skill References",
          "",
          "Authoritative WSTG testing methodology for your specialty is statically embedded below.",
          "Use these payloads, patterns, and procedures during testing.",
          "",
          skillBlocks.join("\n\n"),
        ].join("\n")
      : ""

  // Prepend common vulnerability testing instructions to agent-specific prompt
  const fullPrompt = `${PROMPT_VULN_COMMON}\n\n${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${prompt}${skillSection}`
  return { prompt: fullPrompt, description: shortDesc }
}

export namespace Agent {
  // Autonomous agents run until their evidence-driven work is complete.
  // Explicit per-agent `steps` values from user configuration remain supported;
  // the session loop's stuck/retry/abort guards handle genuine runaway behavior.

  export const Info = z
    .object({
      name: z.string(),
      description: z.string().optional(),
      mode: z.enum(["subagent", "primary", "all"]),
      native: z.boolean().optional(),
      hidden: z.boolean().optional(),
      topP: z.number().optional(),
      temperature: z.number().optional(),
      color: z.string().optional(),
      permission: PermissionNext.Ruleset,
      model: z
        .object({
          modelID: z.string(),
          providerID: z.string(),
        })
        .optional(),
      // Run this agent on the provider's SMALL tier (Phase 1.3, docs/
      // proxy-pipeline-redesign) regardless of the session model — for cheap,
      // routing/extraction-only agents (orchestrator, analyzer). Resolved via
      // Provider.getSmallModel(<session provider>).
      useSmallModel: z.boolean().optional(),
      variant: z.string().optional(),
      prompt: z.string().optional(),
      skills: z.array(z.string()).optional(),
      options: z.record(z.string(), z.any()),
      steps: z.number().int().positive().optional(),
      prependRequestContext: z.boolean().optional(),
    })
    .meta({
      ref: "AgentInfo",
    })
  export type Info = z.infer<typeof Info>

  // Public records expose the stable registry key separately from the display label.
  export const PublicInfo = Info.extend({ id: z.string() }).meta({ ref: "Agent" })
  export type PublicInfo = z.infer<typeof PublicInfo>

  const state = Instance.state(async () => {
    const cfg = await Config.get()

    // Use lightweight dirsOnly() to avoid triggering full skill indexing (4.3s → ~500ms)
    const skillDirs = await Skill.dirsOnly()
    const defaults = PermissionNext.fromConfig({
      "*": "allow",
      doom_loop: "ask",
      external_directory: {
        "*": "ask",
        [Truncate.GLOB]: "allow",
        ...Object.fromEntries(skillDirs.map((dir) => [path.join(dir, "*"), "allow"])),
      },
      question: "deny",
      // mirrors github.com/github/gitignore Node.gitignore pattern for .env files
      read: {
        "*": "allow",
        "*.env": "ask",
        "*.env.*": "ask",
        "*.env.example": "allow",
      },
    })
    const user = PermissionNext.fromConfig(cfg.permission ?? {})

    const result: Record<string, Info> = {
      cyberstrike: {
        name: "cyberstrike",
        description: "The default CyberStrike agent. AI-powered offensive security using the tools registered and permitted for the current session.",
        prompt: `${PROMPT_METHODOLOGY_COMMON}\n\n${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_CYBERSTRIKE}`,
        options: {},
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            question: "allow",
          }),
          user,
        ),
        mode: "primary",
        native: true,
      },
      general: {
        name: "general",
        description: `General-purpose agent for researching complex questions and executing multi-step tasks. Use this agent to execute multiple units of work in parallel.`,
        prompt: `${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_GENERAL}`,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            todoread: "deny",
            todowrite: "deny",
            report_vulnerability: "deny",
            research_knowledge: "allow",
            target_note: "allow",
            triage_vulnerability: "deny",
          }),
          user,
        ),
        options: {},
        mode: "subagent",
        native: true,
      },
      explore: {
        name: "explore",
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
            grep: "allow",
            glob: "allow",
            list: "allow",
            bash: "allow",
            webfetch: "allow",
            websearch: "allow",
            codesearch: "allow",
            skill: "allow",
            read: "allow",
            external_directory: {
              [Truncate.GLOB]: "allow",
            },
          }),
          user,
        ),
        description: `Fast agent specialized for exploring codebases. Use this when you need to quickly find files by patterns (eg. "src/components/**/*.tsx"), search code for keywords (eg. "API endpoints"), or answer questions about the codebase (eg. "how do API endpoints work?"). When calling this agent, specify the desired thoroughness level: "quick" for basic searches, "medium" for moderate exploration, or "very thorough" for comprehensive analysis across multiple locations and naming conventions.`,
        prompt: PROMPT_EXPLORE,
        options: {},
        mode: "subagent",
        native: true,
      },
      compaction: {
        name: "compaction",
        mode: "subagent",
        native: true,
        hidden: true,
        prompt: PROMPT_COMPACTION,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
          }),
          user,
        ),
        options: {},
      },
      title: {
        name: "title",
        mode: "subagent",
        options: {},
        native: true,
        hidden: true,
        temperature: 0.5,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
          }),
          user,
        ),
        prompt: PROMPT_TITLE,
      },
      "normalize-request": {
        name: "normalize-request",
        mode: "subagent",
        options: {},
        native: true,
        hidden: true,
        temperature: 0,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
          }),
          user,
        ),
        prompt: PROMPT_NORMALIZE_REQUEST,
      },
      summary: {
        name: "summary",
        mode: "subagent",
        options: {},
        native: true,
        hidden: true,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
          }),
          user,
        ),
        prompt: PROMPT_SUMMARY,
      },
      "web-application": {
        name: "web-application",
        description: "Web application security specialist. OWASP Top 10, WSTG methodology, API security testing.",
        mode: "subagent",
        native: true,
        color: "red",
        prompt: `${PROMPT_METHODOLOGY_COMMON}\n\n${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_WEB_APPLICATION}`,
        skills: ["wstg-recon-config", "wstg-auth-session", "wstg-injection", "wstg-logic-client-api"],
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            question: "allow",
            bash: "allow",
            hackbrowser: "allow",
            read: "allow",
            glob: "allow",
            grep: "allow",
            webfetch: "allow",
            websearch: "allow",
            report_vulnerability: "allow",
            triage_vulnerability: "allow",
            validate_finding: "allow",
            correlate_javascript: "allow",
            target_endpoint: "allow",
            research_knowledge: "allow",
            target_note: "allow",
            add_intel: "allow",
            update_vrt_check: "allow",
            methodology_status: "allow",
            scope_check: "allow",
            ensure_tools: "allow",
            attack_script: "allow",
          }),
          user,
        ),
        options: {},
      },
      "mobile-application": {
        name: "mobile-application",
        description:
          "Mobile application security specialist. Android/iOS testing, OWASP MASTG/MASVS, static/dynamic analysis, Frida/Objection.",
        mode: "subagent",
        native: true,
        color: "magenta",
        prompt: `${PROMPT_METHODOLOGY_COMMON}\n\n${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_MOBILE_APPLICATION}`,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            question: "allow",
            bash: "allow",
            hackbrowser: "allow",
            read: "allow",
            glob: "allow",
            grep: "allow",
            report_vulnerability: "allow",
            triage_vulnerability: "allow",
            validate_finding: "allow",
            research_knowledge: "allow",
            target_note: "allow",
            add_intel: "allow",
            update_vrt_check: "allow",
            methodology_status: "allow",
            scope_check: "allow",
            ensure_tools: "allow",
            attack_script: "allow",
          }),
          user,
        ),
        options: {},
      },
      "cloud-security": {
        name: "cloud-security",
        description: "Cloud security specialist. AWS, Azure, GCP security testing. IAM, CIS benchmarks.",
        mode: "subagent",
        native: true,
        color: "cyan",
        prompt: `${PROMPT_METHODOLOGY_COMMON}\n\n${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_CLOUD_SECURITY}`,
        skills: [
          "cis-aws-foundations-2.1.1",
          "cis-aws-foundations-2.2",
          "cis-aws-foundations-3.1.1",
          "cis-aws-foundations-4.1",
          "cis-aws-foundations-5.1",
          "cis-aws-foundations-6.2",
          "aws-postexploit",
          "azure-postexploit",
          "k8s-postexploit",
          "gcp-postexploit",
          "cloud-assessment",
          "k8s-assessment",
          "ci-assessment",
        ],
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            question: "allow",
            bash: "allow",
            hackbrowser: "allow",
            read: "allow",
            glob: "allow",
            grep: "allow",
            report_vulnerability: "allow",
            triage_vulnerability: "allow",
            validate_finding: "allow",
            research_knowledge: "allow",
            target_note: "allow",
            add_intel: "allow",
            update_vrt_check: "allow",
            methodology_status: "allow",
            scope_check: "allow",
            ensure_tools: "allow",
            attack_script: "allow",
            awshook: "allow",
            azurehook: "allow",
            kubehook: "allow",
            gcphook: "allow",
            containerhook: "allow",
            iachook: "allow",
            cloud_audit: "allow",
            k8s_audit: "allow",
            ci_audit: "allow",
          }),
          user,
        ),
        options: {},
      },
      "internal-network": {
        name: "internal-network",
        description: "Internal network and Active Directory specialist. AD attacks, Kerberos, lateral movement.",
        mode: "subagent",
        native: true,
        color: "yellow",
        prompt: `${PROMPT_METHODOLOGY_COMMON}\n\n${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_INTERNAL_NETWORK}`,
        skills: [
          "ad-security",
          "kerberos-attacks",
          "ebpf-attacks",
          "windows-postexploit",
          "linux-postexploit",
          "macos-postexploit",
          "aws-postexploit",
          "azure-postexploit",
          "k8s-postexploit",
          "gcp-postexploit",
          "cicd-attacks",
        ],
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            question: "allow",
            bash: "allow",
            hackbrowser: "allow",
            read: "allow",
            glob: "allow",
            grep: "allow",
            report_vulnerability: "allow",
            triage_vulnerability: "allow",
            validate_finding: "allow",
            research_knowledge: "allow",
            target_note: "allow",
            add_intel: "allow",
            update_vrt_check: "allow",
            methodology_status: "allow",
            scope_check: "allow",
            ensure_tools: "allow",
            attack_script: "allow",
            ebpf: "allow",
            winhook: "allow",
            machook: "allow",
            linuxhook: "allow",
            awshook: "allow",
            azurehook: "allow",
            kubehook: "allow",
            gcphook: "allow",
            containerhook: "allow",
            iachook: "allow",
            cloud_audit: "allow",
            k8s_audit: "allow",
            ci_audit: "allow",
            cipipe: "allow",
          }),
          user,
        ),
        options: {},
      },
      "proxy-agent": {
        name: "proxy-agent",
        description: DESC_WEB_PROXY_AGENT.split("\n")[0].trim(),
        // The same orchestrator can be selected directly as a primary agent or
        // delegated by any other agent through Task. "all" preserves both paths.
        mode: "all",
        native: true,
        // NOTE: proxy-agent runs on the FULL run model (no useSmallModel). Routing
        // is the brain of the pipeline — dispatch quality matters; downgrading it to
        // the small tier caused measured mis-/over-/under-dispatch. Only the analyzer
        // (pure recon/extraction) runs cheap.
        color: "blue",
        prompt: `${PROMPT_METHODOLOGY_COMMON}\n\n${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_WEB_PROXY_AGENT}`,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            // Pure orchestrator: deny active testing and finding writes, while allowing
            // endpoint-inventory persistence, delegation, read-only context, and JS correlation.
            // These are the exact tools named by the orchestrator prompt; if omitted here,
            // the model attempts calls that permission enforcement rejects.
            // `task` MUST be allowed explicitly or delegation breaks.
            "*": "deny",
            // The orchestrator reads skill companion files and the canonical
            // workspace manifest/notes before routing captured requests.
            task: "allow",
            question: "allow",
            skill: "allow",
            read: "allow",
            target_workspace: "allow",
            target_notes_read: "allow",
            target_artifact: "allow",
            target_endpoint: "allow",
            web_get_session_context: "allow",
            web_get_detail: "allow",
            web_get_request_detail: "allow",
            correlate_javascript: "allow",
            // The orchestrator performs scope-enforced JavaScript/HTML/source-map intake.
            ingest_javascript_urls: "allow",
            web_get_vulnerabilities: "allow",
            web_get_vuln_detail: "allow",
            triage_vulnerability: "allow",
            research_knowledge: "allow",
            target_note: "allow",
            get_coverage_notes: "allow",
            methodology_status: "allow",
            scope_check: "allow",
          }),
          user,
        ),
        options: {},
      },
      // Proxy Agent SubAgents
      "proxy-analyzer": {
        name: "proxy-analyzer",
        description: DESC_PROXY_ANALYZER.split("\n")[0].trim(),
        mode: "subagent",
        native: true,
        hidden: true,
        useSmallModel: true, // architecture extraction, not exploitation — run cheap
        prompt: `${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_PROXY_ANALYZER}`,
        prependRequestContext: true,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
            // Skill payloads can point to local playbook entries; expose the
            // guarded read tool and read-only target-note lookup to the analyzer.
            read: "allow",
            bash: "allow",
            webfetch: "allow",
            http_replay: "allow",
            web_get_session_context: "allow",
            web_get_detail: "allow",
            web_get_request_detail: "allow",
            // Read-only shared knowledge may help interpret a concrete API/auth signal.
            research_knowledge: "allow",
            skill: "allow",
            target_notes_read: "allow",
            target_artifact: "allow",
            target_note: "allow",
            target_endpoint: "allow",
            correlate_javascript: "allow",
            ingest_javascript_urls: "allow",
            web_write_role: "allow",
            web_write_object: "allow",
            web_write_object_value: "allow",
            web_write_function: "allow",
            web_update_credential_claims: "allow",
            // A concrete analyzer finding must be persisted through the canonical
            // report tool. Proof-gap mode handles evidence-backed missing-PoC candidates; approved-impact mode follows confirmed validation and triage.
            report_vulnerability: "allow",
          }),
          user,
        ),
        options: {},
      },
      "impact-hunter": {
        name: "impact-hunter",
        description: DESC_IMPACT_HUNTER.split("\n")[0].trim(),
        // "all" keeps the Hunter callable as a delegated specialist while also
        // exposing it in the user's Tab / agent picker for a standalone session.
        mode: "all",
        native: true,
        hidden: false,
        color: "red",
        prompt: `${PROMPT_METHODOLOGY_CONTINUATION}\n\n---\n\n${PROMPT_IMPACT_HUNTER}`,
        prependRequestContext: true,
        permission: PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
            question: "allow",
            skill: "allow",
            bash: "allow",
            read: "allow",
            glob: "allow",
            grep: "allow",
            webfetch: "allow",
            http_replay: "allow",
            web_get_session_context: "allow",
            web_get_detail: "allow",
            web_get_request_detail: "allow",
            web_get_vulnerabilities: "allow",
            web_get_vuln_detail: "allow",
            correlate_javascript: "allow",
            ingest_javascript_urls: "allow",
            web_write_role: "allow",
            web_write_object: "allow",
            web_write_object_value: "allow",
            web_write_function: "allow",
            web_update_credential_claims: "allow",
            validate_finding: "allow",
            chain_link: "allow",
            validate_chain: "allow",
            verification_attempt: "allow",
            false_positive_memory: "allow",
            report_vulnerability: "allow",
            triage_vulnerability: "allow",
            update_finding_impact: "allow",
            update_finding_evidence: "allow",
            research_knowledge: "allow",
            target_notes_read: "allow",
            target_artifact: "allow",
            target_note: "allow",
            target_endpoint: "allow",
            add_intel: "allow",
            get_coverage_notes: "allow",
            methodology_status: "allow",
            scope_check: "allow",
          }),
          user,
        ),
        options: {},
      },
      ...(await (async () => {
        const [
          idorAgent,
          authzAgent,
          massAssignmentAgent,
          injectionAgent,
          authnAgent,
          businessLogicAgent,
          ssrfAgent,
          fileAttacksAgent,
          llmAgent,
        ] = await Promise.all([
          loadVulnAgent(PROMPT_PROXY_TESTER_IDOR, DESC_PROXY_TESTER_IDOR, ["wstg-authz-04", "wstg-apit-02"]),
          loadVulnAgent(PROMPT_PROXY_TESTER_AUTHZ, DESC_PROXY_TESTER_AUTHZ, [
            "wstg-authz-02",
            "wstg-authz-03",
            "wstg-authz-01",
          ]),
          loadVulnAgent(PROMPT_PROXY_TESTER_MASS_ASSIGNMENT, DESC_PROXY_TESTER_MASS_ASSIGNMENT, [
            "wstg-inpv-20",
            "wstg-busl-02",
          ]),
          loadVulnAgent(PROMPT_PROXY_TESTER_INJECTION, DESC_PROXY_TESTER_INJECTION, [
            "wstg-injection",
            "wstg-inpv-05",
            "wstg-inpv-12",
            "wstg-inpv-18",
          ]),
          loadVulnAgent(PROMPT_PROXY_TESTER_AUTHN, DESC_PROXY_TESTER_AUTHN, [
            "wstg-auth-session",
            "wstg-athn-04",
            "wstg-athn-09",
            "wstg-athn-11",
            "wstg-sess-10",
          ]),
          loadVulnAgent(PROMPT_PROXY_TESTER_BUSINESS_LOGIC, DESC_PROXY_TESTER_BUSINESS_LOGIC, [
            "wstg-logic-client-api",
            "wstg-busl-04",
            "wstg-busl-10",
          ]),
          loadVulnAgent(PROMPT_PROXY_TESTER_SSRF, DESC_PROXY_TESTER_SSRF, ["wstg-inpv-19", "wstg-conf-13"]),
          loadVulnAgent(PROMPT_PROXY_TESTER_FILE_ATTACKS, DESC_PROXY_TESTER_FILE_ATTACKS, [
            "wstg-inpv-11.1",
            "wstg-inpv-11",
            "wstg-busl-08",
            "wstg-busl-09",
          ]),
          loadVulnAgent(PROMPT_PROXY_TESTER_LLM, DESC_PROXY_TESTER_LLM, ["llm-security"]),
        ])

        const vulnAgentPermission = PermissionNext.merge(
          defaults,
          PermissionNext.fromConfig({
            "*": "deny",
            task: "allow",
            // Skill companion files are read through ReadTool, which still enforces
            // project/external-directory boundaries and per-file permission checks.
            read: "allow",
            bash: {
              // Base: bash is allowed. The permission evaluator is ORDER-BASED
              // (last matching rule wins, no specificity), so `*: allow` MUST come
              // FIRST — the specific HTTP-client denies below then win over it for
              // any command they match. (With `*: allow` last, findLast would pick
              // it for every command and the denies would be inert.) Block HTTP
              // clients so vuln testers funnel through http_replay — defense-in-depth
              // with the prompt mandate. Effective by default, but a later `user`
              // bash rule can still loosen them — unlike the destructive-SQL denies
              // in injectionAgentPermission (merged after `user`, absolute). This is
              // intentional: HTTP-client steering is a routing choice, not a
              // destructive-command risk.
              "*": "allow",
              "*curl *": "deny",
              "*curl.exe*": "deny",
              "*wget *": "deny",
              "*python*requests*": "deny",
              "*python*urllib*": "deny",
              "*python*aiohttp*": "deny",
              "*python*httpx*": "deny",
              "*python3*requests*": "deny",
              "*python3*urllib*": "deny",
              "*python3*aiohttp*": "deny",
              "*python3*httpx*": "deny",
              "*import requests*": "deny",
              "*from requests *": "deny",
              "*import urllib*": "deny",
              "*import aiohttp*": "deny",
              "*import httpx*": "deny",
              // Block inline JS/TS execution — fetch() in bun/node/deno bypasses
              // all Python/curl denies above.
              "*bun -e*": "deny",
              "*bun --eval*": "deny",
              "*node -e*": "deny",
              "*node --eval*": "deny",
              "*deno eval*": "deny",
              "*deno run *": "deny",
              // Block raw TCP tools — can send HTTP without matching other patterns.
              // `* nc *` catches piped/mid-command nc; `nc *` catches command-initial
              // nc (the anchored matcher misses it otherwise) without hitting sync/ncat.
              "* nc *": "deny",
              "nc *": "deny",
              "*ncat *": "deny",
              "*socat *": "deny",
              "*telnet *": "deny",
              // Block base64-pipe-to-interpreter evasion pattern.
              "*base64*| python*": "deny",
              "*base64*| python3*": "deny",
              "*base64*| bun*": "deny",
              "*base64*| node*": "deny",
            },
            webfetch: "deny",
            web_get_session_context: "allow",
            web_get_detail: "allow",
            web_get_request_detail: "allow",
            web_get_vulnerabilities: "allow",
            // Public research is global, read-only context; expose it to every specialist.
            research_knowledge: "allow",
            false_positive_memory: "allow",
            target_notes_read: "allow",
            target_artifact: "allow",
            target_note: "allow",
            validate_finding: "allow",
            correlate_javascript: "allow",
            report_vulnerability: "allow",
            triage_vulnerability: "allow",
            // Methodology Engine tools
            add_intel: "allow",
            update_vrt_check: "allow",
            record_coverage_note: "allow",
            get_coverage_notes: "allow",
            methodology_status: "allow",
            scope_check: "allow",
            attack_script: "allow",
            skill: "allow",
            // Structured replay engine — the ONLY way to send HTTP requests.
            // Permission-enforced: curl/webfetch/Python HTTP denied above.
            http_replay: "allow",
            http_replay_raw: "allow",
            web_update_credential: "allow",
            csrf_extract: "allow",
          }),
          user,
        )

        // Injection-specific permission: blocks destructive SQL payloads and
        // RCE primitives that the injection agent might otherwise execute via
        // bash (curl, sqlmap, etc.). Defense-in-depth alongside prompt rules.
        // Patterns are case-sensitive — common variants listed for both upper
        // and lower case. User overrides cannot loosen these denies because
        // they are merged AFTER the user ruleset.
        const injectionAgentPermission = PermissionNext.merge(
          vulnAgentPermission,
          PermissionNext.fromConfig({
            // Injection-only: deterministic payload-battery / evidence tool. Scoped to
            // this agent (not vulnAgentPermission) to keep the blast radius narrow.
            inject_probe: "allow",
            bash: {
              // Destructive SQL DDL
              "*DROP TABLE*": "deny",
              "*drop table*": "deny",
              "*DROP DATABASE*": "deny",
              "*drop database*": "deny",
              "*DROP SCHEMA*": "deny",
              "*drop schema*": "deny",
              "*TRUNCATE TABLE*": "deny",
              "*truncate table*": "deny",
              // SQL-based file write (destructive primitive)
              "*INTO OUTFILE*": "deny",
              "*into outfile*": "deny",
              "*INTO DUMPFILE*": "deny",
              "*into dumpfile*": "deny",
              // SQL-to-RCE primitives
              "*xp_cmdshell*": "deny",
              "*sp_OACreate*": "deny",
              "*sys_exec*": "deny",
              "*sys_eval*": "deny",
              "*COPY * TO PROGRAM*": "deny",
              "*copy * to program*": "deny",
              // sqlmap dangerous flags (RCE / file write)
              "*--os-shell*": "deny",
              "*--os-cmd*": "deny",
              "*--os-pwn*": "deny",
              "*--file-write*": "deny",
              "*--reg-add*": "deny",
              "*--reg-del*": "deny",
            },
          }),
        )

        // File-attacks-specific permission: inject_probe's LFI mode (read-only Linux/Windows
        // path-traversal file-disclosure) hands this agent the WORKING filter-bypass shape. Scoped
        // to this agent only (not vulnAgentPermission) to keep the blast radius narrow.
        const fileAttacksPermission = PermissionNext.merge(
          vulnAgentPermission,
          PermissionNext.fromConfig({ inject_probe: "allow" }),
        )

        // LLM-specific permission: the LLM tester's instrument is `llmhook` (an
        // automated OWASP LLM Top-10 scanner that posts crafted prompts to the
        // captured chat endpoint). Scoped to this agent only (not
        // vulnAgentPermission) to keep the blast radius narrow — no other vuln
        // tester needs it. It does NOT get `hackbrowser`/`browser`: the endpoint
        // is already captured in the prepended request context, so there is
        // nothing to crawl.
        const llmAgentPermission = PermissionNext.merge(
          vulnAgentPermission,
          PermissionNext.fromConfig({ llmhook: "allow" }),
        )

        return {
          "proxy-tester-idor": {
            name: "proxy-tester-idor",
            description: idorAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: idorAgent.prompt,
            prependRequestContext: true,
            permission: vulnAgentPermission,
            options: {},
          },
          "proxy-tester-authz": {
            name: "proxy-tester-authz",
            description: authzAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: authzAgent.prompt,
            prependRequestContext: true,
            permission: vulnAgentPermission,
            options: {},
          },
          "proxy-tester-mass-assignment": {
            name: "proxy-tester-mass-assignment",
            description: massAssignmentAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: massAssignmentAgent.prompt,
            prependRequestContext: true,
            permission: vulnAgentPermission,
            options: {},
          },
          "proxy-tester-injection": {
            name: "proxy-tester-injection",
            description: injectionAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: injectionAgent.prompt,
            prependRequestContext: true,
            permission: injectionAgentPermission,
            options: {},
          },
          "proxy-tester-authn": {
            name: "proxy-tester-authn",
            description: authnAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: authnAgent.prompt,
            prependRequestContext: true,
            permission: vulnAgentPermission,
            options: {},
          },
          "proxy-tester-business-logic": {
            name: "proxy-tester-business-logic",
            description: businessLogicAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: businessLogicAgent.prompt,
            prependRequestContext: true,
            permission: vulnAgentPermission,
            options: {},
          },
          "proxy-tester-ssrf": {
            name: "proxy-tester-ssrf",
            description: ssrfAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: ssrfAgent.prompt,
            prependRequestContext: true,
            permission: vulnAgentPermission,
            options: {},
          },
          "proxy-tester-file-attacks": {
            name: "proxy-tester-file-attacks",
            description: fileAttacksAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: fileAttacksAgent.prompt,
            prependRequestContext: true,
            permission: fileAttacksPermission,
            options: {},
          },
          "proxy-tester-llm": {
            name: "proxy-tester-llm",
            description: llmAgent.description,
            mode: "subagent" as const,
            native: true,
            hidden: true,
            prompt: llmAgent.prompt,
            prependRequestContext: true,
            permission: llmAgentPermission,
            options: {},
          },
        }
      })()),
    }

    for (const [key, value] of Object.entries(cfg.agent ?? {})) {
      if (value.disable) {
        delete result[key]
        continue
      }
      let item = result[key]
      if (!item)
        item = result[key] = {
          name: key,
          mode: "all",
          permission: PermissionNext.merge(defaults, user),
          options: {},
          native: false,
        }
      if (value.model) item.model = Provider.parseModel(value.model)
      item.variant = value.variant ?? item.variant
      item.prompt = value.prompt ?? item.prompt
      item.description = value.description ?? item.description
      item.temperature = value.temperature ?? item.temperature
      item.topP = value.top_p ?? item.topP
      item.mode = value.mode ?? item.mode
      item.color = value.color ?? item.color
      item.hidden = value.hidden ?? item.hidden
      item.name = value.name ?? item.name
      item.steps = value.steps ?? item.steps
      item.options = mergeDeep(item.options, value.options ?? {})
      item.permission = PermissionNext.merge(item.permission, PermissionNext.fromConfig(value.permission ?? {}))
    }

    // Ensure Truncate.GLOB is allowed unless explicitly configured
    for (const name in result) {
      const agent = result[name]
      const explicit = agent.permission.some((r) => {
        if (r.permission !== "external_directory") return false
        if (r.action !== "deny") return false
        return r.pattern === Truncate.GLOB
      })
      if (explicit) continue

      result[name].permission = PermissionNext.merge(
        result[name].permission,
        PermissionNext.fromConfig({ external_directory: { [Truncate.GLOB]: "allow" } }),
      )
    }

    // Attach the same live runtime/skill/signal routing contract to every
    // task-capable agent, including built-ins, user-defined agents, orchestrators,
    // analyzers, Impact Hunter, and all vulnerability testers. Utility-only
    // agents have no skill permission and are intentionally excluded.
    for (const [id, agent] of Object.entries(result)) {
      if (["compaction", "title", "summary", "normalize-request"].includes(id)) continue
      if (PermissionNext.evaluate("skill", "*", agent.permission).action === "deny") continue
      agent.prompt = [PROMPT_RUNTIME_DISCOVERY, agent.prompt].filter(Boolean).join("\n\n---\n\n")
    }

    return result
  })

  /** Resolve an agent by its stable registry key or by a unique configured display name. */
  export async function get(agent: string) {
    const registry = await state()
    if (registry[agent]) return registry[agent]
    const matches = Object.entries(registry).filter(([, entry]) => entry.name === agent)
    if (matches.length === 1) return matches[0]![1]
    if (matches.length > 1) {
      throw new Error(
        `Agent display name "${agent}" is ambiguous. Use a stable registry ID: ${matches.map(([id]) => id).join(", ")}.`,
      )
    }
    return undefined
  }

  /**
   * Return stable registry keys alongside agent metadata.
   * Invocation, permission matching, and delegation must use the key; display names
   * are configurable and therefore must never be used as registry identifiers.
   */
  export async function entries() {
    return Object.entries(await state()).map(([id, info]) => ({ id, info }))
  }

  /**
   * Resolve the stable registry key for a tool/session agent identity.
   * Prefer the registry key; accept a unique display name only for compatibility.
   */
  export async function resolveID(agent: string | Info | undefined): Promise<string | undefined> {
    if (!agent) return undefined
    const registry = await state()
    if (typeof agent === "string") {
      if (registry[agent]) return agent
      const matches = Object.entries(registry).filter(([, info]) => info.name === agent)
      return matches.length === 1 ? matches[0][0] : undefined
    }
    const direct = Object.entries(registry).find(([, info]) => info === agent)
    if (direct) return direct[0]
    const matches = Object.entries(registry).filter(([, info]) => info.name === agent.name)
    return matches.length === 1 ? matches[0][0] : undefined
  }

  export async function list() {
    const cfg = await Config.get()
    const registry = Object.entries(await state())
    registry.sort(([leftID, left], [rightID, right]) => {
      const preferred = (id: string) => (cfg.default_agent ? id === cfg.default_agent : id === "cyberstrike")
      return Number(preferred(rightID)) - Number(preferred(leftID)) ||
        left.name.localeCompare(right.name) ||
        leftID.localeCompare(rightID)
    })
    return registry.map(([, info]) => info)
  }

  export async function defaultAgent() {
    const cfg = await Config.get()
    const agents = await state()

    if (cfg.default_agent) {
      const agent = agents[cfg.default_agent]
      if (!agent) throw new Error(`default agent "${cfg.default_agent}" not found`)
      if (agent.mode === "subagent") throw new Error(`default agent "${cfg.default_agent}" is a subagent`)
      if (agent.hidden === true) throw new Error(`default agent "${cfg.default_agent}" is hidden`)
      return cfg.default_agent
    }

    // "all" agents such as Agent Proxy can be selected explicitly, never implicitly.
    const primaryVisible = Object.entries(agents).find(([, a]) => a.mode === "primary" && a.hidden !== true)
    if (!primaryVisible) throw new Error("no primary visible agent found")
    return primaryVisible[0]
  }

  export async function generate(input: { description: string; model?: { providerID: string; modelID: string } }) {
    const cfg = await Config.get()
    const defaultModel = input.model ?? (await Provider.defaultModel())
    const model = await Provider.getModel(defaultModel.providerID, defaultModel.modelID)
    const language = await Provider.getLanguage(model)

    const system = [PROMPT_GENERATE]
    await Plugin.trigger("experimental.chat.system.transform", { model }, { system })
    const existing = await entries()

    const params = {
      experimental_telemetry: {
        isEnabled: cfg.experimental?.openTelemetry,
        metadata: {
          userId: cfg.username ?? "unknown",
        },
      },
      temperature: 0.3,
      messages: [
        ...system.map(
          (item): ModelMessage => ({
            role: "system",
            content: item,
          }),
        ),
        {
          role: "user",
          content: `Create an agent configuration based on this request: \"${input.description}\".\n\nIMPORTANT: The following identifiers already exist and must NOT be used: ${existing.map((i) => i.id).join(", ")}\n  Return ONLY the JSON object, no other text, do not wrap in backticks`,
        },
      ],
      model: language,
      schema: z.object({
        identifier: z.string(),
        whenToUse: z.string(),
        systemPrompt: z.string(),
      }),
    } satisfies Parameters<typeof generateObject>[0]

    if (defaultModel.providerID === "openai" && (await Auth.get(defaultModel.providerID))?.type === "oauth") {
      const result = streamObject({
        ...params,
        providerOptions: ProviderTransform.providerOptions(model, {
          instructions: SystemPrompt.instructions(),
          store: false,
        }),
        onError: () => {},
      })
      for await (const part of result.fullStream) {
        if (part.type === "error") throw part.error
      }
      return result.object
    }

    const result = await generateObject(params)
    return result.object
  }
}
