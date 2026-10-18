import { describe, expect, test } from "bun:test"
import { Phase } from "../../src/methodology/phase"
import { rankSkillsForPhase, skillQueriesForPhase } from "../../src/methodology/context"
import type { SkillIndex } from "../../src/skill/index-engine"

describe("Methodology phase skill routing", () => {
  test("every defined phase has a phase-specific skill discovery plan", () => {
    for (const phase of Phase.ALL) {
      const queries = skillQueriesForPhase(phase.id)
      expect(queries.length).toBeGreaterThan(0)
      for (const requiredTag of phase.requiredTags) expect(queries).toContain(requiredTag)
    }
  })

  test("scope/recon, authorization, reporting, and mobile phases prioritize relevant skill families", () => {
    expect(skillQueriesForPhase("scope_analysis")).toContain("target-workspace-workflow")
    expect(skillQueriesForPhase("scope_analysis")).toContain("attack-bb-methodology")
    expect(skillQueriesForPhase("passive_recon")).toContain("recon-subdomain-enumeration")
    expect(skillQueriesForPhase("passive_recon")).toContain("recon-asn-infrastructure")
    expect(skillQueriesForPhase("active_recon")).toContain("recon-port-service-discovery")
    expect(skillQueriesForPhase("active_recon")).toContain("attack-web-recon")
    expect(skillQueriesForPhase("authorization_testing")).toContain("attack-idor-automation")
    expect(skillQueriesForPhase("input_validation")).toContain("attack-ssrf")
    expect(skillQueriesForPhase("input_validation")).toContain("attack-sqli")
    expect(skillQueriesForPhase("session_management")).toContain("attack-jwt")
    expect(skillQueriesForPhase("api_security")).toContain("attack-graphql")
    expect(skillQueriesForPhase("infrastructure")).toContain("attack-cloud-misconfig")
    expect(skillQueriesForPhase("reporting")).toContain("attack-report-writing")
    expect(Phase.get("mobile_application_testing")?.appliesTo).toContain("mobile")
    expect(skillQueriesForPhase("mobile_application_testing")).toContain("OWASP MASVS")
  })


  test("expanded installed skill families are routed to every relevant methodology phase", () => {
    const expected: Partial<Record<Phase.Id, string[]>> = {

      technology_profiling: [
        "wstg-info-08", "wstg-info-09", "wstg-recon-config", "attack-django", "attack-fastapi", "attack-flask-werkzeug",
        "attack-laravel", "attack-nextjs", "attack-nodejs", "attack-springboot",
        "attack-wordpress", "attack-hikvision-isapi", "attack-vmware-vcenter",
        "attack-minio-s3", "attack-exchange-owa", "attack-zimbra",
      ],
      authentication_testing: [
        "wstg-athn", "wstg-idnt", "wstg-auth-session", "attack-401-403-bypass", "attack-captcha-bypass", "attack-forgot-password",
        "attack-mfa-bypass", "attack-oauth", "attack-saml-sso",
      ],
      session_management: ["wstg-sess", "wstg-auth-session", "attack-session", "attack-jwt", "attack-csrf", "attack-saml-sso"],
      authorization_testing: [
        "wstg-authz", "wstg-apit-02", "wstg-auth-session", "attack-idor-automation", "attack-mass-assignment", "attack-bfla",
        "attack-api-noauth-hunt", "attack-cors",
      ],
      input_validation: [
        "wstg-inpv", "wstg-clnt", "wstg-injection", "attack-dom-xss", "attack-nosqli", "attack-deserialization", "attack-file-upload",
        "attack-rce", "attack-prototype-pollution", "attack-request-smuggling",
        "attack-host-header", "attack-cache-poison",
      ],
      business_logic: [
        "wstg-busl", "wstg-logic-client-api", "attack-business-logic", "attack-race-condition", "attack-rate-limit-bypass",
        "attack-clickjacking", "attack-host-header", "attack-cache-poison",
      ],
      data_protection: [
        "wstg-cryp", "wstg-errh", "wstg-conf", "attack-information-disclosure", "attack-source-leak", "attack-phpinfo-exposure",
      ],
      api_security: [
        "wstg-apit", "wstg-authz-05", "wstg-logic-client-api", "attack-graphql", "attack-schema-enumeration", "attack-grpc",
        "attack-mass-assignment", "attack-nosqli", "attack-websocket",
        "attack-host-header", "attack-cache-poison", "attack-clickjacking", "llm-security",
      ],
      infrastructure: [
        "attack-cloud-misconfig", "cloud-assessment", "ci-assessment",
        "cicd-attacks", "k8s-assessment", "ad-security", "attack-ldap",
        "aws-postexploit", "azure-postexploit", "gcp-postexploit", "k8s-postexploit",
        "windows-postexploit", "linux-postexploit", "macos-postexploit", "ebpf-attacks",
        "kerberos-attacks", "mitre_attack", "mitre_attack_ics", "CIS benchmarks", "NIST controls",
      ],
      reporting: [
        "attack-triage-validation", "attack-evidence-hygiene", "attack-report-writing",
        "bugcrowd-reporting", "triage-validation", "evidence-hygiene", "report-writing",
      ],
    }

    for (const phase of Phase.ALL) {
      const queries = skillQueriesForPhase(phase.id)
      for (const skill of expected[phase.id] ?? []) {
        expect(queries, `${phase.id} should route ${skill}`).toContain(skill)
      }
    }
  })


  test("scope and recon phases route to security agents, not the codebase-only explore agent", () => {
    for (const phaseId of ["scope_analysis", "passive_recon", "active_recon"] as const) {
      const agents = Phase.get(phaseId)?.agents ?? []
      expect(agents).toContain("cyberstrike")
      expect(agents).toContain("web-application")
      expect(agents).not.toContain("explore")
    }
  })

  test("recon phases rank their base and specialized skills without dropping skill retrieval", () => {
    const makeSkill = (name: string): SkillIndex.Entry => ({
      name,
      description: "Reconnaissance enumeration and discovery",
      tags: ["recon", "active-recon", "enumeration"],
      tech_stack: [],
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
    })
    const ranked = rankSkillsForPhase("active_recon", [
      "recon-methodology", "recon-subdomain-enumeration", "recon-port-service-discovery",
      "recon-vhost-enumeration", "recon-cms-detection", "recon-origin-ip-discovery",
      "recon-email-security", "recon-gitlab-public-recon", "recon-error-log-mining",
      "recon-visual-recon", "recon-asn-infrastructure", "attack-web-recon",
    ].map(makeSkill))
    const names = ranked.map((skill) => skill.name)
    expect(names).toContain("recon-methodology")
    expect(names).toContain("recon-subdomain-enumeration")
    expect(names).toContain("recon-port-service-discovery")
  })

  test("phase ranking uses required tags and metadata rather than only display-name phrases", () => {
    const makeSkill = (overrides: Partial<SkillIndex.Entry>): SkillIndex.Entry => ({
      name: "generic-web-testing",
      description: "General web application testing",
      tags: [],
      tech_stack: [],
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
      ...overrides,
    })

    const ranked = rankSkillsForPhase("authorization_testing", [
      makeSkill({ name: "generic-web-testing", description: "General web application testing" }),
      makeSkill({
        name: "access-control-review",
        description: "Authorization and object-level access checks",
        tags: ["authz-testing", "authorization", "idor"],
      }),
      makeSkill({
        name: "tampered-idor-skill",
        description: "Authorization IDOR testing",
        tags: ["authz-testing", "idor"],
        verified: "tampered",
      }),
    ])

    expect(ranked[0]?.name).toBe("access-control-review")
    expect(ranked.some((skill) => skill.name === "tampered-idor-skill")).toBe(false)
  })

  test("empty tech_stack metadata does not gain a false match for every observed technology", () => {
    const makeSkill = (overrides: Partial<SkillIndex.Entry>): SkillIndex.Entry => ({
      name: "unrelated-skill",
      description: "General testing notes",
      tags: [],
      tech_stack: [],
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
      ...overrides,
    })

    const ranked = rankSkillsForPhase("technology_profiling", [
      makeSkill({ name: "empty-tech-metadata", tech_stack: [""] }),
      makeSkill({
        name: "react-framework-check",
        description: "Technology profiling and framework detection",
        tags: ["technology", "framework"],
        tech_stack: ["react"],
      }),
    ], 10, ["React 18"])

    expect(ranked.map((skill) => skill.name)).toContain("react-framework-check")
    expect(ranked.map((skill) => skill.name)).not.toContain("empty-tech-metadata")
  })

  test("observed target technologies influence phase skill ranking", () => {
    const makeSkill = (name: string, tech_stack: string[]): SkillIndex.Entry => ({
      name,
      description: "Technology profiling and framework detection",
      tags: ["technology", "framework", "tech-profile"],
      tech_stack,
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
    })

    const ranked = rankSkillsForPhase("technology_profiling", [
      makeSkill("a-generic-framework-check", ["generic"]),
      makeSkill("z-react-framework-check", ["react"]),
    ], 4, ["React 18"])

    expect(ranked[0]?.name).toBe("z-react-framework-check")
  })

  test("recon skill ranking preserves the canonical workflow while surfacing applicable procedures", () => {
    const makeSkill = (name: string, description: string, tags: string[] = []): SkillIndex.Entry => ({
      name,
      description,
      tags,
      tech_stack: [],
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
    })

    const ranked = rankSkillsForPhase("active_recon", [
      makeSkill("generic-web-testing", "General web application testing", ["web"]),
      makeSkill("recon-port-service-discovery", "Active reconnaissance and service enumeration", ["active-recon", "port-scan"]),
      makeSkill("http-fingerprint", "HTTP technology fingerprinting", ["technology", "framework"]),
    ], 2)

    const names = ranked.map((skill) => skill.name)
    expect(names).toContain("recon-port-service-discovery")
    expect(names).not.toContain("generic-web-testing")
  })

  test("scope detection distinguishes mobile artifacts from domain names", () => {
    expect(Phase.detectScopeType(["app.apk"])).toBe("mobile")
    expect(Phase.detectScopeType(["package:com.example.app"])).toBe("mobile")
    expect(Phase.detectScopeType(["com.example.com"])).toBe("single")
    expect(Phase.detectScopeType(["*.example.com"])).toBe("wildcard")
  })

  test("mobile-only phases do not block web reporting, while mobile reporting requires mobile testing", () => {
    expect(Phase.forScope("single").some((phase) => phase.id === "mobile_application_testing")).toBe(false)
    expect(Phase.forScope("mobile").some((phase) => phase.id === "mobile_application_testing")).toBe(true)
    expect(Phase.get("reporting")?.prerequisites).toContain("mobile_application_testing")
  })
})
