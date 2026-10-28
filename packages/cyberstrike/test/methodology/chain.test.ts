import { describe, expect, test } from "bun:test"
import path from "path"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Intel } from "../../src/methodology/intel"
import { Chain } from "../../src/methodology/chain"
import { Log } from "../../src/util/log"

const projectRoot = path.join(__dirname, "../..")
Log.init({ print: false })

describe("Chain — Detection", () => {
  test("detect returns empty array for empty session", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        const chains = Chain.detect(session.id)
        expect(chains).toEqual([])

        await Session.remove(session.id)
      },
    })
  })

  test("detects credential_endpoint chain", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        // Add credential + endpoint intel on same asset
        Intel.add({
          sessionID: session.id,
          data: {
            type: "credential",
            severity: "high",
            title: "Default admin credentials",
            detail: "admin:admin123 found in login page",
            asset: "app.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: ["credential"],
          },
        })

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "POST /api/admin/users",
            detail: "Admin user management endpoint",
            asset: "app.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: ["admin", "endpoint"],
          },
        })

        const chains = Chain.detect(session.id)
        const credentialChain = chains.find((c) => c.pattern === "credential_endpoint")
        expect(credentialChain).toBeDefined()
        if (credentialChain) {
          expect(credentialChain.expectedImpact).toContain("POTENTIAL_ACCOUNT_ACCESS")
        }

        await Session.remove(session.id)
      },
    })
  })

  test("detects xss_csrf chain when XSS VRT check is vulnerable", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        // Add endpoint with XSS (generates VRT checks including XSS)
        const xssEntry = Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /search",
            detail: "Search endpoint with XSS via q parameter",
            asset: "app.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: ["xss"],
          },
        })

        // Mark the XSS VRT check as vulnerable (required for chain detection)
        const checks = Intel.getVrtChecks(session.id, xssEntry.id)
        const xssCheck = checks.find((c) => c.category.includes("XSS"))
        if (xssCheck) {
          Intel.updateVrtCheck(session.id, xssCheck.entryID, xssCheck.category, {
            status: "tested_vulnerable",
            technique: "Manual testing",
            testedBy: "test-agent",
            evidence: { requestSent: "GET /search?q=<script>alert(1)</script>" },
          })
        }

        // Add state-changing endpoint (POST = state change)
        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "POST /api/user/update",
            detail: "State-changing user update endpoint, no CSRF protection",
            asset: "app.example.com",
            source: "test",
            confidenceLevel: "high",
            tags: ["state-change", "csrf"],
          },
        })

        const chains = Chain.detect(session.id)
        const xssCsrfChain = chains.find((c) => c.pattern === "xss_csrf")
        expect(xssCsrfChain).toBeDefined()

        await Session.remove(session.id)
      },
    })
  })

  test("does not detect chain for unrelated assets", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        Intel.add({
          sessionID: session.id,
          data: {
            type: "credential",
            severity: "high",
            title: "Credential found",
            detail: "admin:password",
            asset: "site-a.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: ["credential"],
          },
        })

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "Admin endpoint",
            detail: "/admin/dashboard",
            asset: "completely-different-site.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: ["admin"],
          },
        })

        const chains = Chain.detect(session.id)
        // These are on completely different domains, so no chain should form
        const credChain = chains.find((c) => c.pattern === "credential_endpoint")
        expect(credChain).toBeUndefined()

        await Session.remove(session.id)
      },
    })
  })

  test("save and load persists chains", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        Intel.add({
          sessionID: session.id,
          data: {
            type: "credential",
            severity: "high",
            title: "Leaked API key",
            detail: "API key found in JS source",
            asset: "target.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: ["credential"],
          },
        })

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /api/sensitive",
            detail: "Sensitive data endpoint",
            asset: "target.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: ["endpoint"],
          },
        })

        const detected = Chain.detect(session.id)
        if (detected.length > 0) {
          Chain.save(session.id, detected)
          const loaded = Chain.load(session.id)
          expect(loaded.length).toBe(detected.length)
          expect(loaded[0].pattern).toBe(detected[0].pattern)
        }

        await Session.remove(session.id)
      },
    })
  })
})

describe("Chain — Format", () => {
  test("formatForPrompt returns empty string for empty chains", () => {
    const result = Chain.formatForPrompt([])
    expect(result).toBe("")
  })

  test("formatForPrompt returns markdown for chains", () => {
    const chains: Chain.Candidate[] = [
      {
        id: "test-chain-1",
        pattern: "credential_endpoint",
        entryIDs: ["a", "b"],
        entryTitles: ["Cred found", "Admin endpoint"],
        assets: ["target.com"],
        expectedImpact: "ACCOUNT_TAKEOVER",
        severity: "critical",
        testingPlan: "Use credential on endpoint",
        status: "detected",
        confidence: 80,
        detectedAt: Date.now(),
      },
    ]
    const result = Chain.formatForPrompt(chains)
    expect(result.length).toBeGreaterThan(0)
    expect(result).toContain("Chain")
    expect(result).toContain("CREDENTIAL_ENDPOINT")
  })

  test("formatForPrompt separates evidence-backed terminal chains from legacy status strings", () => {
    const common: Omit<Chain.Candidate, "id" | "status" | "validation"> = {
      pattern: "information_amplification",
      entryIDs: ["info-a", "info-b"],
      entryTitles: ["Internal configuration", "API schema"],
      assets: ["example.com"],
      expectedImpact: "POTENTIAL_INTERNAL_API_OR_SERVICE_EXPOSURE",
      severity: "high",
      testingPlan: "Validate actual reachability and impact",
      confidence: 40,
      detectedAt: Date.now(),
    }
    const result = Chain.formatForPrompt([
      {
        ...common,
        id: "confirmed-chain",
        status: "confirmed",
        validation: {
          id: "cvn-confirmed",
          outcome: "confirmed",
          combinedFindingID: "vul-combined",
          evidence: "Combined impact evidence was observed with controls.",
          validatedBy: "test",
          validatedAt: 100,
        },
      },
      { ...common, id: "legacy-confirmed", status: "confirmed" },
      {
        ...common,
        id: "disproven-chain",
        status: "disproven",
        validation: {
          id: "cvn-disproven",
          outcome: "disproven",
          evidence: "A negative control disproved the combined impact.",
          validatedBy: "test",
          validatedAt: 200,
        },
      },
    ])

    expect(result).toContain("1 evidence-backed confirmed")
    expect(result).toContain("Combined finding: vul-combined")
    expect(result).toContain("CONFIRMED STATUS — VALIDATION RECORD MISSING")
    expect(result).toContain("[DISPROVEN] chain_id=disproven-chain")
  })
})

describe("Chain — Safety and confidence", () => {
  test("credential discovery remains a hypothesis until validity and access are demonstrated", async () => {
    await Instance.provide({ directory: projectRoot, fn: async () => {
      const session = await Session.create({})
      Intel.add({ sessionID: session.id, data: { type: "credential", severity: "high", title: "Possible API key in JavaScript", detail: "A key-shaped string was found in a public script; validity has not been checked", asset: "app.example.com", source: "test", confidenceLevel: "confirmed", tags: ["credential"] } })
      Intel.add({ sessionID: session.id, data: { type: "endpoint", severity: "medium", title: "GET /api/account", detail: "Account endpoint", asset: "api.example.com", source: "test", confidenceLevel: "high", tags: ["endpoint"] } })
      const candidate = Chain.detect(session.id).find((c) => c.pattern === "credential_endpoint")
      expect(candidate).toBeDefined()
      expect(candidate?.confidence).toBeLessThan(60)
      expect(candidate?.expectedImpact).toContain("POTENTIAL")
      expect(candidate?.testingPlan).toContain("authorized test account")
      await Session.remove(session.id)
    }})
  })
  test("does not relate unrelated registrable domains sharing a two-label suffix", async () => {
    await Instance.provide({ directory: projectRoot, fn: async () => {
      const session = await Session.create({})
      Intel.add({ sessionID: session.id, data: { type: "credential", severity: "high", title: "Credential candidate", detail: "Unverified credential-shaped string", asset: "victim.co.uk", source: "test", confidenceLevel: "high", tags: ["credential"] } })
      Intel.add({ sessionID: session.id, data: { type: "endpoint", severity: "medium", title: "GET /admin", detail: "Admin endpoint", asset: "other.co.uk", source: "test", confidenceLevel: "high", tags: ["endpoint"] } })
      expect(Chain.detect(session.id).some((c) => c.pattern === "credential_endpoint")).toBe(false)
      await Session.remove(session.id)
    }})
  })
  test("prompt labels detected chains as hypotheses, not confirmed findings", () => {
    const result = Chain.formatForPrompt([{ id: "chain-1", pattern: "credential_endpoint", entryIDs: ["a","b"], entryTitles: ["Credential candidate","API endpoint"], assets: ["example.com"], expectedImpact: "POTENTIAL_ACCOUNT_ACCESS", severity: "medium", testingPlan: "Verify only with authorized test account", status: "detected", confidence: 30, detectedAt: Date.now() }])
    expect(result).toContain("not confirmed findings")
    expect(result).toContain("unproven until tested")
  })
})

describe("Chain — Single-finding escalation", () => {
  test("evaluates SSTI-to-RCE escalation even when only one intel entry exists", async () => {
    await Instance.provide({ directory: projectRoot, fn: async () => {
      const session = await Session.create({})
      const entry = Intel.add({ sessionID: session.id, data: {
        type: "endpoint", severity: "high", title: "POST /render",
        detail: "Template rendering input; SSTI is only a candidate until the terminal capability is proven",
        asset: "app.example.com", source: "test", confidenceLevel: "high", tags: ["ssti"],
      }})
      const check = Intel.getVrtChecks(session.id, entry.id).find((c) => c.category.toLowerCase().includes("ssti"))
      expect(check).toBeDefined()
      if (check) Intel.updateVrtCheck(session.id, check.entryID, check.category, {
        status: "tested_vulnerable", technique: "controlled test", testedBy: "test-agent",
        evidence: { requestSent: "controlled harmless template expression" },
      })
      const candidate = Chain.detect(session.id).find((c) => c.pattern === "ssti_rce")
      expect(candidate).toBeDefined()
      expect(candidate?.entryIDs).toEqual([entry.id])
      expect(candidate?.entryTitles).toEqual([entry.title])
      expect(candidate?.expectedImpact).toContain("POTENTIAL")
      expect(candidate?.severity).toBe("high")
      expect(candidate?.confidence).toBeLessThanOrEqual(60)
      expect(candidate?.testingPlan).toContain("RCE as unproven")
      await Session.remove(session.id)
    }})
  })
})


describe("Chain — Informational signal amplification", () => {
  test("chains INFO configuration and API-schema observations into a higher-impact hypothesis", async () => {
    await Instance.provide({ directory: projectRoot, fn: async () => {
      const session = await Session.create({})
      Intel.add({ sessionID: session.id, data: {
        type: "configuration",
        severity: "info",
        title: "Internal service configuration disclosed",
        detail: "Deployment metadata names internal-api.staging.example.com",
        asset: "app.example.com",
        source: "test",
        confidenceLevel: "high",
        tags: ["information-disclosure", "internal-service"],
      }})
      Intel.add({ sessionID: session.id, data: {
        type: "api_schema",
        severity: "info",
        title: "OpenAPI schema lists internal routes",
        detail: "Public schema includes route descriptions for internal user management",
        asset: "app.example.com",
        source: "test",
        confidenceLevel: "high",
        tags: ["api-schema", "route-disclosure"],
      }})

      const chain = Chain.detect(session.id).find((item) => item.pattern === "information_amplification")
      expect(chain).toBeDefined()
      expect(chain?.expectedImpact).toBe("POTENTIAL_INTERNAL_API_OR_SERVICE_EXPOSURE")
      expect(chain?.severity).toBe("high")
      expect(chain?.status).toBe("detected")
      expect(chain?.confidence).toBeLessThan(50)
      expect(chain?.testingPlan).toContain("do not treat names or paths alone as impact")
      await Session.remove(session.id)
    }})
  })

  test("chains INFO identity-boundary and sensitive-data signals without auto-confirming IDOR", async () => {
    await Instance.provide({ directory: projectRoot, fn: async () => {
      const session = await Session.create({})
      Intel.add({ sessionID: session.id, data: {
        type: "business_rule",
        severity: "info",
        title: "Workspace ownership rule documented",
        detail: "Profile records are associated with a tenant and workspace owner",
        asset: "app.example.com",
        source: "test",
        confidenceLevel: "high",
        tags: ["tenant", "authorization"],
      }})
      Intel.add({ sessionID: session.id, data: {
        type: "sensitive_data",
        severity: "info",
        title: "Customer profile fields described",
        detail: "Profile documentation mentions email address and phone number",
        asset: "app.example.com",
        source: "test",
        confidenceLevel: "high",
        tags: ["customer-data"],
      }})

      const chain = Chain.detect(session.id).find((item) => item.pattern === "information_amplification")
      expect(chain).toBeDefined()
      expect(chain?.expectedImpact).toBe("POTENTIAL_CROSS_TENANT_OR_PRIVATE_DATA_ACCESS")
      expect(chain?.status).toBe("detected")
      expect(chain?.testingPlan).toContain("baseline and negative control")
      await Session.remove(session.id)
    }})
  })

  test("does not chain generic INFO entries with no complementary relationship", async () => {
    await Instance.provide({ directory: projectRoot, fn: async () => {
      const session = await Session.create({})
      Intel.add({ sessionID: session.id, data: {
        type: "technology",
        severity: "info",
        title: "Frontend framework identified",
        detail: "The site references a common frontend framework",
        asset: "app.example.com",
        source: "test",
        confidenceLevel: "high",
      }})
      Intel.add({ sessionID: session.id, data: {
        type: "technology",
        severity: "info",
        title: "Analytics library identified",
        detail: "The site references a common analytics library",
        asset: "app.example.com",
        source: "test",
        confidenceLevel: "high",
      }})
      expect(Chain.detect(session.id).some((item) => item.pattern === "information_amplification")).toBe(false)
      await Session.remove(session.id)
    }})
  })
})
