import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Vulnerability } from "../../src/session/vulnerability"
import { Chain } from "../../src/methodology/chain"
import { Identifier } from "../../src/id/id"

function candidate(): Chain.Candidate {
  return {
    id: Identifier.ascending("chain_candidate"),
    pattern: "custom",
    entryIDs: ["int-source", "int-target"],
    entryTitles: ["Source intel", "Target intel"],
    assets: ["https://example.test"],
    expectedImpact: "Combined impact hypothesis",
    severity: "high",
    testingPlan: "Validate both findings independently",
    status: "detected",
    confidence: 60,
    detectedAt: Date.now(),
  }
}

test("chain finding links are session-scoped, idempotent, and survive chain re-detection", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      const otherSession = await Session.create({})
      try {
        const source = Vulnerability.add({
          sessionID: session.id,
          data: { severity: "medium", title: "Source finding", description: "source evidence" },
        })
        const target = Vulnerability.add({
          sessionID: session.id,
          data: { severity: "medium", title: "Target finding", description: "target evidence" },
        })
        const outside = Vulnerability.add({
          sessionID: otherSession.id,
          data: { severity: "medium", title: "Other session finding", description: "must not cross sessions" },
        })
        const chain = candidate()
        Chain.save(session.id, [chain])

        const input = {
          sessionID: session.id,
          chainID: chain.id,
          sourceFindingID: source.id,
          targetFindingID: target.id,
          relation: "enables" as const,
        }
        const linked = Chain.linkFindings(input)
        expect(linked.ok).toBe(true)
        if (!linked.ok) throw new Error("Expected chain finding link to be stored")
        expect(linked.created).toBe(true)

        const repeated = Chain.linkFindings(input)
        expect(repeated.ok).toBe(true)
        if (!repeated.ok) throw new Error("Expected existing chain finding link")
        expect(repeated.created).toBe(false)

        const acrossSessions = Chain.linkFindings({ ...input, targetFindingID: outside.id })
        expect(acrossSessions).toEqual({ ok: false, reason: "finding_not_found" })

        const falsePositive = Vulnerability.add({
          sessionID: session.id,
          data: { severity: "low", title: "Rejected finding", description: "false positive candidate" },
        })
        expect(Vulnerability.update({
          sessionID: session.id,
          id: falsePositive.id,
          status: "false_positive",
          expectedStatus: "new",
        })).toBe(true)
        expect(Chain.linkFindings({ ...input, targetFindingID: falsePositive.id })).toEqual({
          ok: false,
          reason: "inactive_finding",
        })
        expect(Chain.linkFindings({ ...input, targetFindingID: source.id })).toEqual({
          ok: false,
          reason: "self_link",
        })

        // Re-detection updates the existing chain row instead of deleting the FK-linked edge.
        Chain.save(session.id, [{ ...chain, expectedImpact: "Updated hypothesis text" }])
        const reloaded = Chain.load(session.id).find((item) => item.id === chain.id)
        expect(reloaded?.expectedImpact).toBe("Updated hypothesis text")
        expect(reloaded?.findingLinks).toHaveLength(1)
        expect(reloaded?.findingLinks?.[0]).toMatchObject({
          sourceFindingID: source.id,
          targetFindingID: target.id,
          relation: "enables",
        })
      } finally {
        await Session.remove(otherSession.id)
        await Session.remove(session.id)
      }
    },
  })
})
