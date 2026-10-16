import { describe, expect, test } from "bun:test"
import { SkillSigning } from "../../src/skill/signing"

const official = "cyberstrike-official"

function skillContent(extraFrontmatter = "") {
  return `---
name: signing-fixture
description: Signature verification fixture.
${extraFrontmatter}---
# Test skill
`
}

describe("SkillSigning", () => {
  test("rejects an official signer claim with no hash", async () => {
    const content = skillContent(`signed_by: ${official}\n`)
    expect(await SkillSigning.verify({ content, signed_by: official })).toBe("tampered")
  })

  test("rejects an official signer claim with no signature", async () => {
    const unsigned = skillContent(`signed_by: ${official}\n`)
    const sha256 = await SkillSigning.computeHash(unsigned)
    const content = skillContent(`sha256: ${sha256}\nsigned_by: ${official}\n`)
    expect(await SkillSigning.verify({ content, sha256, signed_by: official })).toBe("tampered")
  })

  test("rejects an invalid official signature", async () => {
    const unsigned = skillContent()
    const sha256 = await SkillSigning.computeHash(unsigned)
    const signature = Buffer.alloc(64).toString("base64")
    const content = skillContent(`sha256: ${sha256}\nsignature: ${signature}\nsigned_by: ${official}\n`)
    expect(await SkillSigning.verify({ content, sha256, signature, signed_by: official })).toBe("tampered")
  })

  test("keeps unsigned skills available as unverified", async () => {
    const content = skillContent()
    expect(await SkillSigning.verify({ content })).toBe("unverified")
  })

  test("classifies a correctly hashed non-official skill as community", async () => {
    const content = skillContent()
    const sha256 = await SkillSigning.computeHash(content)
    expect(await SkillSigning.verify({ content, sha256 })).toBe("community")
  })
})
