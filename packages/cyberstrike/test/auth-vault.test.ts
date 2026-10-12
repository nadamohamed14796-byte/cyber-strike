import { describe, expect, test } from "bun:test"
import { isAuthVaultDataValid, normalizeAuthOrigin } from "../src/auth-vault"

describe("normalizeAuthOrigin", () => {
  test("matches only the normalized origin, not a path", () => {
    expect(normalizeAuthOrigin("https://Example.com/login?next=/account")).toBe("https://example.com")
    expect(normalizeAuthOrigin("https://example.com/another/path")).toBe("https://example.com")
  })

  test("preserves non-default ports as part of the origin", () => {
    expect(normalizeAuthOrigin("https://example.com:8443/login")).toBe("https://example.com:8443")
  })

  test("rejects non-http protocols", () => {
    expect(() => normalizeAuthOrigin("file:///tmp/secret")).toThrow("Only http(s) origins")
  })

  test("rejects credentials embedded in a URL", () => {
    expect(() => normalizeAuthOrigin("https://user:pass@example.com")).toThrow("Do not put credentials")
  })
})


describe("AuthVault persisted data validation", () => {
  const validRecord = () => ({
    id: "0123456789abcdef0123456789abcdef",
    origin: "https://example.com",
    purpose: "target",
    account: "research-account",
    username: "tester@example.com",
    targetID: "target_123",
    password: {
      iv: Buffer.alloc(12, 1).toString("base64"),
      tag: Buffer.alloc(16, 2).toString("base64"),
      ciphertext: Buffer.alloc(32, 3).toString("base64"),
    },
    createdAt: 1,
    updatedAt: 2,
  })

  test("accepts an empty vault and a correctly shaped encrypted profile", () => {
    expect(isAuthVaultDataValid([])).toBe(true)
    expect(isAuthVaultDataValid([validRecord()])).toBe(true)
  })

  test("rejects malformed rows instead of trusting an array cast", () => {
    expect(isAuthVaultDataValid([null])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), username: 123 }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), account: "bad\nlabel" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), username: "bad\nname" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), origin: "file:///etc/passwd" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), targetID: undefined }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), targetID: "target\nforged" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), purpose: "research", targetID: "target_123" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), password: { iv: "abc", tag: "bad", ciphertext: "x" } }])).toBe(false)
  })

  test("rejects duplicate profile IDs that would make secret lookup ambiguous", () => {
    const row = validRecord()
    expect(isAuthVaultDataValid([row, { ...row, account: "another-account" }])).toBe(false)
  })
})


test("AuthVault encrypts secrets at rest, scopes reads, and serializes concurrent updates", async () => {
  const { mkdtemp, readFile, readdir, rm, stat } = await import("node:fs/promises")
  const os = await import("node:os")
  const path = await import("node:path")
  const root = await mkdtemp(path.join(os.tmpdir(), "cyberstrike-auth-vault-test-"))
  const dataHome = path.join(root, "xdg-data")
  const configHome = path.join(root, "xdg-config")
  const cacheHome = path.join(root, "xdg-cache")
  const stateHome = path.join(root, "xdg-state")
  const secret = "auth-vault-test-password-not-for-storage"
  const replacement = "auth-vault-replacement-password-not-for-storage"
  const key = "test-only-vault-key-with-more-than-thirty-two-characters"
  const env = Object.fromEntries(Object.entries(process.env).filter(
    (entry): entry is [string, string] => typeof entry[1] === "string",
  )) as Record<string, string>
  Object.assign(env, {
    XDG_DATA_HOME: dataHome,
    XDG_CONFIG_HOME: configHome,
    XDG_CACHE_HOME: cacheHome,
    XDG_STATE_HOME: stateHome,
    CYBERSTRIKE_CREDENTIALS_KEY: key,
  })
  const script = `
    const { AuthVault } = await import("./src/auth-vault.ts")
    const profile = await AuthVault.save({
      origin: "https://example.test/login",
      purpose: "target",
      account: "primary",
      username: "tester@example.test",
      password: ${JSON.stringify(secret)},
      targetID: "target_test_123",
    })
    const updated = await AuthVault.save({
      origin: "https://example.test",
      purpose: "target",
      account: "primary",
      username: "tester@example.test",
      password: ${JSON.stringify(replacement)},
      targetID: "target_test_123",
    })
    const decoded = await AuthVault.getSecret({
      id: updated.id, origin: updated.origin, purpose: "target", targetID: "target_test_123",
    })
    const wrongTarget = await AuthVault.getSecret({
      id: profile.id, origin: profile.origin, purpose: "target", targetID: "other_target",
    })
    await Promise.all(Array.from({ length: 6 }, (_, index) => AuthVault.save({
      origin: "https://example.test",
      purpose: "target",
      account: "parallel-" + index,
      username: "parallel-" + index + "@example.test",
      password: "parallel-secret-" + index,
      targetID: "target_test_123",
    })))
    const listed = await AuthVault.list({ purpose: "target", targetID: "target_test_123" })
    const removed = await AuthVault.remove({
      id: profile.id, origin: profile.origin, purpose: "target", targetID: "target_test_123",
    })
    console.log(JSON.stringify({
      profile,
      updatedSameID: updated.id === profile.id,
      decodedPassword: decoded?.password,
      wrongTarget: wrongTarget ?? null,
      listedCount: listed.length,
      removed,
      afterRemoveCount: (await AuthVault.list({ purpose: "target", targetID: "target_test_123" })).length,
    }))
  `
  try {
    const proc = Bun.spawn([process.execPath, "-e", script], {
      cwd: process.cwd(),
      env,
      stdout: "pipe",
      stderr: "pipe",
    })
    const [exitCode, stdout, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ])
    if (exitCode !== 0) throw new Error("AuthVault subprocess failed: " + stderr)
    expect(exitCode).toBe(0)
    const result = JSON.parse(stdout) as {
      profile: { id: string; origin: string; purpose: string; targetID?: string }
      updatedSameID: boolean
      decodedPassword: string
      wrongTarget: unknown
      listedCount: number
      removed: boolean
      afterRemoveCount: number
    }
    expect(result.profile.origin).toBe("https://example.test")
    expect(result.profile.purpose).toBe("target")
    expect(result.profile.targetID).toBe("target_test_123")
    expect(result.updatedSameID).toBe(true)
    expect(result.decodedPassword).toBe(replacement)
    expect(result.wrongTarget).toBeNull()
    expect(result.listedCount).toBe(7)
    expect(result.removed).toBe(true)
    expect(result.afterRemoveCount).toBe(6)

    const vaultPath = path.join(dataHome, "cyberstrike", "auth-vault.json")
    const raw = await readFile(vaultPath, "utf8")
    expect(raw).not.toContain(secret)
    expect(raw).not.toContain(replacement)
    expect(raw).toContain("ciphertext")
    expect((await stat(vaultPath)).mode & 0o777).toBe(0o600)
    expect((await stat(path.dirname(vaultPath))).mode & 0o777).toBe(0o700)
    expect((await readdir(path.dirname(vaultPath))).filter((name) => name.endsWith(".tmp"))).toEqual([])

    const wrongKeyEnv = { ...env, CYBERSTRIKE_CREDENTIALS_KEY: "different-wrong-key-that-is-also-long-enough-for-test" }
    const wrongKeyScript = `
      const { AuthVault } = await import("./src/auth-vault.ts")
      const rows = await AuthVault.list({ purpose: "target", targetID: "target_test_123" })
      try {
        await AuthVault.getSecret({ id: rows[0].id, origin: rows[0].origin, purpose: "target", targetID: "target_test_123" })
        console.log("unexpected-decryption-success")
      } catch {
        console.log("wrong-key-rejected")
      }
    `
    const wrongKeyProc = Bun.spawn([process.execPath, "-e", wrongKeyScript], {
      cwd: process.cwd(),
      env: wrongKeyEnv,
      stdout: "pipe",
      stderr: "pipe",
    })
    const [wrongKeyExit, wrongKeyOut, wrongKeyErr] = await Promise.all([
      wrongKeyProc.exited,
      new Response(wrongKeyProc.stdout).text(),
      new Response(wrongKeyProc.stderr).text(),
    ])
    if (wrongKeyExit !== 0) throw new Error("Wrong-key subprocess failed: " + wrongKeyErr)
    expect(wrongKeyExit).toBe(0)
    expect(wrongKeyOut.trim()).toBe("wrong-key-rejected")
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
