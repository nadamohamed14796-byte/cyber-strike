import { describe, test, expect } from "bun:test"
import * as tar from "tar"
import fs from "node:fs/promises"
import { tmpdir } from "../fixture/fixture"
import { Discovery } from "../../src/skill/discovery"
import path from "path"

const CLOUDFLARE_SKILLS_URL = "https://developers.cloudflare.com/.well-known/skills/"

describe("remote skill path validation", () => {
  const root = path.resolve("/tmp/cyberstrike-skill-cache/example")

  test("bounded response reader accepts bodies at the limit and rejects oversized bodies", async () => {
    expect(await Discovery.readBoundedBody(new Response("1234"), 4)).toEqual(new Uint8Array([49, 50, 51, 52]))
    expect(await Discovery.readBoundedBody(new Response("12345"), 4)).toBeUndefined()
    expect(await Discovery.readBoundedBody(new Response("1234", { headers: { "content-length": "5" } }), 4)).toBeUndefined()
  })

  test("invalid registry URLs fail closed without throwing", async () => {
    expect(await Discovery.pull("not a URL")).toEqual([])
    expect(await Discovery.pull("")).toEqual([])
  })

  test("bounded response reader accounts for the chunk that exhausts a shared budget", async () => {
    let received = 0
    const result = await Discovery.readBoundedBody(new Response("1234"), 10, (size) => {
      received += size
      return received <= 3
    })
    expect(result).toBeUndefined()
    expect(received).toBe(4)
  })

  test("remote skill URL policy rejects local, literal-IP, credentialed, and non-HTTPS destinations", () => {
    expect(Discovery.isSafeRemoteURLShape("https://developers.cloudflare.com/.well-known/skills/index.json")).toBe(true)
    for (const url of [
      "http://example.com/index.json",
      "file:///etc/passwd",
      "https://127.0.0.1/index.json",
      "https://[::1]/index.json",
      "https://localhost/index.json",
      "https://internal.example.local/index.json",
      "https://user:pass@example.com/index.json",
      "https://example.com:8443/index.json",
    ]) {
      expect(Discovery.isSafeRemoteURLShape(url)).toBe(false)
    }
  })

  test("remote skill redirects cannot downgrade HTTPS or target local hosts", () => {
    expect(Discovery.safeRemoteRedirectURL(
      "https://developers.cloudflare.com/.well-known/skills/index.json",
      "../catalog.json",
    )).toBe("https://developers.cloudflare.com/.well-known/catalog.json")
    expect(Discovery.safeRemoteRedirectURL("https://example.com/index.json", "https://cdn.example.net/skills.tar.gz"))
      .toBe("https://cdn.example.net/skills.tar.gz")
    for (const location of [
      "http://example.com/index.json",
      "https://127.0.0.1/metadata",
      "https://localhost/private",
      "file:///etc/passwd",
    ]) {
      expect(Discovery.safeRemoteRedirectURL("https://example.com/index.json", location)).toBeUndefined()
    }
    expect(Discovery.safeRemoteRedirectURL("https://example.com/index.json", "http://[")).toBeUndefined()
  })

  test("remote DNS destinations must resolve only to public addresses", () => {
    expect(Discovery.isPublicAddress("8.8.8.8")).toBe(true)
    expect(Discovery.isPublicAddress("2606:4700:4700::1111")).toBe(true)
    expect(Discovery.isPublicAddress("2001:200::1")).toBe(true)
    for (const address of [
      "127.0.0.1", "10.0.0.1", "169.254.169.254", "172.16.0.1",
      "192.168.1.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
      "224.0.0.1", "::1", "fc00::1", "fe80::1", "2001:db8::1",
      "2001:1::1", "2001:2::1", "2002:7f00:1::", "3fff::1",
      "2001:0000:0000:0000:0000:0000:0000:0001",
    ]) {
      expect(Discovery.isPublicAddress(address)).toBe(false)
    }
  })

  test("archive expansion limits reject decompression bombs and excessive manifests", () => {
    const mebibyte = 1024 * 1024
    expect(Discovery.isSafeArchiveExpansion([1, 2, 3])).toBe(true)
    expect(Discovery.isSafeArchiveExpansion([25 * mebibyte + 1])).toBe(false)
    expect(Discovery.isSafeArchiveExpansion([50 * mebibyte, 50 * mebibyte, 1])).toBe(false)
    expect(Discovery.isSafeArchiveExpansion([-1])).toBe(false)
    expect(Discovery.isSafeArchiveExpansion([Number.NaN])).toBe(false)
    expect(Discovery.isSafeArchiveExpansion(Array.from({ length: 10_001 }, () => 0))).toBe(false)
  })

  test("accepts ordinary skill slugs and nested relative files", () => {
    expect(Discovery.isSafeSkillName("agents-sdk")).toBe(true)
    expect(Discovery.isSafeSkillName("wstg.injection_01")).toBe(true)
    expect(Discovery.resolveSkillFilePath(root, "references/guide.md")).toBe(path.join(root, "references", "guide.md"))
  })

  test("rejects names that can escape the skill cache", () => {
    for (const name of ["../outside", "..", "nested/name", "nested\\name", "/tmp/outside", "C:outside", ""]) {
      expect(Discovery.isSafeSkillName(name)).toBe(false)
    }
  })

  test("rejects parent traversal, absolute paths, and URL-like file entries", () => {
    for (const file of ["../outside.txt", "references/../../outside.txt", "..\\outside.txt", "C:\\outside.txt", "/tmp/outside.txt", "https://example.com/outside.txt", ""]) {
      expect(Discovery.resolveSkillFilePath(root, file)).toBeUndefined()
    }
  })

  test("rejects a resolved destination equal to or outside the skill root", () => {
    expect(Discovery.resolveSkillFilePath(root, ".")).toBeUndefined()
    expect(Discovery.resolveSkillFilePath(root, "safe/../../outside.txt")).toBeUndefined()
  })
})

describe("Discovery.pull", () => {
  test("downloads skills from cloudflare url", async () => {
    const dirs = await Discovery.pull(CLOUDFLARE_SKILLS_URL)
    expect(dirs.length).toBeGreaterThan(0)
    for (const dir of dirs) {
      expect(dir).toStartWith(Discovery.dir())
      const md = path.join(dir, "SKILL.md")
      expect(await Bun.file(md).exists()).toBe(true)
    }
  }, 30_000)

  test("url without trailing slash works", async () => {
    const dirs = await Discovery.pull(CLOUDFLARE_SKILLS_URL.replace(/\/$/, ""))
    expect(dirs.length).toBeGreaterThan(0)
    for (const dir of dirs) {
      const md = path.join(dir, "SKILL.md")
      expect(await Bun.file(md).exists()).toBe(true)
    }
  }, 30_000)

  test("returns empty array for invalid url", async () => {
    const dirs = await Discovery.pull("https://example.invalid/.well-known/skills/")
    expect(dirs).toEqual([])
  })

  test("returns empty array for non-json response", async () => {
    const dirs = await Discovery.pull("https://example.com/")
    expect(dirs).toEqual([])
  })

  test("downloads reference files alongside SKILL.md", async () => {
    const dirs = await Discovery.pull(CLOUDFLARE_SKILLS_URL)
    // find a skill dir that should have reference files (e.g. agents-sdk)
    const agentsSdk = dirs.find((d) => d.endsWith("/agents-sdk"))
    if (agentsSdk) {
      const refs = path.join(agentsSdk, "references")
      expect(await Bun.file(path.join(agentsSdk, "SKILL.md")).exists()).toBe(true)
      // agents-sdk has reference files per the index
      const refDir = await Array.fromAsync(new Bun.Glob("**/*.md").scan({ cwd: refs, onlyFiles: true }))
      expect(refDir.length).toBeGreaterThan(0)
    }
  }, 30_000)

  test("caches downloaded files on second pull", async () => {
    // first pull to populate cache
    const first = await Discovery.pull(CLOUDFLARE_SKILLS_URL)
    expect(first.length).toBeGreaterThan(0)

    // second pull should return same results from cache
    const second = await Discovery.pull(CLOUDFLARE_SKILLS_URL)
    expect(second.length).toBe(first.length)
    expect(second.sort()).toEqual(first.sort())
  }, 60_000)
})


test("rejects unsafe archive traversal and links", () => {
  const root = "/tmp/cyberstrike-safe-skill-cache"
  expect(Discovery.isSafeArchiveEntry(root, "SKILL.md", "File")).toBe(true)
  expect(Discovery.isSafeArchiveEntry(root, "references/guide.md", "File")).toBe(true)
  expect(Discovery.isSafeArchiveEntry(root, "../../outside.txt", "File")).toBe(false)
  expect(Discovery.isSafeArchiveEntry(root, "/etc/passwd", "File")).toBe(false)
  expect(Discovery.isSafeArchiveEntry(root, "escape", "SymbolicLink")).toBe(false)
  expect(Discovery.isSafeArchiveEntry(root, "escape", "Link")).toBe(false)
})

test("downloads and extracts archive bytes without UTF-8 corruption", async () => {
  await using tmp = await tmpdir()
  const sourceFile = path.join(tmp.path, "SKILL.md")
  const archiveFile = path.join(tmp.path, "fixture.tar.gz")
  await fs.writeFile(sourceFile, "# Binary archive fixture\n\narchive bytes must be preserved\n")
  await tar.c({ gzip: true, file: archiveFile, cwd: tmp.path }, ["SKILL.md"])
  const archiveBytes = await fs.readFile(archiveFile)
  const skillName = "archive-fixture-" + process.pid + "-" + Date.now()
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input)
    if (url.endsWith("/index.json")) {
      return new Response(JSON.stringify({
        skills: [{ name: skillName, description: "binary fixture", type: "archive", url: "fixture.tar.gz" }],
      }), { headers: { "content-type": "application/json" } })
    }
    if (url.endsWith("/fixture.tar.gz")) {
      const body = new ArrayBuffer(archiveBytes.byteLength)
      new Uint8Array(body).set(archiveBytes)
      return new Response(body)
    }
    return new Response("not found", { status: 404 })
  }) as typeof fetch

  try {
    const dirs = await Discovery.pull("https://example.com/")
    expect(dirs).toContain(path.join(Discovery.dir(), skillName))
    expect(await fs.readFile(path.join(Discovery.dir(), skillName, "SKILL.md"), "utf8")).toContain(
      "archive bytes must be preserved",
    )
  } finally {
    globalThis.fetch = originalFetch
    await fs.rm(path.join(Discovery.dir(), skillName), { recursive: true, force: true })
  }
})
