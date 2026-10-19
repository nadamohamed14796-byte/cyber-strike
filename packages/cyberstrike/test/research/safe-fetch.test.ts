import { expect, spyOn, test } from "bun:test"
import { fetchResearchText, isPublicResearchAddress, researchSourceHasCredentials } from "../../src/research/safe-fetch"
import { researchSessionCookieForHost } from "../../src/research/safe-fetch"
import { Database } from "../../src/storage/db"
import { Instance } from "../../src/project/instance"
import { RequestTable, SessionTable, WebCredentialTable } from "../../src/session/session.sql"
import { tmpdir } from "../fixture/fixture"

const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }]
function fetchTest(url: string, selectedSource: typeof source = source, resolveHost = publicLookup) {
  return fetchResearchText(url, selectedSource, resolveHost)
}

const source = {
  id: "test",
  name: "Test source",
  kind: "research" as const,
  seedUrls: ["https://research.example/"],
  hosts: ["research.example"],
  trust: 80,
}

async function withFetch(implementation: typeof fetch, run: () => Promise<void>) {
  const original = globalThis.fetch
  globalThis.fetch = implementation
  try {
    await run()
  } finally {
    globalThis.fetch = original
  }
}

test("blocks a redirect outside the configured HTTPS source hosts", async () => {
  const requested: string[] = []
  const redirectModes: RequestRedirect[] = []

  await withFetch(
    (async (input, init) => {
      requested.push(new URL(input instanceof Request ? input.url : String(input)).toString())
      redirectModes.push(init?.redirect ?? "follow")
      return new Response(null, {
        status: 302,
        headers: { location: "http://127.0.0.1:8080/admin" },
      })
    }) as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example/start", source)).rejects.toThrow(
        "blocked research redirect",
      )
    },
  )

  expect(requested).toEqual(["https://research.example/start"])
  expect(redirectModes).toEqual(["manual"])
})

test("follows same-host HTTPS redirects and returns the complete response body", async () => {
  const requested: string[] = []
  const redirectModes: RequestRedirect[] = []

  await withFetch(
    (async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      requested.push(url.toString())
      redirectModes.push(init?.redirect ?? "follow")
      if (url.pathname === "/start") {
        return new Response(null, { status: 302, headers: { location: "/article" } })
      }
      return new Response("A useful public security research article.", {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
      })
    }) as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example/start", source)).resolves.toBe(
        "A useful public security research article.",
      )
    },
  )

  expect(requested).toEqual(["https://research.example/start", "https://research.example/article"])
  expect(redirectModes).toEqual(["manual", "manual"])
})

test("reads complete research documents even when Content-Length is absent", async () => {
  const requested: string[] = []

  await withFetch(
    (async (input) => {
      requested.push(new URL(input instanceof Request ? input.url : String(input)).toString())
      return new Response(new Uint8Array(1_500_001), {
        status: 200,
        headers: { "content-type": "text/html" },
      })
    }) as typeof fetch,
    async () => {
      const result = await fetchTest("https://research.example/large", source)
      expect(result).toHaveLength(1_500_001)
    },
  )

  expect(requested).toEqual(["https://research.example/large"])
})

test("rejects an allowlisted source hostname on a non-standard HTTPS port before fetching", async () => {
  let requests = 0
  await withFetch(
    (async () => {
      requests++
      return new Response("must not be fetched")
    }) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example:8443/private", source)).rejects.toThrow(
        "blocked research host",
      )
    },
  )
  expect(requests).toBe(0)
})

test("rejects an initially out-of-scope URL without making a request", async () => {
  let requests = 0

  await withFetch(
    (async () => {
      requests++
      return new Response("should not be fetched")
    }) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://untrusted.example/private", source)).rejects.toThrow(
        "blocked research host",
      )
    },
  )

  expect(requests).toBe(0)
})

test("cancels bodies from unsupported content types", async () => {
  let canceled = false
  await withFetch(
    (async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("binary response"))
          },
          cancel() {
            canceled = true
          },
        }),
        { status: 200, headers: { "content-type": "application/octet-stream" } },
      )) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example/binary", source)).rejects.toThrow(
        "unsupported content type",
      )
    },
  )
  expect(canceled).toBe(true)
})

test("retries transient server failures but succeeds once the source recovers", async () => {
  let requests = 0
  await withFetch(
    (async () => {
      requests++
      if (requests === 1) return new Response("temporarily unavailable", { status: 503 })
      return new Response("Recovered public report.", {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      })
    }) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example/retry", source)).resolves.toBe(
        "Recovered public report.",
      )
    },
  )
  expect(requests).toBe(2)
})

test("stops at the configured redirect budget", async () => {
  const requested: string[] = []
  await withFetch(
    (async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      requested.push(url.toString())
      const depth = Number(url.pathname.slice(1))
      return new Response(null, {
        status: 302,
        headers: { location: "/" + (depth + 1) },
      })
    }) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example/0", source)).rejects.toThrow(
        "too many research redirects",
      )
    },
  )
  expect(requested).toHaveLength(6)
  expect(requested[5]).toBe("https://research.example/5")
})

test("does not retry terminal client errors", async () => {
  let requests = 0
  await withFetch(
    (async () => {
      requests++
      return new Response("not found", {
        status: 404,
        headers: { "content-type": "text/plain" },
      })
    }) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example/missing", source)).rejects.toThrow("HTTP 404")
    },
  )
  expect(requests).toBe(1)
})

test("rejects source URLs containing embedded credentials", async () => {
  let requests = 0
  await withFetch(
    (async () => {
      requests++
      return new Response("should not be fetched")
    }) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://user:password@research.example/private", source)).rejects.toThrow(
        "blocked research host",
      )
    },
  )
  expect(requests).toBe(0)
})



test("enforces the total fetch deadline across redirects without sleeping", async () => {
  let now = 1_000_000
  const clock = spyOn(Date, "now").mockImplementation(() => now)
  let requests = 0
  try {
    await withFetch(
      (async () => {
        requests++
        // Simulate a slow first hop deterministically; no real 120-second wait.
        now += 120_001
        return new Response(null, {
          status: 302,
          headers: { location: "/next" },
        })
      }) as unknown as typeof fetch,
      async () => {
        await expect(fetchTest("https://research.example/start", source)).rejects.toThrow(
          "research fetch exceeded total time budget",
        )
      },
    )
    expect(requests).toBe(1)
  } finally {
    clock.mockRestore()
  }
})


test("rejects private, local, link-local, reserved and documentation IP literals", () => {
  for (const address of [
    "0.1.2.3",
    "10.1.2.3",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.10.20",
    "172.16.2.3",
    "192.168.1.2",
    "192.0.2.5",
    "198.18.1.2",
    "203.0.113.9",
    "224.0.0.1",
    "240.0.0.1",
    "::",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
    "2001:1::1",
    "2001:20::1",
    "2002::1",
    "3fff::1",
    "2001:0001:0000:0000:0000:0000:0000:0001",
    "3fff:0000:0000:0000:0000:0000:0000:0001",
  ]) {
    expect(isPublicResearchAddress(address)).toBe(false)
  }
  expect(isPublicResearchAddress("93.184.216.34")).toBe(true)
  expect(isPublicResearchAddress("192.0.0.9")).toBe(true)
  expect(isPublicResearchAddress("192.0.0.10")).toBe(true)
  expect(isPublicResearchAddress("192.0.0.8")).toBe(false)
  // These special-purpose AS112 anycast ranges are globally reachable; do not treat them as private/reserved.
  expect(isPublicResearchAddress("192.31.196.1")).toBe(true)
  expect(isPublicResearchAddress("192.52.193.1")).toBe(true)
  expect(isPublicResearchAddress("192.175.48.1")).toBe(true)
  expect(isPublicResearchAddress("2606:4700:4700::1111")).toBe(true)
})

test("blocks an allowlisted-looking hostname when DNS resolves to a private address", async () => {
  const resolver = async () => [{ address: "10.0.0.7", family: 4 }]
  await expect(fetchTest("https://research.example/private", source, resolver)).rejects.toThrow(
    "blocked research host resolving to a non-public address",
  )
})

test("revalidates DNS answers after a redirect", async () => {
  let resolution = 0
  const resolver = async () => {
    resolution++
    return [{ address: resolution === 1 ? "93.184.216.34" : "127.0.0.1", family: 4 }]
  }
  await withFetch(
    (async () => new Response(null, { status: 302, headers: { location: "/next" } })) as unknown as typeof fetch,
    async () => {
      await expect(fetchTest("https://research.example/start", source, resolver)).rejects.toThrow(
        "blocked research host resolving to a non-public address",
      )
    },
  )
  expect(resolution).toBe(2)
})


test("does not forward source credentials across a same-policy subdomain redirect", async () => {
  const envKey = "CYBERSTRIKE_RESEARCH_COOKIE_TEST"
  const prior = process.env[envKey]
  process.env[envKey] = "session=private"
  const seen: Array<{ url: string; cookie: string | null }> = []
  const multiHostSource = { ...source, hosts: ["research.example", "sub.research.example"] }
  try {
    await withFetch(
      (async (input, init) => {
        const url = new URL(input instanceof Request ? input.url : String(input))
        const headers = new Headers(init?.headers)
        seen.push({ url: url.toString(), cookie: headers.get("cookie") })
        if (url.hostname === "research.example") {
          return new Response(null, { status: 302, headers: { location: "https://sub.research.example/article" } })
        }
        return new Response("public report", { status: 200, headers: { "content-type": "text/plain" } })
      }) as typeof fetch,
      async () => {
        await expect(fetchResearchText("https://research.example/start", multiHostSource, publicLookup))
          .resolves.toBe("public report")
      },
    )
    expect(seen[0]?.cookie).toBe("session=private")
    expect(seen[1]?.cookie).toBeNull()
  } finally {
    if (prior === undefined) delete process.env[envKey]
    else process.env[envKey] = prior
  }
})


test("detects configured source-scoped auth without exposing the credential value", () => {
  const envKey = "CYBERSTRIKE_RESEARCH_COOKIE_TEST"
  const prior = process.env[envKey]
  try {
    delete process.env[envKey]
    expect(researchSourceHasCredentials(source)).toBe(false)
    process.env[envKey] = "  session=private  "
    expect(researchSourceHasCredentials(source)).toBe(true)
  } finally {
    if (prior === undefined) delete process.env[envKey]
    else process.env[envKey] = prior
  }
})


test("captured session cookies are reused only for the exact host and never forwarded across redirects", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID().replace(/-/g, "")
      const sessionID = "ses_research_cookie_" + marker.slice(0, 18)
      const credentialID = "cred_research_cookie_" + marker.slice(0, 18)
      const now = Date.now()
      Database.use((db) => {
        db.insert(SessionTable).values({
          id: sessionID,
          project_id: Instance.project.id,
          slug: "research-cookie-test",
          directory: dir.path,
          title: "Research cookie isolation test",
          version: "1",
          time_created: now,
          time_updated: now,
        }).run()
        db.insert(WebCredentialTable).values({
          id: credentialID,
          session_id: sessionID,
          label: "captured proxy request",
          headers: { Cookie: "session=from-capture" },
          time_created: now,
          time_updated: now,
        }).run()
        db.insert(RequestTable).values({
          id: "req_research_cookie_" + marker.slice(0, 18),
          session_id: sessionID,
          credential_id: credentialID,
          method: "GET",
          normalized_path: "/private",
          status: "captured",
          host: "research.example",
          scheme: "https",
          origin: "https://research.example:443",
          raw_request: "GET /private HTTP/1.1\r\nHost: research.example\r\n\r\n",
          time_created: now,
          time_updated: now,
        }).run()
        db.insert(RequestTable).values({
          id: "req_raw_cookie_" + marker.slice(0, 18),
          session_id: sessionID,
          method: "GET",
          normalized_path: "/private",
          status: "captured",
          host: "raw.example",
          scheme: "https",
          origin: "https://raw.example:443",
          raw_request: "GET /private HTTP/1.1\r\nHost: raw.example\r\nCookie: raw=session-captured\r\n\r\n",
          time_created: now + 1,
          time_updated: now + 1,
        }).run()
        db.insert(RequestTable).values({
          id: "req_other_cookie_" + marker.slice(0, 18),
          session_id: sessionID,
          method: "GET",
          normalized_path: "/private",
          status: "captured",
          host: "other.example",
          scheme: "https",
          origin: "https://other.example:443",
          raw_request: "GET /private HTTP/1.1\\r\\nHost: other.example\\r\\nCookie: other=session-secret\\r\\n\\r\\n",
          time_created: now + 1,
          time_updated: now + 1,
        }).run()
      })

      expect(researchSessionCookieForHost([sessionID], "research.example")).toBe("session=from-capture")
      expect(researchSessionCookieForHost([sessionID], "raw.example")).toBe("raw=session-captured")
      expect(researchSessionCookieForHost([sessionID], "sub.research.example")).toBeUndefined()
      expect(researchSourceHasCredentials({ ...source, hosts: ["research.example"] }, [sessionID])).toBe(true)
      expect(researchSourceHasCredentials({ ...source, hosts: ["unrelated.example"] }, [sessionID])).toBe(false)

      const seen: Array<{ hostname: string; cookie: string | null }> = []
      const redirectSource = { ...source, hosts: ["research.example", "sub.research.example"] }
      await withFetch(
        (async (input, init) => {
          const url = new URL(input instanceof Request ? input.url : String(input))
          seen.push({ hostname: url.hostname, cookie: new Headers(init?.headers).get("cookie") })
          if (url.hostname === "research.example") {
            return new Response(null, { status: 302, headers: { location: "https://sub.research.example/article" } })
          }
          return new Response("public security report", { status: 200, headers: { "content-type": "text/plain" } })
        }) as typeof fetch,
        async () => {
          await expect(fetchResearchText("https://research.example/private", redirectSource, publicLookup, [sessionID]))
            .resolves.toBe("public security report")
        },
      )
      expect(seen).toEqual([
        { hostname: "research.example", cookie: "session=from-capture" },
        { hostname: "sub.research.example", cookie: null },
      ])
      await Instance.dispose()
    },
  })
})
