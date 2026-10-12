import { expect, spyOn, test } from "bun:test"
import { fetchResearchText } from "../../src/research/safe-fetch"

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
      await expect(fetchResearchText("https://research.example/start", source)).rejects.toThrow(
        "blocked research redirect",
      )
    },
  )

  expect(requested).toEqual(["https://research.example/start"])
  expect(redirectModes).toEqual(["manual"])
})

test("follows same-host HTTPS redirects and returns the bounded response body", async () => {
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
      await expect(fetchResearchText("https://research.example/start", source)).resolves.toBe(
        "A useful public security research article.",
      )
    },
  )

  expect(requested).toEqual(["https://research.example/start", "https://research.example/article"])
  expect(redirectModes).toEqual(["manual", "manual"])
})

test("rejects oversized responses even when Content-Length is absent", async () => {
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
      await expect(fetchResearchText("https://research.example/large", source)).rejects.toThrow(
        "research document too large",
      )
    },
  )

  expect(requested).toEqual(["https://research.example/large"])
})

test("rejects an initially out-of-scope URL without making a request", async () => {
  let requests = 0

  await withFetch(
    (async () => {
      requests++
      return new Response("should not be fetched")
    }) as unknown as typeof fetch,
    async () => {
      await expect(fetchResearchText("https://untrusted.example/private", source)).rejects.toThrow(
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
      await expect(fetchResearchText("https://research.example/binary", source)).rejects.toThrow(
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
      await expect(fetchResearchText("https://research.example/retry", source)).resolves.toBe(
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
      await expect(fetchResearchText("https://research.example/0", source)).rejects.toThrow(
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
      await expect(fetchResearchText("https://research.example/missing", source)).rejects.toThrow("HTTP 404")
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
      await expect(fetchResearchText("https://user:password@research.example/private", source)).rejects.toThrow(
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
        await expect(fetchResearchText("https://research.example/start", source)).rejects.toThrow(
          "research fetch exceeded total time budget",
        )
      },
    )
    expect(requests).toBe(1)
  } finally {
    clock.mockRestore()
  }
})
