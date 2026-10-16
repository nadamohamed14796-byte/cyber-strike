import { expect, test } from "bun:test"
import { Database } from "../../src/storage/db"
import { RequestTable, SessionTable, WebCredentialTable } from "../../src/session/session.sql"
import { Instance } from "../../src/project/instance"
import { fetchResearchText, researchSourceHasCredentials } from "../../src/research/safe-fetch"
import { tmpdir } from "../fixture/fixture"

const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }]

test("captured research cookies are reused only on the exact host and never forwarded across redirects", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const sessionID = "ses_research_cookie_" + crypto.randomUUID().replace(/-/g, "").slice(0, 20)
      const credentialID = "cred_research_cookie_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16)
      const now = Date.now()
      const cookieEnv = "CYBERSTRIKE_RESEARCH_COOKIE_CAPTURED_SESSION_COOKIE_TEST"
      const authEnv = "CYBERSTRIKE_RESEARCH_AUTHORIZATION_CAPTURED_SESSION_COOKIE_TEST"
      const originalCookie = process.env[cookieEnv]
      const originalAuthorization = process.env[authEnv]
      delete process.env[cookieEnv]
      delete process.env[authEnv]

      Database.use((db) => {
        db.insert(SessionTable).values({
          id: sessionID,
          project_id: Instance.project.id,
          slug: "research-cookie-test",
          directory: dir.path,
          title: "Research cookie test",
          version: "1",
          time_created: now,
          time_updated: now,
        }).run()
        db.insert(WebCredentialTable).values({
          id: credentialID,
          session_id: sessionID,
          label: "captured-source-session",
          headers: { Cookie: "research_session=exact-host-secret" },
          time_created: now,
          time_updated: now,
        }).run()
        db.insert(RequestTable).values({
          id: "req_research_cookie_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16),
          session_id: sessionID,
          credential_id: credentialID,
          method: "GET",
          normalized_path: "/account",
          raw_request: "GET /account HTTP/1.1\r\nHost: research.example\r\n\r\n",
          status: "processed",
          scheme: "https",
          host: "research.example",
          origin: "https://research.example",
          time_created: now,
          time_updated: now,
        }).run()
        db.insert(RequestTable).values({
          id: "req_research_cookie_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16),
          session_id: sessionID,
          credential_id: null,
          method: "GET",
          normalized_path: "/writeups",
          raw_request: "GET /writeups HTTP/1.1\r\nHost: mirror.example\r\nCookie: mirror_session=mirror-host-secret\r\n\r\n",
          status: "processed",
          scheme: "https",
          host: "mirror.example",
          origin: "https://mirror.example",
          time_created: now + 1,
          time_updated: now + 1,
        }).run()
      })

      const source = {
        id: "captured-session-cookie-test",
        name: "Cookie scope test",
        kind: "research" as const,
        seedUrls: ["https://research.example/"],
        hosts: ["research.example", "mirror.example"],
        trust: 80,
      }
      const requested: Array<{ url: string; cookie: string | null }> = []
      const originalFetch = globalThis.fetch
      globalThis.fetch = (async (input, init) => {
        const url = new URL(input instanceof Request ? input.url : String(input))
        requested.push({ url: url.toString(), cookie: new Headers(init?.headers).get("cookie") })
        if (url.hostname === "research.example") {
          return new Response(null, { status: 302, headers: { location: "https://mirror.example/report" } })
        }
        return new Response("Public research report content.", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        })
      }) as typeof fetch

      try {
        expect(researchSourceHasCredentials(source, [sessionID])).toBe(true)
        expect(researchSourceHasCredentials({ ...source, hosts: ["unrelated.example"] }, [sessionID])).toBe(false)
        await expect(fetchResearchText("https://research.example/start", source, publicLookup, [sessionID]))
          .resolves.toBe("Public research report content.")
        expect(requested[0]).toMatchObject({
          url: "https://research.example/start",
          cookie: "research_session=exact-host-secret",
        })
        // A cookie captured for mirror.example is not attached to the redirected hop,
        // because that hop's initial request host was research.example.
        expect(requested[1]).toMatchObject({
          url: "https://mirror.example/report",
          cookie: null,
        })

        await expect(fetchResearchText("https://mirror.example/writeups", source, publicLookup, [sessionID]))
          .resolves.toBe("Public research report content.")
        expect(requested[2]).toMatchObject({
          url: "https://mirror.example/writeups",
          cookie: "mirror_session=mirror-host-secret",
        })
      } finally {
        globalThis.fetch = originalFetch
        if (originalCookie === undefined) delete process.env[cookieEnv]
        else process.env[cookieEnv] = originalCookie
        if (originalAuthorization === undefined) delete process.env[authEnv]
        else process.env[authEnv] = originalAuthorization
        await Instance.dispose()
      }
    },
  })
})
