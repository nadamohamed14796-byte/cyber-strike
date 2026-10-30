import { describe, expect, test } from "bun:test"
import { createHash } from "crypto"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { Observation } from "../../src/session/observation"
import { tmpdir } from "../fixture/fixture"

describe("Observation.operationTreeForRequest", () => {
  test("correlates distinct formAction body shapes under one endpoint operation", async () => {
    await using dir = await tmpdir({ git: true })
    await Instance.provide({
      directory: dir.path,
      fn: async () => {
        const session = await Session.create({ title: "operation-observation-tree-test" })
        const method = "POST"
        const origin = "https://example.test"
        const path = "/b/home"
        const opGroupHash = createHash("sha256")
          .update([method, origin, path, ""].join(" "))
          .digest("hex")
          .slice(0, 16)

        const create = (keyHash: string, credentialID: string, action: string) => {
          const request = Request.add({
            sessionID: session.id,
            method,
            normalizedPath: path,
            origin,
            credentialID,
            rawRequest: `POST ${path} HTTP/1.1\\r\\nHost: example.test\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n\\r\\nformAction=${action}`,
            bodyHash: "body-" + action,
            keyHash,
          })
          if (!request) throw new Error("request fixture was not inserted")
          Observation.observe({
            sessionID: session.id,
            keyHash,
            opGroupHash,
            requestID: request.id,
            credentialID,
            valueHash: "values-" + action,
            slots: [{ loc: "body", name: "formAction", value: action }],
          })
          return request
        }

        const owner = create("shape-user-contacts", "credential-owner", "fa_loadUserContacts")
        const lowUser = create("shape-org-groups", "credential-low", "fa_loadOrgGroupList")
        const tree = Observation.operationTreeForRequest(session.id, lowUser.id)

        expect(tree?.keyHashes.sort()).toEqual(["shape-org-groups", "shape-user-contacts"])
        expect(tree?.credentials.sort()).toEqual(["credential-low", "credential-owner"])
        expect(tree?.params).toEqual([
          {
            name: "formAction",
            loc: "body",
            byCredential: [
              { credentialID: "credential-owner", values: ["fa_loadUserContacts"], redacted: false },
              { credentialID: "credential-low", values: ["fa_loadOrgGroupList"], redacted: false },
            ],
          },
        ])
        expect(owner.id).not.toBe(lowUser.id)
        await Session.remove(session.id)
        await Instance.dispose()
      },
    })
  })
})
