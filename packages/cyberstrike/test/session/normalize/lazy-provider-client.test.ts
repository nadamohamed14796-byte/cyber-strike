import { expect, test } from "bun:test"
import { createLazyProviderClient } from "../../../src/session/normalize"

test("does not initialize the provider until Tier 3 classification is requested", async () => {
  let creates = 0
  let classifications = 0
  const client = createLazyProviderClient(
    { providerID: "unused-provider", modelID: "unused-model" },
    async () => {
      creates++
      return {
        async classify() {
          classifications++
          return { decisions: [], model: "fixture-model" }
        },
      }
    },
  )

  expect(creates).toBe(0)
  expect(classifications).toBe(0)
  await client.classify({} as any)
  expect(creates).toBe(1)
  expect(classifications).toBe(1)
  await client.classify({} as any)
  expect(creates).toBe(1)
  expect(classifications).toBe(2)
})
