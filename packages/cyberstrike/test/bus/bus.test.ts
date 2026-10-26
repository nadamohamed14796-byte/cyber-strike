import { describe, expect, test } from "bun:test"
import path from "path"
import z from "zod"
import { Bus } from "../../src/bus"
import { BusEvent } from "../../src/bus/bus-event"
import { GlobalBus } from "../../src/bus/global"
import { Instance } from "../../src/project/instance"

const projectRoot = path.join(__dirname, "../..")

describe("Bus.publish", () => {
  test("a failing local subscriber does not block other subscribers or global delivery", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const event = BusEvent.define("test.bus.delivery", z.object({ value: z.string() }))
        const localCalls: string[] = []
        const globalCalls: unknown[] = []
        const globalListener = (input: { payload: { type: string } }) => {
          if (input.payload.type === event.type) globalCalls.push(input)
        }

        const unsubscribeFailing = Bus.subscribe(event, () => {
          throw new Error("test subscriber failure")
        })
        const unsubscribeHealthy = Bus.subscribe(event, () => {
          localCalls.push("healthy")
        })
        GlobalBus.on("event", globalListener)

        try {
          await Bus.publish(event, { value: "ok" })
        } finally {
          unsubscribeFailing()
          unsubscribeHealthy()
          GlobalBus.off("event", globalListener)
        }

        expect(localCalls).toEqual(["healthy"])
        expect(globalCalls).toHaveLength(1)
      },
    })
  })
})
