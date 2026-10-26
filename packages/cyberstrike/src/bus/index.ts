import z from "zod"
import { Log } from "../util/log"
import { Instance } from "../project/instance"
import { BusEvent } from "./bus-event"
import { GlobalBus } from "./global"

export namespace Bus {
  const log = Log.create({ service: "bus" })
  type Subscription = (event: any) => void | Promise<void>

function notify(subscribers: Subscription[], event: any, type: string) {
  const pending: Promise<void>[] = []
  for (const sub of [...subscribers]) {
    try {
      pending.push(
        Promise.resolve(sub(event)).catch((error) => {
          log.error("subscription handler failed", { type, error })
        }),
      )
    } catch (error) {
      // A broken local subscriber must not block other listeners or global delivery.
      log.error("subscription handler failed", { type, error })
    }
  }
  return Promise.all(pending)
}

  export const InstanceDisposed = BusEvent.define(
    "server.instance.disposed",
    z.object({
      directory: z.string(),
    }),
  )

  const state = Instance.state(
    () => {
      const subscriptions = new Map<any, Subscription[]>()

      return {
        subscriptions,
      }
    },
    async (entry) => {
      const wildcard = entry.subscriptions.get("*")
      if (!wildcard) return
      const event = {
        type: InstanceDisposed.type,
        properties: {
          directory: Instance.directory,
        },
      }
      await notify(wildcard, event, InstanceDisposed.type)
    },
  )

  export async function publish<Definition extends BusEvent.Definition>(
    def: Definition,
    properties: z.output<Definition["properties"]>,
  ) {
    const payload = {
      type: def.type,
      properties,
    }
    log.info("publishing", {
      type: def.type,
    })
    const subscribers = [
      ...(state().subscriptions.get(def.type) ?? []),
      ...(state().subscriptions.get("*") ?? []),
    ]
    const pending = notify(subscribers, payload, def.type)
    try {
      GlobalBus.emit("event", {
        directory: Instance.directory,
        payload,
      })
    } catch (error) {
      log.error("global event broadcast failed", { type: def.type, error })
    }
    await pending
  }

  export function subscribe<Definition extends BusEvent.Definition>(
    def: Definition,
    callback: (event: { type: Definition["type"]; properties: z.infer<Definition["properties"]> }) => void,
  ) {
    return raw(def.type, callback)
  }

  export function once<Definition extends BusEvent.Definition>(
    def: Definition,
    callback: (event: {
      type: Definition["type"]
      properties: z.infer<Definition["properties"]>
    }) => "done" | undefined,
  ) {
    const unsub = subscribe(def, (event) => {
      if (callback(event)) unsub()
    })
  }

  export function subscribeAll(callback: (event: any) => void) {
    return raw("*", callback)
  }

  function raw(type: string, callback: (event: any) => void) {
    log.info("subscribing", { type })
    const subscriptions = state().subscriptions
    let match = subscriptions.get(type) ?? []
    match.push(callback)
    subscriptions.set(type, match)

    return () => {
      log.info("unsubscribing", { type })
      const match = subscriptions.get(type)
      if (!match) return
      const index = match.indexOf(callback)
      if (index === -1) return
      match.splice(index, 1)
    }
  }
}
