import { Rpc } from "../../src/util/rpc"

// This intentionally awaits after registering the listener. Bun can dispatch
// messages during top-level await, so the handler must already be installed.
Rpc.listen({
  echo: async (input: string) => input,
})
Rpc.emit("worker.ready", { protocol: 1 })

await Bun.sleep(300)
