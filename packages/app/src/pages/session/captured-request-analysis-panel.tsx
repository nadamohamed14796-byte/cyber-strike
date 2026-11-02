import { createEffect, createMemo, createSignal, Show } from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import { useSync } from "@/context/sync"

const PROXY_BROKER_TITLES = new Set([
  "Agent Proxy",
  "Extension Proxy Broker (@proxy-agent subagent)",
])

/**
 * Main-session entry point for the dedicated Extension Agent child session.
 * The Main view exposes queue position numbers only; request details and
 * analysis remain inside the child session.
 */
export function CapturedRequestAnalysisPanel() {
  const params = useParams()
  const navigate = useNavigate()
  const sync = useSync()

  const parentID = () => params.id ?? ""
  const [requestsReady, setRequestsReady] = createSignal(false)

  createEffect(() => {
    const sessionID = parentID()
    if (!sessionID) return
    void sync.session.request(sessionID).then(() => setRequestsReady(true)).catch(() => setRequestsReady(true))
  })

  const brokerSession = createMemo(() =>
    (sync.data.session ?? []).find(
      (item) => item.parentID === parentID() && PROXY_BROKER_TITLES.has(item.title ?? ""),
    ),
  )

  // Keep the child transcript synced even when it is not the active route.
  // This lets text-only extension tasks trigger the same auto-open behavior as
  // captured HTTP requests, without requiring a request inventory row.
  let syncedBrokerID: string | undefined
  createEffect(() => {
    const id = brokerSession()?.id
    if (!id || id === syncedBrokerID) return
    syncedBrokerID = id
    void sync.session.sync(id).catch(() => {})
  })

  const brokerMessages = createMemo(() => {
    const id = brokerSession()?.id
    return id ? (sync.data.message[id] ?? []) : []
  })
  const latestBrokerUserMessage = createMemo(() =>
    [...brokerMessages()].reverse().find((message) => message.role === "user"),
  )
  const mountedAt = Date.now()
  let lastOpenedMessageID: string | undefined
  createEffect(() => {
    const message = latestBrokerUserMessage()
    const id = brokerSession()?.id
    if (!id || !message || message.time.created < mountedAt || message.id === lastOpenedMessageID) return
    lastOpenedMessageID = message.id
    navigate(`/${params.dir}/session/${id}`)
  })

  // Cumulative number of all requests received by this parent session.
  const requestCount = createMemo(() => sync.data.request[parentID()]?.length ?? 0)

  // New extension captures/tasks should open the Agent execution view automatically.
  // Keep the initial count as a baseline so reopening an old session does not
  // unexpectedly navigate away. The broker may appear in sync data slightly
  // after the request row, so retain the pending navigation until it is ready.
  let initialized = false
  let previousRequestCount = 0
  let previousBrokerID: string | undefined
  let pendingAgentNavigation = false

  createEffect(() => {
    const ready = requestsReady()
    const count = requestCount()
    const broker = brokerSession()

    if (!ready) return

    if (!initialized) {
      initialized = true
      previousRequestCount = count
      previousBrokerID = broker?.id
      return
    }

    if (count > previousRequestCount) pendingAgentNavigation = true
    if (broker?.id && broker.id !== previousBrokerID) pendingAgentNavigation = true
    previousRequestCount = count
    previousBrokerID = broker?.id

    if (!pendingAgentNavigation || !broker?.id) return
    pendingAgentNavigation = false
    navigate(`/${params.dir}/session/${broker.id}`)
  })

  function enterAgentProxy() {
    const childID = brokerSession()?.id
    if (!childID) return
    navigate(`/${params.dir}/session/${childID}`)
  }

  return (
    <Show when={brokerSession()}>
      <section
        aria-label="Extension Agent queue"
        class="absolute right-4 bottom-32 z-[80] w-[min(390px,calc(100%_-_32px))] rounded-xl border border-border-base bg-background-base p-3 shadow-xl"
      >
        <div class="flex items-center justify-between gap-3">
          <div class="flex min-w-0 items-center gap-2">
            <h2 class="shrink-0 text-13-semibold text-text-strong">Extension Agent</h2>
            <span
              aria-label={`${requestCount()} captured requests`}
              class="inline-flex min-w-6 items-center justify-center rounded bg-surface-base px-2 py-1 text-11-semibold tabular-nums text-text-weak"
            >
              {requestCount()}
            </span>
          </div>

          <button
            type="button"
            onClick={enterAgentProxy}
            class="shrink-0 rounded-md border border-border-base bg-surface-raised-base px-3 py-1.5 text-12-semibold text-text-base hover:bg-surface-base"
          >
            Enter
          </button>
        </div>
      </section>
    </Show>
  )
}
