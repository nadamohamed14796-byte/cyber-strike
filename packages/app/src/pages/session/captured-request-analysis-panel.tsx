import { createEffect, createMemo, Show } from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import { useSync } from "@/context/sync"

const EXTENSION_TASKS_TITLES = new Set([
  "Extension Agent Tasks",
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

  const brokerSession = createMemo(() =>
    (sync.data.session ?? []).find(
      (item) => item.parentID === parentID() && EXTENSION_TASKS_TITLES.has(item.title ?? ""),
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

  // Each extension turn is one task, regardless of whether it originated as HTTP or plain text.
  const taskCount = createMemo(() => brokerMessages().filter((message) => message.role === "user").length)

  function enterExtensionTasks() {
    const childID = brokerSession()?.id
    if (!childID) return
    navigate(`/${params.dir}/session/${childID}`)
  }

  return (
    <Show when={brokerSession()}>
      <section
        aria-label="Extension Agent tasks"
        class="absolute right-4 bottom-32 z-[80] w-[min(390px,calc(100%_-_32px))] rounded-xl border border-border-base bg-background-base p-3 shadow-xl"
      >
        <div class="flex items-center justify-between gap-3">
          <div class="flex min-w-0 items-center gap-2">
            <h2 class="shrink-0 text-13-semibold text-text-strong">Extension Agent Tasks</h2>
            <span
              aria-label={`${taskCount()} extension tasks`}
              class="inline-flex min-w-6 items-center justify-center rounded bg-surface-base px-2 py-1 text-11-semibold tabular-nums text-text-weak"
            >
              {taskCount()}
            </span>
          </div>

          <button
            type="button"
            onClick={enterExtensionTasks}
            class="shrink-0 rounded-md border border-border-base bg-surface-raised-base px-3 py-1.5 text-12-semibold text-text-base hover:bg-surface-base"
          >
            Enter
          </button>
        </div>
      </section>
    </Show>
  )
}
