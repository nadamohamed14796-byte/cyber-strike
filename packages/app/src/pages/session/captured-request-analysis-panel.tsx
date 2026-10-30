import { createEffect, createMemo, For, Show } from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import { useSync } from "@/context/sync"

type CapturedRequestRow = {
  id: string
  status?: "queued" | "processing" | "processed" | "failed" | string
}

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

  createEffect(() => {
    const sessionID = parentID()
    if (!sessionID) return
    void sync.session.request(sessionID).catch(() => {})
  })

  const brokerSession = createMemo(() =>
    (sync.data.session ?? []).find(
      (item) => item.parentID === parentID() && PROXY_BROKER_TITLES.has(item.title ?? ""),
    ),
  )

  const requests = createMemo(() =>
    (((sync.data.request[parentID()] ?? []) as unknown as CapturedRequestRow[]).slice()).sort(
      (a, b) => a.id.localeCompare(b.id),
    ),
  )

  // Only active/waiting queue slots are represented in Main. Completed and
  // failed request details stay in the Agent Proxy child session history.
  const queueRequests = createMemo(() =>
    requests().filter((item) => item.status === "processing" || item.status === "queued"),
  )

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
            <div aria-label="Queue positions" class="flex min-w-0 flex-wrap items-center gap-1">
              <For each={queueRequests()}>
                {(_, index) => (
                  <span class="inline-flex size-6 items-center justify-center rounded bg-surface-base text-10-semibold tabular-nums text-text-weak">
                    {index() + 1}
                  </span>
                )}
              </For>
            </div>
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
