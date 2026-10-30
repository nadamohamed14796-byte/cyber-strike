import { createEffect, createMemo, Show } from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import { useSync } from "@/context/sync"

type CapturedRequestRow = {
  id: string
  method?: string
  origin?: string
  normalized_path?: string
  status?: "queued" | "processing" | "processed" | "failed" | string
  time?: {
    created?: number
    updated?: number
  }
}

const PROXY_BROKER_TITLES = new Set([
  "Agent Proxy",
  "Extension Proxy Broker (@proxy-agent subagent)",
])

/**
 * Small entry point from the Main session into the Extension's dedicated
 * Agent Proxy session. Queue state comes from Request rows, not chat messages.
 */
export function CapturedRequestAnalysisPanel() {
  const params = useParams()
  const navigate = useNavigate()
  const sync = useSync()

  const parentID = () => params.id ?? ""

  createEffect(() => {
    const sessionID = parentID()
    if (!sessionID) return
    // Fetch once when this parent session is opened. Subsequent request.updated
    // events keep the shared request inventory current as captures arrive.
    void sync.session.request(sessionID).catch(() => {})
  })

  const brokerSession = createMemo(() =>
    (sync.data.session ?? []).find(
      (item) => item.parentID === parentID() && PROXY_BROKER_TITLES.has(item.title ?? ""),
    ),
  )

  const requests = createMemo(() =>
    // Request IDs are assigned at intake, before normalization can finish.
    // Sorting by created time would let a slower earlier capture appear after
    // a later one, so keep the durable intake-ID order used by the FIFO queue.
    (((sync.data.request[parentID()] ?? []) as unknown as CapturedRequestRow[]).slice()).sort(
      (a, b) => a.id.localeCompare(b.id),
    ),
  )

  const activeRequest = createMemo(() => requests().find((item) => item.status === "processing"))
  const nextRequest = createMemo(
    () => activeRequest() ?? requests().find((item) => item.status === "queued"),
  )
  const nextRequestNumber = createMemo(() => {
    const current = nextRequest()
    if (!current) return 0
    return requests().findIndex((item) => item.id === current.id) + 1
  })
  const queuedCount = createMemo(() => requests().filter((item) => item.status === "queued").length)
  const processingCount = createMemo(() => requests().filter((item) => item.status === "processing").length)
  const processedCount = createMemo(() => requests().filter((item) => item.status === "processed").length)
  const failedCount = createMemo(() => requests().filter((item) => item.status === "failed").length)

  const currentRequestLabel = createMemo(() => {
    const current = nextRequest()
    if (!current) return ""
    return `${current.method ?? "HTTP"} ${current.origin ?? ""}${current.normalized_path ?? ""}`.trim()
  })

  function enterAgentProxy() {
    const childID = brokerSession()?.id
    if (!childID) return
    navigate(`/${params.dir}/session/${childID}`)
  }

  return (
    <Show when={brokerSession() && requests().length > 0}>
      <section
        aria-label="Extension Agent Proxy"
        class="absolute right-4 bottom-32 z-[80] w-[min(390px,calc(100%_-_32px))] rounded-xl border border-border-base bg-background-base p-3 shadow-xl"
      >
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <span
                class="inline-block size-2 shrink-0 rounded-full"
                classList={{
                  "bg-icon-warning-base": processingCount() > 0 || queuedCount() > 0,
                  "bg-icon-success-base": processingCount() === 0 && queuedCount() === 0 && failedCount() === 0,
                  "bg-icon-danger-base": processingCount() === 0 && queuedCount() === 0 && failedCount() > 0,
                }}
              />
              <h2 class="text-13-semibold text-text-strong">Extension Agent</h2>
              <span class="rounded bg-surface-base px-2 py-0.5 text-10-semibold text-text-weak">
                {requests().length} request(s)
              </span>
            </div>

            <Show
              when={nextRequest()}
              fallback={
                <p class="mt-1 text-11-regular text-text-weak">
                  Queue complete. {processedCount()} analyzed · {failedCount()} failed.
                </p>
              }
            >
              <p class="mt-1 text-12-medium text-text-base">
                {activeRequest()
                  ? `Analyzing request #${nextRequestNumber()} of ${requests().length}`
                  : `Next request #${nextRequestNumber()} is queued`}
              </p>
              <p class="mt-1 truncate text-11-regular text-text-weak" title={currentRequestLabel()}>
                {currentRequestLabel()}
              </p>
            </Show>

            <p class="mt-2 text-10-regular text-text-weaker">
              {queuedCount()} queued · {processingCount()} analyzing · {processedCount()} done · {failedCount()} failed
            </p>
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
