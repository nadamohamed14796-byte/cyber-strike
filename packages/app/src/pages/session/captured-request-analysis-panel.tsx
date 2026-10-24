import { createEffect, createMemo, createSignal, For, on, onCleanup, Show } from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import { SessionTurn } from "@cyberstrike-io/ui/session-turn"
import { useSDK } from "@/context/sdk"
import { useSync } from "@/context/sync"

type AnalysisStatus = "analyzing" | "processed" | "failed"

type RequestAnalysis = {
  requestID: string
  analysisSessionID: string
  method: string
  url: string
  status: AnalysisStatus
}

type RequestRow = {
  id: string
  method?: string
  origin?: string
  normalized_path?: string
  raw_request?: string
  response_status?: number
  response_content_type?: string
  response_size?: number
  status?: string
}

function parseRequest(raw?: string) {
  if (!raw) return { headers: [] as string[], body: "" }
  const normalized = raw.replace(/\r\n/g, "\n")
  const split = normalized.indexOf("\n\n")
  const head = split === -1 ? normalized : normalized.slice(0, split)
  const body = split === -1 ? "" : normalized.slice(split + 2)
  return { headers: head.split("\n").slice(1).filter(Boolean), body }
}

export function CapturedRequestAnalysisPanel() {
  const params = useParams()
  const navigate = useNavigate()
  const sdk = useSDK()
  const sync = useSync()
  const [open, setOpen] = createSignal(false)
  const [request, setRequest] = createSignal<RequestRow>()
  const [expanded, setExpanded] = createSignal<Record<string, boolean>>({})
  const [requestLoadError, setRequestLoadError] = createSignal("")
  let seenKey: string | undefined
  let requestLoadGeneration = 0

  const parentID = () => params.id ?? ""
  const analyses = createMemo(() => {
    const sessionID = parentID()
    if (!sessionID) return []
    const messages = sync.data.message[sessionID] ?? []
    const rows: Array<RequestAnalysis & { messageID: string; text: string }> = []
    for (const message of messages) {
      for (const part of sync.data.part[message.id] ?? []) {
        if (part.type !== "text") continue
        const metadata = (part as unknown as {
          metadata?: {
            kind?: string
            requestAnalysis?: RequestAnalysis
          }
        }).metadata
        const value = metadata?.requestAnalysis
        if (
          metadata?.kind !== "ingest-summary" ||
          !value?.requestID ||
          !value.analysisSessionID ||
          !value.method ||
          !value.url
        ) continue
        rows.push({
          ...value,
          messageID: message.id,
          text: part.text,
        })
      }
    }
    return rows.sort((a, b) => a.messageID.localeCompare(b.messageID))
  })
  const selected = createMemo(() => analyses().at(-1))
  const analysisSessionID = () => selected()?.analysisSessionID
  const childMessages = createMemo(() => {
    const id = analysisSessionID()
    return id ? (sync.data.message[id] ?? []) : []
  })
  const childUserMessages = createMemo(() => childMessages().filter((message) => message.role === "user"))
  const requestParts = createMemo(() => parseRequest(request()?.raw_request))
  const queryParams = createMemo(() => {
    try {
      return [...new URL(selected()?.url ?? "").searchParams.entries()]
    } catch {
      return []
    }
  })

  // Open automatically only when a new request actually starts. Queued requests
  // never create an analysis notice and therefore never open this panel.
  createEffect(() => {
    const sessionID = parentID()
    const item = selected()
    if (!sessionID || !item) return
    const key = sessionID + ":" + item.requestID
    if (key === seenKey) return
    seenKey = key
    if (item.status === "analyzing") setOpen(true)
  })

  createEffect(
    on([open, analysisSessionID], ([visible, id]) => {
      if (!visible || !id) return
      void sync.session.sync(id).catch(() => {})
    }),
  )

  createEffect(
    on([open, parentID, () => selected()?.requestID], ([visible, sessionID, requestID]) => {
      if (!visible || !sessionID || !requestID) return
      const generation = ++requestLoadGeneration
      setRequest(undefined)
      setRequestLoadError("")
      void sdk.client.session.request({ sessionID }).then((result) => {
        if (generation !== requestLoadGeneration) return
        const rows = (result.data ?? []) as unknown as RequestRow[]
        setRequest(rows.find((item) => item.id === requestID))
      }).catch((error: unknown) => {
        if (generation !== requestLoadGeneration) return
        setRequestLoadError(error instanceof Error ? error.message : String(error))
      })
      onCleanup(() => {
        requestLoadGeneration += 1
      })
    }),
  )

  const statusLabel = () => {
    const status = selected()?.status
    if (status === "processed") return "COMPLETE"
    if (status === "failed") return "FAILED"
    return "ANALYZING"
  }

  return (
    <>
      <Show when={selected() && !open()}>
        <button
          type="button"
          onClick={() => setOpen(true)}
          class="absolute right-4 bottom-32 z-[80] rounded-lg border border-border-base bg-background-base px-4 py-2 text-12-medium text-text-base shadow-xl hover:bg-surface-raised-base"
        >
          {selected()?.status === "analyzing" ? "View live request analysis" : "View last request analysis"}
        </button>
      </Show>
      <Show when={selected() && open()}>
        <section
          aria-label="Captured request analysis"
          class="absolute z-[80] right-3 top-14 bottom-32 w-[min(880px,calc(100%_-_24px))] min-h-[280px] overflow-hidden rounded-xl border border-border-base bg-background-base shadow-2xl flex flex-col"
        >
          <header class="flex items-start justify-between gap-3 border-b border-border-weak-base bg-background-stronger px-4 py-3">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span
                  class="inline-block size-2 rounded-full"
                  classList={{
                    "bg-icon-success-base": selected()?.status === "processed",
                    "bg-icon-danger-base": selected()?.status === "failed",
                    "bg-icon-warning-base": selected()?.status === "analyzing",
                  }}
                />
                <h2 class="text-14-semibold text-text-strong">Captured request analysis</h2>
                <span class="rounded px-2 py-0.5 text-10-semibold bg-surface-base text-text-weak">{statusLabel()}</span>
              </div>
              <p class="mt-1 truncate text-12-medium text-text-base">{selected()?.method} {selected()?.url}</p>
              <p class="mt-1 text-10-regular text-text-weaker">Request ID: {selected()?.requestID}</p>
            </div>
            <div class="flex shrink-0 items-center gap-2">
              <button
                type="button"
                class="rounded-md border border-border-base px-2 py-1 text-11-medium hover:bg-surface-raised-base"
                onClick={() => {
                  const id = analysisSessionID()
                  if (!id) return
                  navigate(`/${params.dir}/session/${id}`)
                }}
              >
                Open full session
              </button>
              <button
                type="button"
                aria-label="Close request analysis"
                class="size-7 rounded-md text-16-medium hover:bg-surface-raised-base"
                onClick={() => setOpen(false)}
              >×</button>
            </div>
          </header>

          <div class="grid min-h-0 flex-1 grid-cols-1 md:grid-cols-[minmax(240px,0.8fr)_minmax(0,1.7fr)]">
            <aside class="min-h-0 overflow-y-auto border-b border-border-weak-base p-3 md:border-b-0 md:border-r">
              <h3 class="mb-2 text-11-semibold uppercase tracking-wide text-text-weaker">Request details</h3>
              <div class="mb-3 rounded-lg border border-border-weak-base p-2">
                <div class="flex items-center justify-between gap-2">
                  <span class="text-11-medium text-text-weaker">Method</span>
                  <span class="text-12-semibold text-text-base">{request()?.method ?? selected()?.method}</span>
                </div>
                <Show when={request()?.response_status !== undefined}>
                  <div class="mt-1 flex items-center justify-between gap-2">
                    <span class="text-11-medium text-text-weaker">Response</span>
                    <span class="text-12-medium text-text-base">{request()?.response_status}</span>
                  </div>
                </Show>
                <Show when={request()?.response_content_type}>
                  <div class="mt-1 break-all text-11-regular text-text-weak">{request()?.response_content_type}</div>
                </Show>
              </div>
              <div class="mb-3">
                <div class="mb-1 text-11-medium text-text-weaker">URL</div>
                <pre class="whitespace-pre-wrap break-all rounded bg-surface-base p-2 text-11-regular text-text-base">{selected()?.url}</pre>
              </div>
              <div class="mb-3">
                <div class="mb-1 text-11-medium text-text-weaker">Query parameters ({queryParams().length})</div>
                <Show when={queryParams().length > 0} fallback={<p class="text-11-regular text-text-weak">No query parameters.</p>}>
                  <div class="flex flex-col gap-1">
                    <For each={queryParams()}>
                      {([key, value]) => (
                        <div class="grid grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] gap-2 rounded bg-surface-base px-2 py-1">
                          <span class="break-all text-11-medium text-text-weak">{key}</span>
                          <span class="break-all text-11-regular text-text-base">{value || "(empty)"}</span>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
              </div>
              <details class="mb-3 rounded border border-border-weak-base p-2">
                <summary class="cursor-pointer text-11-medium text-text-base">Headers ({requestParts().headers.length})</summary>
                <Show when={requestParts().headers.length > 0} fallback={<p class="mt-2 text-11-regular text-text-weak">Raw headers are unavailable.</p>}>
                  <pre class="mt-2 whitespace-pre-wrap break-all text-10-regular text-text-weak">{requestParts().headers.join("\n")}</pre>
                </Show>
              </details>
              <details class="mb-3 rounded border border-border-weak-base p-2">
                <summary class="cursor-pointer text-11-medium text-text-base">Request body</summary>
                <pre class="mt-2 whitespace-pre-wrap break-all text-10-regular text-text-weak">{requestParts().body || "(empty or unavailable)"}</pre>
              </details>
              <Show when={requestLoadError()}>
                <p class="text-11-regular text-icon-danger-base">Could not load raw request: {requestLoadError()}</p>
              </Show>
              <Show when={!request() && !requestLoadError()}>
                <p class="text-11-regular text-text-weaker">Loading captured headers and body…</p>
              </Show>
            </aside>

            <main class="min-h-0 overflow-y-auto p-3">
              <div class="mb-2 flex items-center justify-between gap-2">
                <h3 class="text-11-semibold uppercase tracking-wide text-text-weaker">Live agent activity</h3>
                <span class="text-10-regular text-text-weaker">{childUserMessages().length} turn(s)</span>
              </div>
              <Show
                when={childUserMessages().length > 0}
                fallback={
                  <div class="rounded-lg border border-border-weak-base p-4 text-12-regular text-text-weak">
                    The analysis session has started. Waiting for the first visible agent step…
                  </div>
                }
              >
                <div class="flex flex-col gap-3">
                  <For each={childUserMessages()}>
                    {(message) => (
                      <div class="min-w-0 rounded-lg border border-border-weak-base py-2">
                        <SessionTurn
                          sessionID={analysisSessionID()!}
                          messageID={message.id}
                          lastUserMessageID={childUserMessages().at(-1)?.id}
                          stepsExpanded={expanded()[message.id] ?? true}
                          onStepsExpandedToggle={() =>
                            setExpanded((previous) => ({
                              ...previous,
                              [message.id]: !(previous[message.id] ?? true),
                            }))
                          }
                          classes={{
                            root: "min-w-0 w-full relative",
                            content: "flex flex-col justify-between !overflow-visible",
                            container: "w-full px-2",
                          }}
                        />
                      </div>
                    )}
                  </For>
                </div>
              </Show>
              <Show when={selected()?.status === "processed" || selected()?.status === "failed"}>
                <div class="mt-3 rounded-lg border border-border-weak-base p-3 text-12-regular text-text-base">
                  Analysis {selected()?.status === "processed" ? "completed" : "failed"}.
                  <Show when={selected()?.status === "failed"}>
                    <p class="mt-1 text-text-weak">Open the full session to inspect the final error or incomplete step.</p>
                  </Show>
                </div>
              </Show>
            </main>
          </div>
        </section>
      </Show>
    </>
  )
}
