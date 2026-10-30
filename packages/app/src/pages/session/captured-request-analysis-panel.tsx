import { createEffect, createMemo, createSignal, For, on, onCleanup, Show } from "solid-js"
import { useNavigate, useParams } from "@solidjs/router"
import { SessionTurn } from "@cyberstrike-io/ui/session-turn"
import { Identifier } from "@/utils/id"
import { useSDK } from "@/context/sdk"
import { useSync } from "@/context/sync"

type AnalysisStatus = "analyzing" | "processed" | "failed"

type RequestAnalysis = {
  requestID: string
  analysisSessionID?: string
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
  response_headers?: Record<string, string>
  processed_response?: string
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
  const [activeRequestID, setActiveRequestID] = createSignal<string>()
  const [request, setRequest] = createSignal<RequestRow>()
  const [expanded, setExpanded] = createSignal<Record<string, boolean>>({})
  const [requestLoadError, setRequestLoadError] = createSignal("")
  const [retryingRequest, setRetryingRequest] = createSignal(false)
  const [retryNotice, setRetryNotice] = createSignal("")
  const [retryError, setRetryError] = createSignal("")
  const [replyDraft, setReplyDraft] = createSignal("")
  const [replySending, setReplySending] = createSignal(false)
  const [replyError, setReplyError] = createSignal("")
  const [replyNotice, setReplyNotice] = createSignal("")
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
  const latest = createMemo(() => analyses().at(-1))
  const selected = createMemo(
    () => analyses().find((item) => item.requestID === activeRequestID()) ?? latest(),
  )
  const analysisSessionID = () => selected()?.analysisSessionID
  const childMessages = createMemo(() => {
    const id = analysisSessionID()
    return id ? (sync.data.message[id] ?? []) : []
  })
  const childUserMessages = createMemo(() => childMessages().filter((message) => message.role === "user"))
  const childBusy = createMemo(() => {
    const id = analysisSessionID()
    return !!id && (sync.data.session_status[id]?.type ?? "idle") !== "idle"
  })
  const replyDisabled = createMemo(
    () => !analysisSessionID() || childUserMessages().length === 0 || childBusy() || replySending(),
  )
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
    const item = latest()
    if (!sessionID || !item) return
    const key = sessionID + ":" + item.requestID
    if (key === seenKey) return
    seenKey = key
    setActiveRequestID(item.requestID)
    if (item.status === "analyzing") setOpen(true)
  })

  createEffect(
    on([open, analysisSessionID], ([visible, id]) => {
      if (!visible || !id) return
      void sync.session.sync(id).catch(() => {})
    }),
  )

  createEffect(
    on(
      () => selected()?.requestID,
      () => {
        // Never carry a draft from one captured request into another request's session.
        setReplyDraft("")
        setReplyError("")
        setReplyNotice("")
      },
    ),
  )

  createEffect(
    on([open, parentID, () => selected()?.requestID], ([visible, sessionID, requestID]) => {
      if (!visible || !sessionID || !requestID) return
      const generation = ++requestLoadGeneration
      setRequest(undefined)
      setRequestLoadError("")
      setRetryNotice("")
      setRetryError("")
      // Keep the request row in the shared sync store. request.updated events
      // refresh its status from queued → processing → processed/failed, so the
      // panel does not stay stuck on the optimistic "queued" state after retry.
      void sync.session.request(sessionID)?.then(() => {
        if (generation !== requestLoadGeneration) return
        const rows = (sync.data.request[sessionID] ?? []) as unknown as RequestRow[]
        const row = rows.find((item) => item.id === requestID)
        if (row) setRequest(row)
        else setRequestLoadError("Captured request is not present in the current session.")
      }).catch((error: unknown) => {
        if (generation !== requestLoadGeneration) return
        setRequestLoadError(error instanceof Error ? error.message : String(error))
      })
      onCleanup(() => {
        requestLoadGeneration += 1
      })
    }),
  )

  // Request rows are refreshed by request.updated events. Re-read the
  // selected row whenever the shared request inventory changes.
  createEffect(() => {
    if (!open()) return
    const sessionID = parentID()
    const requestID = selected()?.requestID
    if (!sessionID || !requestID) return
    const rows = (sync.data.request[sessionID] ?? []) as unknown as RequestRow[]
    const row = rows.find((item) => item.id === requestID)
    if (row) setRequest(row)
  })

  const displayStatus = (): AnalysisStatus => {
    const persistedStatus = request()?.id === selected()?.requestID ? request()?.status : undefined
    if (persistedStatus === "queued" || persistedStatus === "processing") return "analyzing"
    if (persistedStatus === "processed" || persistedStatus === "failed") return persistedStatus
    return selected()?.status ?? "analyzing"
  }

  const statusLabel = () => {
    const status = displayStatus()
    if (status === "processed") return "COMPLETE"
    if (status === "failed") return "FAILED"
    return "ANALYZING"
  }

  async function sendReply() {
    const text = replyDraft().trim()
    const sessionID = analysisSessionID()
    const requestID = selected()?.requestID
    const lastUserMessage = childUserMessages().at(-1)
    if (!text || !sessionID || !requestID || !lastUserMessage || replySending() || childBusy()) return

    const submittedDraft = replyDraft()
    const brokerFollowUp = [
      "## Current request",
      `- request_id: ${requestID}`,
      "- source: Extension analysis panel",
      "",
      text,
    ].join("\\n")
    setReplyDraft("")
    setReplyError("")
    setReplyNotice("")
    setReplySending(true)
    try {
      const result = await sdk.client.session.promptAsync({
        sessionID,
        messageID: Identifier.ascending("message"),
        agent: "proxy-agent",
        model: lastUserMessage.model,
        variant: lastUserMessage.variant,
        parts: [
          {
            id: Identifier.ascending("part"),
            type: "text",
            text: brokerFollowUp,
          },
        ],
      })
      if (result.error) throw new Error(JSON.stringify(result.error))
      await sync.session.sync(sessionID).catch(() => {})
      if (selected()?.requestID === requestID) {
        setReplyNotice("Message sent to the shared Extension Proxy Broker.")
      }
    } catch (error) {
      if (selected()?.requestID === requestID) {
        setReplyDraft(submittedDraft)
        setReplyError(error instanceof Error ? error.message : String(error))
      }
    } finally {
      setReplySending(false)
    }
  }

  return (
    <>
      <Show when={selected() && !open()}>
        <button
          type="button"
          onClick={() => {
            setActiveRequestID(latest()?.requestID)
            setOpen(true)
          }}
          class="absolute right-4 bottom-32 z-[80] rounded-lg border border-border-base bg-background-base px-4 py-2 text-12-medium text-text-base shadow-xl hover:bg-surface-raised-base"
        >
          {displayStatus() === "analyzing" ? "View live request analysis" : "View last request analysis"}
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
                    "bg-icon-success-base": displayStatus() === "processed",
                    "bg-icon-danger-base": displayStatus() === "failed",
                    "bg-icon-warning-base": displayStatus() === "analyzing",
                  }}
                />
                <h2 class="text-14-semibold text-text-strong">Captured request analysis</h2>
                <span class="rounded px-2 py-0.5 text-10-semibold bg-surface-base text-text-weak">{statusLabel()}</span>
              </div>
              <p class="mt-1 truncate text-12-medium text-text-base">{selected()?.method} {selected()?.url}</p>
              <p class="mt-1 text-10-regular text-text-weaker">Request ID: {selected()?.requestID}</p>
            </div>
            <div class="flex shrink-0 items-center gap-2">
              <Show when={selected()?.status === "failed" && request()?.status === "failed"}>
                <button
                  type="button"
                  disabled={retryingRequest()}
                  class="rounded-md border border-border-base px-2 py-1 text-11-medium hover:bg-surface-raised-base disabled:cursor-not-allowed disabled:opacity-50"
                  onClick={async () => {
                    const sessionID = parentID()
                    const requestID = selected()?.requestID
                    if (!sessionID || !requestID || retryingRequest()) return
                    setRetryingRequest(true)
                    setRetryNotice("")
                    setRetryError("")
                    try {
                      const result = await sdk.client.session.requestRetry({ sessionID, requestID })
                      if (result.error) {
                        throw new Error(JSON.stringify(result.error))
                      }
                      setRequest((previous) => previous ? { ...previous, status: "queued" } : previous)
                      setRetryNotice("Retry queued. Analysis will restart when this request reaches the front of the queue.")
                    } catch (error) {
                      setRetryError(error instanceof Error ? error.message : String(error))
                    } finally {
                      setRetryingRequest(false)
                    }
                  }}
                >
                  {retryingRequest() ? "Queueing retry…" : "Retry analysis"}
                </button>
              </Show>
              <button
                type="button"
                disabled={!analysisSessionID()}
                class="rounded-md border border-border-base px-2 py-1 text-11-medium hover:bg-surface-raised-base disabled:cursor-not-allowed disabled:opacity-50"
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

          <div class="flex shrink-0 gap-2 overflow-x-auto border-b border-border-weak-base px-3 py-2">
            <For each={analyses().slice().reverse()}>
              {(item) => (
                <button
                  type="button"
                  onClick={() => setActiveRequestID(item.requestID)}
                  class="flex min-w-0 max-w-64 shrink-0 flex-col gap-1 rounded-md border px-3 py-2 text-left"
                  classList={{
                    "border-border-base bg-surface-raised-base": selected()?.requestID === item.requestID,
                    "border-border-weak-base bg-transparent hover:bg-surface-base": selected()?.requestID !== item.requestID,
                  }}
                >
                  <span class="text-10-semibold text-text-weaker">{item.method} · {item.status.toUpperCase()}</span>
                  <span class="max-w-60 truncate text-11-medium text-text-base">{item.url}</span>
                  <span class="text-10-regular text-text-weaker">{item.requestID}</span>
                </button>
              )}
            </For>
          </div>

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
              <details class="mb-3 rounded border border-border-weak-base p-2">
                <summary class="cursor-pointer text-11-medium text-text-base">
                  Response headers ({Object.keys(request()?.response_headers ?? {}).length})
                </summary>
                <Show
                  when={Object.keys(request()?.response_headers ?? {}).length > 0}
                  fallback={<p class="mt-2 text-10-regular text-text-weak">Response headers are unavailable.</p>}
                >
                  <pre class="mt-2 whitespace-pre-wrap break-all text-10-regular text-text-weak">
                    {Object.entries(request()?.response_headers ?? {}).map(([key, value]) => key + ": " + value).join("\n")}
                  </pre>
                </Show>
              </details>
              <details class="mb-3 rounded border border-border-weak-base p-2">
                <summary class="cursor-pointer text-11-medium text-text-base">
                  Captured response body ({request()?.response_size ?? 0} bytes)
                </summary>
                <pre class="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-10-regular text-text-weak">
                  {request()?.processed_response?.slice(0, 12000) || "(empty or unavailable)"}
                </pre>
                <Show when={(request()?.processed_response?.length ?? 0) > 12000}>
                  <p class="mt-2 text-10-regular text-text-weaker">Preview limited to the first 12,000 characters.</p>
                </Show>
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
              <Show when={retryNotice()}>
                <p role="status" class="mb-2 rounded-lg border border-border-weak-base p-2 text-11-regular text-text-base">{retryNotice()}</p>
              </Show>
              <Show when={retryError()}>
                <p role="alert" class="mb-2 rounded-lg border border-border-weak-base p-2 text-11-regular text-icon-danger-base">Could not retry analysis: {retryError()}</p>
              </Show>
              <Show
                when={childUserMessages().length > 0}
                fallback={
                  <div class="rounded-lg border border-border-weak-base p-4 text-12-regular text-text-weak">
                    <Show
                      when={displayStatus() === "failed" && !analysisSessionID()}
                      fallback="The analysis session has started. Waiting for the first visible agent step…"
                    >
                      The agent session could not be created. This request was marked failed before analysis tools started.
                    </Show>
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
              <Show when={displayStatus() === "processed" || displayStatus() === "failed"}>
                <div class="mt-3 rounded-lg border border-border-weak-base p-3 text-12-regular text-text-base">
                  Analysis {displayStatus() === "processed" ? "completed" : "failed"}.
                  <Show when={displayStatus() === "failed"}>
                    <p class="mt-1 text-text-weak">
                      {analysisSessionID()
                        ? "You can continue in the shared Proxy Agent broker session or open it to inspect the final error."
                        : "The agent session could not start; the request was marked failed before tool execution."}
                    </p>
                  </Show>
                </div>
              </Show>
              <Show when={analysisSessionID()}>
                <form
                  class="sticky bottom-0 mt-3 border-t border-border-weak-base bg-background-base pt-3"
                  onSubmit={(event) => {
                    event.preventDefault()
                    void sendReply()
                  }}
                >
                  <label for="proxy-agent-reply" class="mb-1 block text-11-semibold text-text-weak">
                    Continue with Proxy Agent
                  </label>
                  <textarea
                    id="proxy-agent-reply"
                    value={replyDraft()}
                    onInput={(event) => setReplyDraft(event.currentTarget.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault()
                        void sendReply()
                      }
                    }}
                    rows={2}
                    disabled={replyDisabled()}
                    placeholder="Ask about this request or continue a supported investigation…"
                    class="w-full resize-y rounded-lg border border-border-base bg-background-base px-3 py-2 text-12-regular text-text-base outline-none focus:border-border-strong disabled:cursor-not-allowed disabled:opacity-60"
                  />
                  <div class="mt-2 flex items-center justify-between gap-2">
                    <p class="text-10-regular text-text-weaker">
                      This goes to the shared Proxy Agent broker under the active Main Agent; the Main Agent's conversation stays separate.
                    </p>
                    <button
                      type="submit"
                      disabled={!replyDraft().trim() || replyDisabled()}
                      class="shrink-0 rounded-md border border-border-base bg-surface-raised-base px-3 py-1.5 text-11-medium text-text-base hover:bg-surface-base disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {replySending() ? "Sending…" : childBusy() ? "Agent working…" : "Send"}
                    </button>
                  </div>
                  <Show when={replyError()}>
                    <p role="alert" class="mt-2 text-11-regular text-icon-danger-base">
                      Could not message Proxy Agent: {replyError()}
                    </p>
                  </Show>
                  <Show when={replyNotice()}>
                    <p role="status" class="mt-2 text-11-regular text-text-weak">{replyNotice()}</p>
                  </Show>
                </form>
              </Show>
            </main>
          </div>
        </section>
      </Show>
    </>
  )
}
