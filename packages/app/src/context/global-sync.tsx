import {
  type Config,
  type Path,
  type Project,
  type ProviderAuthResponse,
  type ProviderListResponse,
  createCyberstrikeClient,
} from "@cyberstrike-io/sdk/v2/client"
import { createStore, produce, reconcile, type SetStoreFunction, type Store } from "solid-js/store"
import { useGlobalSDK } from "./global-sdk"
import type { InitError } from "../pages/error"
import {
  createContext,
  createEffect,
  untrack,
  getOwner,
  useContext,
  onCleanup,
  onMount,
  type ParentProps,
  Switch,
  Match,
} from "solid-js"
import { showToast } from "@cyberstrike-io/ui/toast"
import { getFilename } from "@cyberstrike-io/util/path"
import { usePlatform } from "./platform"
import { useLanguage } from "@/context/language"
import { Persist, persisted } from "@/utils/persist"
import { createRefreshQueue } from "./global-sync/queue"
import { createChildStoreManager } from "./global-sync/child-store"
import { trimSessions } from "./global-sync/session-trim"
import { estimateRootSessionTotal, loadRootSessionsWithFallback } from "./global-sync/session-load"
import { applyDirectoryEvent, applyGlobalEvent } from "./global-sync/event-reducer"
import { bootstrapDirectory, bootstrapGlobal } from "./global-sync/bootstrap"
import { sanitizeProject } from "./global-sync/utils"
import type { ProjectMeta, State } from "./global-sync/types"
import { SESSION_RECENT_LIMIT } from "./global-sync/types"

type GlobalStore = {
  ready: boolean
  error?: InitError
  path: Path
  project: Project[]
  provider: ProviderListResponse
  provider_auth: ProviderAuthResponse
  config: Config
  reload: undefined | "pending" | "complete"
}

function errorMessage(error: unknown) {
  if (error instanceof Error && error.message) return error.message
  if (typeof error === "string" && error) return error
  return "Unknown error"
}

function setDevStats(value: {
  activeDirectoryStores: number
  evictions: number
  loadSessionsFullFetchFallback: number
}) {
  ;(globalThis as { __CYBERSTRIKE_GLOBAL_SYNC_STATS?: typeof value }).__CYBERSTRIKE_GLOBAL_SYNC_STATS = value
}

function createGlobalSync() {
  const globalSDK = useGlobalSDK()
  const platform = usePlatform()
  const language = useLanguage()
  const owner = getOwner()
  if (!owner) throw new Error("GlobalSync must be created within owner")

  const stats = {
    evictions: 0,
    loadSessionsFallback: 0,
  }

  const sdkCache = new Map<string, ReturnType<typeof createCyberstrikeClient>>()
  const booting = new Map<string, Promise<void>>()
  const sessionLoads = new Map<string, Promise<void>>()
  const sessionMeta = new Map<string, { limit: number }>()
  const messageRepairs = new Map<
    string,
    { dirty: boolean; cancelled: boolean; missingParts: Set<string> }
  >()
  const repairKey = (directory: string, sessionID: string, messageID: string) =>
    [directory, sessionID, messageID].join("\0")

  const [projectCache, setProjectCache, , projectCacheReady] = persisted(
    Persist.global("globalSync.project", ["globalSync.project.v1"]),
    createStore({ value: [] as Project[] }),
  )

  const [globalStore, setGlobalStore] = createStore<GlobalStore>({
    ready: false,
    path: { state: "", config: "", worktree: "", directory: "", home: "" },
    project: projectCache.value,
    provider: { all: [], connected: [], default: {} },
    provider_auth: {},
    config: {},
    reload: undefined,
  })

  const updateStats = (activeDirectoryStores: number) => {
    if (!import.meta.env.DEV) return
    setDevStats({
      activeDirectoryStores,
      evictions: stats.evictions,
      loadSessionsFullFetchFallback: stats.loadSessionsFallback,
    })
  }

  const paused = () => untrack(() => globalStore.reload) !== undefined

  const queue = createRefreshQueue({
    paused,
    bootstrap,
    bootstrapInstance,
  })

  const children = createChildStoreManager({
    owner,
    markStats: updateStats,
    incrementEvictions: () => {
      stats.evictions += 1
      updateStats(Object.keys(children.children).length)
    },
    isBooting: (directory) => booting.has(directory),
    isLoadingSessions: (directory) => sessionLoads.has(directory),
    onBootstrap: (directory) => {
      void bootstrapInstance(directory)
    },
    onDispose: (directory) => {
      queue.clear(directory)
      sessionMeta.delete(directory)
      sdkCache.delete(directory)
      for (const [key, repair] of messageRepairs) {
        if (!key.startsWith(directory + "\0")) continue
        repair.cancelled = true
        messageRepairs.delete(key)
      }
    },
  })

  const sdkFor = (directory: string) => {
    const cached = sdkCache.get(directory)
    if (cached) return cached
    const sdk = globalSDK.createClient({
      directory,
      throwOnError: true,
    })
    sdkCache.set(directory, sdk)
    return sdk
  }

  // A delta can arrive after reconnect before its part snapshot is restored.
  // Fetch only missing parts and merge them; never overwrite newer local text.
  const repairMessage = (
    directory: string,
    sessionID: string,
    messageID: string,
    partID: string,
    store: Store<State>,
    setStore: SetStoreFunction<State>,
  ) => {
    const key = repairKey(directory, sessionID, messageID)
    const existing = messageRepairs.get(key)
    if (existing) {
      existing.missingParts.add(partID)
      existing.dirty = true
      return
    }

    const repair = { dirty: false, cancelled: false, missingParts: new Set([partID]) }
    messageRepairs.set(key, repair)
    void (async () => {
      try {
        while (!repair.cancelled) {
          for (const id of repair.missingParts) {
            if (store.part[messageID]?.some((part) => part.id === id)) repair.missingParts.delete(id)
          }
          if (repair.missingParts.size === 0) return

          repair.dirty = false
          const response = await sdkFor(directory).session.message(
            { sessionID, messageID, directory },
            { throwOnError: true },
          )
          if (repair.cancelled) return
          if (repair.dirty) continue

          const needed = new Set(
            [...repair.missingParts].filter((id) => !store.part[messageID]?.some((part) => part.id === id)),
          )
          const recovered = response.data.parts.filter((part) => needed.has(part.id))
          if (recovered.length === 0) {
            console.warn("Could not recover missing streamed message part", {
              directory,
              sessionID,
              messageID,
              partIDs: [...needed],
            })
            return
          }

          setStore(
            produce((draft) => {
              const messages = draft.message[sessionID]
              if (!messages) draft.message[sessionID] = [response.data.info]
              else {
                const message = Binary.search(messages, response.data.info.id, (item) => item.id)
                if (!message.found) messages.splice(message.index, 0, response.data.info)
              }
              const parts = (draft.part[messageID] ??= [])
              for (const part of recovered) {
                const current = Binary.search(parts, part.id, (item) => item.id)
                if (!current.found) parts.splice(current.index, 0, part)
              }
            }),
          )
        }
      } catch (error) {
        console.warn("Message-part recovery failed", {
          directory,
          sessionID,
          messageID,
          error: error instanceof Error ? error.message : String(error),
        })
      } finally {
        if (messageRepairs.get(key) === repair) messageRepairs.delete(key)
      }
    })()
  }

  createEffect(() => {
    if (!projectCacheReady()) return
    if (globalStore.project.length !== 0) return
    const cached = projectCache.value
    if (cached.length === 0) return
    setGlobalStore("project", cached)
  })

  createEffect(() => {
    if (!projectCacheReady()) return
    const projects = globalStore.project
    if (projects.length === 0) {
      const cachedLength = untrack(() => projectCache.value.length)
      if (cachedLength !== 0) return
    }
    setProjectCache("value", projects.map(sanitizeProject))
  })

  createEffect(() => {
    if (globalStore.reload !== "complete") return
    setGlobalStore("reload", undefined)
    queue.refresh()
  })

  async function loadSessions(directory: string) {
    const pending = sessionLoads.get(directory)
    if (pending) return pending

    children.pin(directory)
    const [store, setStore] = children.child(directory, { bootstrap: false })
    const meta = sessionMeta.get(directory)
    if (meta && meta.limit >= store.limit) {
      const next = trimSessions(store.session, { limit: store.limit, permission: store.permission })
      if (next.length !== store.session.length) {
        setStore("session", reconcile(next, { key: "id" }))
      }
      children.unpin(directory)
      return
    }

    const limit = Math.max(store.limit + SESSION_RECENT_LIMIT, SESSION_RECENT_LIMIT)
    const promise = loadRootSessionsWithFallback({
      directory,
      limit,
      list: (query) => globalSDK.client.session.list(query),
      onFallback: () => {
        stats.loadSessionsFallback += 1
        updateStats(Object.keys(children.children).length)
      },
    })
      .then((x) => {
        const nonArchived = (x.data ?? [])
          .filter((s) => !!s?.id)
          .filter((s) => !s.time?.archived)
          .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
        const limit = store.limit
        const childSessions = store.session.filter((s) => !!s.parentID)
        const sessions = trimSessions([...nonArchived, ...childSessions], { limit, permission: store.permission })
        setStore(
          "sessionTotal",
          estimateRootSessionTotal({ count: nonArchived.length, limit: x.limit, limited: x.limited }),
        )
        setStore("session", reconcile(sessions, { key: "id" }))
        sessionMeta.set(directory, { limit })
      })
      .catch((err) => {
        console.error("Failed to load sessions", err)
        const project = getFilename(directory)
        showToast({
          title: language.t("toast.session.listFailed.title", { project }),
          description: errorMessage(err),
        })
      })

    sessionLoads.set(directory, promise)
    promise.finally(() => {
      sessionLoads.delete(directory)
      children.unpin(directory)
    })
    return promise
  }

  async function bootstrapInstance(directory: string) {
    if (!directory) return
    const pending = booting.get(directory)
    if (pending) return pending

    children.pin(directory)
    const promise = (async () => {
      const child = children.ensureChild(directory)
      const cache = children.vcsCache.get(directory)
      if (!cache) return
      const sdk = sdkFor(directory)
      await bootstrapDirectory({
        directory,
        sdk,
        store: child[0],
        setStore: child[1],
        vcsCache: cache,
        loadSessions,
      })
    })()

    booting.set(directory, promise)
    promise.finally(() => {
      booting.delete(directory)
      children.unpin(directory)
    })
    return promise
  }

  const unsub = globalSDK.event.listen((e) => {
    const directory = e.name
    const event = e.details

    if (directory === "global") {
      applyGlobalEvent({
        event,
        project: globalStore.project,
        refresh: queue.refresh,
        setGlobalProject(next) {
          if (typeof next === "function") {
            setGlobalStore("project", produce(next))
            return
          }
          setGlobalStore("project", next)
        },
      })
      return
    }

    const existing = children.children[directory]
    if (!existing) return
    children.mark(directory)
    const [store, setStore] = existing

    // Async prompts return before model execution finishes. Surface the actual
    // provider/server error instead of leaving an optimistic message unexplained.
    if (event.type === "session.error") {
      const properties = event.properties as {
        sessionID?: string
        error?: { name?: string; message?: string; data?: { message?: string } }
      }
      const message =
        properties.error?.data?.message || properties.error?.message || properties.error?.name
      showToast({
        title: language.t("common.requestFailed"),
        description: message || language.t("common.requestFailed"),
      })
      return
    }

    if (event.type === "message.removed") {
      const properties = event.properties as { sessionID: string; messageID: string }
      const key = repairKey(directory, properties.sessionID, properties.messageID)
      const repair = messageRepairs.get(key)
      if (repair) {
        repair.cancelled = true
        messageRepairs.delete(key)
      }
    }
    if (event.type === "message.part.updated") {
      const part = (event.properties as { part: { sessionID: string; messageID: string; id: string } }).part
      const repair = messageRepairs.get(repairKey(directory, part.sessionID, part.messageID))
      if (repair?.missingParts.has(part.id)) repair.dirty = true
    }
    if (event.type === "message.part.delta") {
      const properties = event.properties as { sessionID: string; messageID: string; partID: string }
      const repair = messageRepairs.get(repairKey(directory, properties.sessionID, properties.messageID))
      if (repair?.missingParts.has(properties.partID)) repair.dirty = true
    }
    if (event.type === "message.part.removed") {
      const properties = event.properties as { sessionID: string; messageID: string; partID: string }
      const repair = messageRepairs.get(repairKey(directory, properties.sessionID, properties.messageID))
      if (repair?.missingParts.delete(properties.partID)) {
        repair.dirty = true
        if (repair.missingParts.size === 0) {
          repair.cancelled = true
          messageRepairs.delete(repairKey(directory, properties.sessionID, properties.messageID))
        }
      }
    }

    applyDirectoryEvent({
      event,
      directory,
      store,
      setStore,
      push: queue.push,
      repairMessage: (sessionID, messageID, partID) =>
        repairMessage(directory, sessionID, messageID, partID, store, setStore),
      vcsCache: children.vcsCache.get(directory),
      loadLsp: () => {
        sdkFor(directory)
          .lsp.status()
          .then((x) => setStore("lsp", x.data ?? []))
      },
    })
  })

  onCleanup(unsub)
  onCleanup(() => {
    queue.dispose()
  })
  onCleanup(() => {
    for (const directory of Object.keys(children.children)) {
      children.disposeDirectory(directory)
    }
  })

  async function bootstrap() {
    await bootstrapGlobal({
      globalSDK: globalSDK.client,
      connectErrorTitle: language.t("dialog.server.add.error"),
      connectErrorDescription: language.t("error.globalSync.connectFailed", { url: globalSDK.url }),
      requestFailedTitle: language.t("common.requestFailed"),
      setGlobalStore,
    })
  }

  onMount(() => {
    void bootstrap()
  })

  const projectApi = {
    loadSessions,
    meta(directory: string, patch: ProjectMeta) {
      children.projectMeta(directory, patch)
    },
    icon(directory: string, value: string | undefined) {
      children.projectIcon(directory, value)
    },
  }

  const updateConfig = async (config: Config) => {
    setGlobalStore("reload", "pending")
    return globalSDK.client.global.config
      .update({ config })
      .then(bootstrap)
      .then(() => {
        setGlobalStore("reload", "complete")
      })
      .catch((error) => {
        setGlobalStore("reload", undefined)
        throw error
      })
  }

  return {
    data: globalStore,
    set: setGlobalStore,
    get ready() {
      return globalStore.ready
    },
    get error() {
      return globalStore.error
    },
    child: children.child,
    bootstrap,
    updateConfig,
    project: projectApi,
  }
}

const GlobalSyncContext = createContext<ReturnType<typeof createGlobalSync>>()

export function GlobalSyncProvider(props: ParentProps) {
  const value = createGlobalSync()
  return (
    <Switch>
      <Match when={value.ready}>
        <GlobalSyncContext.Provider value={value}>{props.children}</GlobalSyncContext.Provider>
      </Match>
    </Switch>
  )
}

export function useGlobalSync() {
  const context = useContext(GlobalSyncContext)
  if (!context) throw new Error("useGlobalSync must be used within GlobalSyncProvider")
  return context
}

export { canDisposeDirectory, pickDirectoriesToEvict } from "./global-sync/eviction"
export { estimateRootSessionTotal, loadRootSessionsWithFallback } from "./global-sync/session-load"
