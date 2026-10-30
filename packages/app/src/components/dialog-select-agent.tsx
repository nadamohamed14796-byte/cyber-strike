import { createMemo, createSignal } from "solid-js"
import { useSync } from "@/context/sync"
import { useLocal } from "@/context/local"
import { Dialog } from "@cyberstrike-io/ui/dialog"
import { List } from "@cyberstrike-io/ui/list"
import { useDialog } from "@cyberstrike-io/ui/context/dialog"
import { useLanguage } from "@/context/language"
import { agentColor } from "@/utils/agent"

export function DialogSelectAgent() {
  const sync = useSync()
  const local = useLocal()
  const dialog = useDialog()
  const language = useLanguage()
  const [hoveredName, setHoveredName] = createSignal("")

  const items = createMemo(() => {
    const visible = sync.data.agent.filter((a) => !a.hidden)
    const primary = visible.filter((a) => a.mode !== "subagent")
    return visible.map((a) => {
      const idx = primary.findIndex((p) => p.name === a.name)
      return {
        id: a.id,
        name: a.name,
        description: a.description ?? "",
        mode: a.mode,
        color: agentColor(a.name, a.color, idx >= 0 ? idx : undefined),
      }
    })
  })

  const primary = createMemo(() => items().filter((a) => a.mode !== "subagent"))

  const currentItem = createMemo(() => {
    const id = local.agent.current()?.id
    return items().find((a) => a.id === id)
  })

  return (
    <Dialog
      title={language.t("dialog.agent.title")}
      description={language.t("dialog.agent.description", {
        total: items().length,
        primary: primary().length,
      })}
    >
      <List
        search={{
          placeholder: language.t("common.search.placeholder"),
          autofocus: true,
        }}
        emptyMessage="No agents found"
        key={(x) => x?.id ?? ""}
        items={items}
        current={currentItem()}
        filterKeys={["name", "description", "mode"]}
        sortBy={(a, b) => {
          if (a.mode !== "subagent" && b.mode === "subagent") return -1
          if (a.mode === "subagent" && b.mode !== "subagent") return 1
          return a.name.localeCompare(b.name)
        }}
        onMove={(x) => setHoveredName(x?.id ?? "")}
        onSelect={(x) => {
          if (!x) return
          local.agent.set(x.id)
          dialog.close()
        }}
      >
        {(item) => {
          const hovered = () => item.id === hoveredName()
          return (
            <div
              class="w-full flex items-center gap-3"
              style={{
                "border-left": `3px solid ${item.color}`,
                "padding-left": "10px",
                margin: "-6px -8px",
                "padding-top": "6px",
                "padding-bottom": "6px",
                "padding-right": "8px",
                "border-radius": "var(--radius-md)",
                background: hovered() ? `color-mix(in srgb, ${item.color} 18%, transparent)` : undefined,
              }}
            >
              <div class="flex flex-col gap-0.5 min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <span class="truncate capitalize">{item.name}</span>
                  {item.id === currentItem()?.id && (
                    <span class="text-11-regular text-text-weaker">{language.t("dialog.agent.current")}</span>
                  )}
                </div>
                {item.description && <span class="text-11-regular text-text-weaker truncate">{item.description}</span>}
              </div>
              <span
                class="text-11-regular shrink-0"
                style={{ color: item.mode === "subagent" ? undefined : item.color }}
              >
                {item.mode}
              </span>
            </div>
          )
        }}
      </List>
    </Dialog>
  )
}
