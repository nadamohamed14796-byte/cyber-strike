import type { MessageV2 } from "./message-v2"

/**
 * Whether this user turn has already attempted an actual tool call.
 * Partial streamed tool inputs stay pending and do not count. A tool-call
 * finish reason is also authoritative when a provider omits input-start parts.
 */
export function hasToolCallForUserTurn(messages: MessageV2.WithParts[], userMessageID: string): boolean {
  return messages.some((message) => {
    if (message.info.role !== "assistant" || message.info.parentID !== userMessageID) return false
    if (message.info.finish === "tool-calls") return true
    return message.parts.some((part) => {
      if (part.type !== "tool") return false
      if (part.state.status === "pending") return false
      if (part.state.status === "error" && part.state.error === "Tool execution aborted") return false
      return true
    })
  })
}
