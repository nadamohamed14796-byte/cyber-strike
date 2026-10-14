/**
 * Explicit sanitizer for target-note text that must not retain credentials.
 * This helper is not an automatic persistence boundary: private target evidence
 * may intentionally preserve exact observed values for authorized reproduction.
 * Callers must choose deliberately between sanitized metadata and raw target-local
 * evidence; raw evidence must never be copied into global research or public reports.
 */
export function redactTargetNoteSecrets(value: string): string {
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT REDACTED]")
    .replace(/(^|\n)(\s*(?:authorization|cookie|set-cookie)\s*:\s*)[^\r\n]*/gi, "$1$2[REDACTED]")
    // Consume complete quoted values (including spaces), otherwise a value such
    // as {"password":"two word secret"} could leak everything after its first word.
    .replace(/(["']?(?:authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|password|client[_-]?secret)["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,\s;}\r\n]+)/gi, "$1[REDACTED]")
}

/** Sanitize values embedded into generated Markdown metadata as one line. */
export function redactTargetNoteLine(value: string, maxLength: number): string {
  return redactTargetNoteSecrets(value)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, maxLength)
}
