export type TargetWorkflowMessage = {
  info: { role: string }
  parts: Array<{
    type: string
    text?: string
    ignored?: boolean
    synthetic?: boolean
  }>
}

/** Combine the root request with the current agent's task so child agents inherit intent. */
export function targetWorkflowText(
  rootMessages: TargetWorkflowMessage[],
  sessionMessages: TargetWorkflowMessage[],
): string {
  return [...rootMessages, ...sessionMessages]
    .filter((msg) => msg.info.role === "user")
    .flatMap((msg) =>
      msg.parts
        .filter((part) => part.type === "text" && !part.ignored && !part.synthetic)
        .map((part) => part.text ?? ""),
    )
    .join(" ")
    .slice(-12000)
}

/** Whether a conversation is part of a target/recon/security-testing workflow. */
export function requestsTargetWorkflow(text: string): boolean {
  return (
    /\b(target|scope|subdomains?|hosts?|recon(?:naissance)?|bug\s*bounty|pentest|penetration\s*test|hunting|asset\s*inventory|evidence|finding|report)\b/i.test(text) ||
    /(?:التارجت|تارجت|اسكوب|السكوب|نطاق|نطاقات|سب.?دومين|استطلاع|صيد\s+الثغرات|تقرير\s+ثغرات)/iu.test(text) ||
    (/\.(?:txt|list|csv)\b/i.test(text) && /\b(domain|host|scope|subdomain)\b/i.test(text))
  )
}
