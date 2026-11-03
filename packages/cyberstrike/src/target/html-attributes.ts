/** Read an exact HTML attribute name; data-* and prefixed names are distinct attributes. */
export function htmlAttribute(attributes: string, name: string): string | undefined {
  const pattern = /(?:^|\s)([a-z_:][a-z0-9_:.-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi
  for (const match of attributes.matchAll(pattern)) {
    if ((match[1] ?? "").toLowerCase() !== name.toLowerCase()) continue
    return match[3] ?? match[4] ?? match[5]
  }
  return undefined
}
