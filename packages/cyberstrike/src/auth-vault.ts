import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { Global } from "../global"

const FILE = path.join(Global.Path.data, "auth-vault.json")
const ALGORITHM = "aes-256-gcm"

export type AuthPurpose = "research" | "target"

export interface AuthProfileInput {
  origin: string
  purpose: AuthPurpose
  account: string
  username: string
  password: string
  targetID?: string
}

interface StoredProfile {
  id: string
  origin: string
  purpose: AuthPurpose
  account: string
  username: string
  targetID?: string
  password: { iv: string; tag: string; ciphertext: string }
  createdAt: number
  updatedAt: number
}

export type AuthProfileSummary = Omit<StoredProfile, "password">

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function isBase64(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
}

function isStoredProfile(value: unknown): value is StoredProfile {
  if (!isRecord(value)) return false
  if (
    typeof value.id !== "string" ||
    !/^[a-f0-9]{32}$/i.test(value.id) ||
    typeof value.origin !== "string" ||
    (value.purpose !== "research" && value.purpose !== "target") ||
    typeof value.account !== "string" ||
    !value.account.trim() ||
    value.account.length > 120 ||
    /[\r\n\0]/.test(value.account) ||
    typeof value.username !== "string" ||
    !value.username.trim() ||
    value.username.length > 320 ||
    /[\r\n\0]/.test(value.username) ||
    typeof value.createdAt !== "number" ||
    !Number.isSafeInteger(value.createdAt) ||
    typeof value.updatedAt !== "number" ||
    !Number.isSafeInteger(value.updatedAt)
  ) return false

  try {
    if (normalizeAuthOrigin(value.origin) !== value.origin) return false
  } catch {
    return false
  }

  if (value.purpose === "target" && (typeof value.targetID !== "string" || !value.targetID.trim())) return false
  if (
    value.targetID !== undefined &&
    (typeof value.targetID !== "string" || !value.targetID.trim() || value.targetID.length > 128 || /[\r\n\0]/.test(value.targetID))
  ) return false
  if (value.purpose === "research" && value.targetID !== undefined) return false
  if (!isRecord(value.password)) return false
  const iv = value.password.iv
  const tag = value.password.tag
  const ciphertext = value.password.ciphertext
  if (!isBase64(iv) || !isBase64(tag) || !isBase64(ciphertext)) return false

  // AES-256-GCM uses a 12-byte IV and 16-byte authentication tag here.
  return Buffer.from(iv, "base64").length === 12 &&
    Buffer.from(tag, "base64").length === 16 &&
    Buffer.from(ciphertext, "base64").length > 0
}

/** Validate persisted JSON before exposing account metadata or decrypting any secret. */
export function isAuthVaultDataValid(value: unknown): boolean {
  if (!Array.isArray(value)) return false
  const ids = new Set<string>()
  for (const row of value) {
    if (!isStoredProfile(row) || ids.has(row.id)) return false
    ids.add(row.id)
  }
  return true
}

function key() {
  const secret = process.env.CYBERSTRIKE_CREDENTIALS_KEY
  if (!secret || secret.length < 32) {
    throw new Error("Credential vault is locked. Set CYBERSTRIKE_CREDENTIALS_KEY to a private value of at least 32 characters, then restart CyberStrike.")
  }
  return createHash("sha256").update(secret, "utf8").digest()
}

export function normalizeAuthOrigin(value: string): string {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error("Site must be a valid http(s) URL.")
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Only http(s) origins can have saved web accounts.")
  }
  if (url.username || url.password) throw new Error("Do not put credentials inside the URL.")
  return url.origin.toLowerCase()
}

async function read(): Promise<StoredProfile[]> {
  try {
    const raw = await fs.readFile(FILE, "utf8")
    const parsed: unknown = JSON.parse(raw)
    if (!isAuthVaultDataValid(parsed)) {
      // Fail closed; malformed rows must never be partially trusted or decrypted.
      throw new Error("Invalid credential vault format; refusing to use malformed records.")
    }
    return parsed as StoredProfile[]
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return []
    throw error
  }
}

async function write(rows: StoredProfile[]) {
  await fs.mkdir(Global.Path.data, { recursive: true, mode: 0o700 })
  // mkdir's mode is ignored when the directory already exists; enforce the
  // private directory mode before writing the credential vault.
  await fs.chmod(Global.Path.data, 0o700)
  const temp = FILE + "." + process.pid + "." + randomBytes(6).toString("hex") + ".tmp"
  try {
    await fs.writeFile(temp, JSON.stringify(rows, null, 2), { encoding: "utf8", mode: 0o600, flag: "wx" })
    await fs.rename(temp, FILE)
    await fs.chmod(FILE, 0o600)
  } finally {
    // A failed write/rename must not leave temporary vault files behind.
    await fs.rm(temp, { force: true }).catch(() => undefined)
  }
}

// Serialize read-modify-write operations within this process. Without this,
// concurrent saves/removals can overwrite one another's latest state.
let mutationTail: Promise<unknown> = Promise.resolve()

function serializeMutation<T>(operation: () => Promise<T>): Promise<T> {
  const result = mutationTail.then(operation, operation)
  mutationTail = result.then(
    () => undefined,
    () => undefined,
  )
  return result
}
function encrypt(value: string) {
  const iv = randomBytes(12)
  const cipher = createCipheriv(ALGORITHM, key(), iv)
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()])
  return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") }
}

function decrypt(value: StoredProfile["password"]) {
  const decipher = createDecipheriv(ALGORITHM, key(), Buffer.from(value.iv, "base64"))
  decipher.setAuthTag(Buffer.from(value.tag, "base64"))
  return Buffer.concat([decipher.update(Buffer.from(value.ciphertext, "base64")), decipher.final()]).toString("utf8")
}

function summary({ password: _secret, ...profile }: StoredProfile): AuthProfileSummary {
  return profile
}

export namespace AuthVault {
  export async function save(input: AuthProfileInput): Promise<AuthProfileSummary> {
    const origin = normalizeAuthOrigin(input.origin)
    const account = input.account.trim()
    const username = input.username.trim()
    if (!account || !username || !input.password) throw new Error("Account label, username/email, and password are required.")
    if (account.length > 120 || username.length > 320 || /[\r\n\0]/.test(account) || /[\r\n\0]/.test(username)) {
      throw new Error("Account labels must be one line (maximum 120 characters) and usernames one line (maximum 320 characters).")
    }
    const targetID = input.targetID?.trim() || undefined
    if (input.purpose === "target" && (!targetID || targetID.length > 128 || /[\r\n\0]/.test(targetID))) {
      throw new Error("Target-purpose credentials must be bound to a valid stable targetID (maximum 128 characters, one line).")
    }
    if (input.purpose === "research" && targetID) {
      throw new Error("Research profiles cannot be bound to a targetID; use purpose=target for target-scoped accounts.")
    }
    return serializeMutation(async () => {
      const rows = await read()
      const existing = rows.find((row) => row.origin === origin && row.purpose === input.purpose &&
        row.account.toLowerCase() === account.toLowerCase() && row.targetID === targetID)
      const now = Date.now()
      const row: StoredProfile = {
        id: existing?.id ?? randomBytes(16).toString("hex"),
        origin,
        purpose: input.purpose,
        account,
        username,
        ...(targetID ? { targetID } : {}),
        password: encrypt(input.password),
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      }
      const next = existing ? rows.map((item) => item.id === existing.id ? row : item) : [...rows, row]
      await write(next)
      return summary(row)
    })
  }
  export async function list(filter: { origin?: string; purpose?: AuthPurpose; targetID?: string } = {}): Promise<AuthProfileSummary[]> {
    const origin = filter.origin ? normalizeAuthOrigin(filter.origin) : undefined
    return (await read())
      .filter((row) => !origin || row.origin === origin)
      .filter((row) => !filter.purpose || row.purpose === filter.purpose)
      .filter((row) => filter.purpose !== "target" || row.targetID === filter.targetID)
      .map(summary)
  }

  /** Internal browser integration only. Never return this value from an agent-facing tool or log it. */
  export async function getSecret(input: { id: string; origin: string; purpose: AuthPurpose; targetID?: string }) {
    const origin = normalizeAuthOrigin(input.origin)
    const row = (await read()).find((item) => item.id === input.id && item.origin === origin &&
      item.purpose === input.purpose && (input.purpose !== "target" || item.targetID === input.targetID))
    if (!row) return undefined
    return { ...summary(row), password: decrypt(row.password) }
  }

  export async function remove(input: { id: string; origin: string; purpose: AuthPurpose; targetID?: string }): Promise<boolean> {
    const origin = normalizeAuthOrigin(input.origin)
    return serializeMutation(async () => {
      const rows = await read()
      const next = rows.filter((row) => !(row.id === input.id && row.origin === origin &&
        row.purpose === input.purpose && (input.purpose !== "target" || row.targetID === input.targetID)))
      if (next.length === rows.length) return false
      await write(next)
      return true
    })
  }
}
