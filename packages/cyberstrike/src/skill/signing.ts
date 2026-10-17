import { Log } from "../util/log"
import { hashSkillContent } from "./signature-format"

export namespace SkillSigning {
  const log = Log.create({ service: "skill-signing" })

  // CyberStrike official Ed25519 public key (base64-encoded raw 32-byte key)
  // Used to verify skills signed by the CyberStrike team.
  // The corresponding private key is kept offline by maintainers.
  const OFFICIAL_PUBLIC_KEY_B64 = "qC5noNpNWhgt8fyKZyc9p6kXOHvsHDDO4GCqfDHJ/RA="

  export type VerificationStatus = "official" | "community" | "unverified" | "tampered"

  export async function computeHash(content: string): Promise<string> {
    return hashSkillContent(content)
  }

  export async function verify(skill: {
    content: string
    sha256?: string
    signature?: string
    signed_by?: string
  }): Promise<VerificationStatus> {
    const signature = skill.signature
    const claimsOfficial = skill.signed_by === "cyberstrike-official"
    if (claimsOfficial && (!skill.sha256 || !signature)) {
      log.warn("official skill is missing its required hash or signature")
      return "tampered"
    }
    if (!skill.sha256) return "unverified"

    const computed = await computeHash(skill.content)
    if (computed !== skill.sha256) {
      log.warn("skill hash mismatch", { expected: skill.sha256, computed })
      return "tampered"
    }

    if (!claimsOfficial) return "community"
    if (!signature) return "tampered" // Narrow the type after the official-claim gate above.

    try {
      const raw = Buffer.from(OFFICIAL_PUBLIC_KEY_B64, "base64")
      const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"])
      const sig = Buffer.from(signature, "base64")
      const data = new TextEncoder().encode(skill.sha256)
      const valid = await crypto.subtle.verify("Ed25519", key, sig, data)
      return valid ? "official" : "tampered"
    } catch (err) {
      log.error("signature verification failed", { err })
      return "tampered"
    }
  }

  export async function sign(content: string, privateKeyB64: string): Promise<{ sha256: string; signature: string }> {
    const hash = await computeHash(content)
    const raw = Buffer.from(privateKeyB64, "base64")
    const key = await crypto.subtle.importKey("pkcs8", raw, { name: "Ed25519" }, false, ["sign"])
    const data = new TextEncoder().encode(hash)
    const sig = await crypto.subtle.sign("Ed25519", key, data)
    return {
      sha256: hash,
      signature: Buffer.from(sig).toString("base64"),
    }
  }

  export async function generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])
    const pub = await crypto.subtle.exportKey("raw", pair.publicKey)
    const priv = await crypto.subtle.exportKey("pkcs8", pair.privateKey)
    return {
      publicKey: Buffer.from(pub).toString("base64"),
      privateKey: Buffer.from(priv).toString("base64"),
    }
  }
}
