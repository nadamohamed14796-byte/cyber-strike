/**
 * Build a deliberately small environment for the Hackbrowser worker process.
 *
 * Do not spread process.env into the child: the worker receives the selected
 * model credential in its WorkerOptions IPC payload, and must not inherit
 * unrelated CyberStrike, Gmail OAuth, website-password, or tool secrets.
 *
 * A few cloud providers need the SDK's ambient credential chain (currently
 * Bedrock and Vertex). Those variables are forwarded only when the selected
 * model uses that provider. Everything else must be represented explicitly in
 * the serializable model descriptor or configured as a non-secret runtime
 * setting below.
 */
const RUNTIME_ENV_KEYS = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "TZ",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "PLAYWRIGHT_BROWSERS_PATH",
  "DISPLAY",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
  "DBUS_SESSION_BUS_ADDRESS",
  "SYSTEMROOT",
  "WINDIR",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "COMSPEC",
  "PATHEXT",
] as const

const AWS_BEDROCK_ENV_KEYS = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_SECURITY_TOKEN",
  "AWS_REGION",
  "AWS_DEFAULT_REGION",
  "AWS_PROFILE",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_CONFIG_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_BEARER_TOKEN_BEDROCK",
  "AWS_EC2_METADATA_DISABLED",
  "AWS_ENDPOINT_URL",
  "AWS_ENDPOINT_URL_BEDROCK",
  "AWS_ENDPOINT_URL_BEDROCK_RUNTIME",
] as const

const GOOGLE_VERTEX_ENV_KEYS = [
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_PROJECT",
  "GOOGLE_CLOUD_LOCATION",
  "GOOGLE_CLOUD_QUOTA_PROJECT",
  "GCLOUD_PROJECT",
  "CLOUDSDK_CONFIG",
  "GOOGLE_GENAI_USE_VERTEXAI",
  "GOOGLE_API_USE_CLIENT_CERTIFICATE",
  "GOOGLE_API_USE_MTLS_ENDPOINT",
] as const

function copyDefined(
  source: NodeJS.ProcessEnv,
  target: Record<string, string>,
  keys: readonly string[],
): void {
  for (const key of keys) {
    const value = source[key]
    if (typeof value === "string" && value.length > 0) target[key] = value
  }
}

/**
 * Keep the child environment explicit and provider-scoped.
 * Never add CYBERSTRIKE_* or Gmail OAuth secrets to this allowlist.
 */
export function buildHackbrowserWorkerEnvironment(
  source: NodeJS.ProcessEnv,
  modelNpm: string,
): Record<string, string> {
  const child: Record<string, string> = {}
  copyDefined(source, child, RUNTIME_ENV_KEYS)

  if (modelNpm === "@ai-sdk/amazon-bedrock") {
    copyDefined(source, child, AWS_BEDROCK_ENV_KEYS)
  }

  if (modelNpm === "@ai-sdk/google-vertex" || modelNpm === "@ai-sdk/google-vertex/anthropic") {
    copyDefined(source, child, GOOGLE_VERTEX_ENV_KEYS)
  }

  return child
}
