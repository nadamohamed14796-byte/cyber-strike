import { describe, expect, test } from "bun:test"
import { buildHackbrowserWorkerEnvironment } from "../src/hackbrowser-subprocess/worker-environment"

describe("Hackbrowser worker environment", () => {
  test("copies required runtime variables but drops unrelated and CyberStrike secrets", () => {
    const source = {
      PATH: "/usr/bin",
      HOME: "/home/tester",
      PLAYWRIGHT_BROWSERS_PATH: "/home/tester/.cache/ms-playwright",
      CYBERSTRIKE_CREDENTIALS_KEY: "vault-key-must-not-leak",
      CYBERSTRIKE_AUTH_PASSWORD: "site-password-must-not-leak",
      CYBERSTRIKE_GMAIL_OAUTH_CLIENT_SECRET: "gmail-secret-must-not-leak",
      CYBERSTRIKE_GMAIL_OAUTH_REFRESH_TOKEN: "gmail-refresh-must-not-leak",
      OPENAI_API_KEY: "unrelated-provider-key-must-not-leak",
      NODE_OPTIONS: "--require /tmp/untrusted.js",
      NODE_PATH: "/tmp/untrusted-modules",
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
      AWS_SECRET_ACCESS_KEY: "aws-secret-not-needed-for-openai",
      GOOGLE_APPLICATION_CREDENTIALS: "/tmp/gcp.json",
    } as NodeJS.ProcessEnv

    const result = buildHackbrowserWorkerEnvironment(source, "@ai-sdk/openai")

    expect(result.PATH).toBe("/usr/bin")
    expect(result.HOME).toBe("/home/tester")
    expect(result.PLAYWRIGHT_BROWSERS_PATH).toBe("/home/tester/.cache/ms-playwright")
    expect(result.CYBERSTRIKE_CREDENTIALS_KEY).toBeUndefined()
    expect(result.CYBERSTRIKE_AUTH_PASSWORD).toBeUndefined()
    expect(result.CYBERSTRIKE_GMAIL_OAUTH_CLIENT_SECRET).toBeUndefined()
    expect(result.CYBERSTRIKE_GMAIL_OAUTH_REFRESH_TOKEN).toBeUndefined()
    expect(result.OPENAI_API_KEY).toBeUndefined()
    expect(result.NODE_OPTIONS).toBeUndefined()
    expect(result.NODE_PATH).toBeUndefined()
    expect(result.NODE_TLS_REJECT_UNAUTHORIZED).toBeUndefined()
    expect(result.AWS_SECRET_ACCESS_KEY).toBeUndefined()
    expect(result.GOOGLE_APPLICATION_CREDENTIALS).toBeUndefined()
    // The helper is a projection; it must not mutate the parent environment.
    expect(source.CYBERSTRIKE_AUTH_PASSWORD).toBe("site-password-must-not-leak")
  })

  test("passes ambient credentials only to the matching cloud provider", () => {
    const source = {
      PATH: "/usr/bin",
      AWS_ACCESS_KEY_ID: "aws-id",
      AWS_SECRET_ACCESS_KEY: "aws-secret",
      AWS_REGION: "us-east-1",
      GOOGLE_APPLICATION_CREDENTIALS: "/secure/gcp.json",
      GOOGLE_CLOUD_PROJECT: "project-1",
      CYBERSTRIKE_CREDENTIALS_KEY: "vault-key",
    } as NodeJS.ProcessEnv

    const bedrock = buildHackbrowserWorkerEnvironment(source, "@ai-sdk/amazon-bedrock")
    expect(bedrock.AWS_ACCESS_KEY_ID).toBe("aws-id")
    expect(bedrock.AWS_SECRET_ACCESS_KEY).toBe("aws-secret")
    expect(bedrock.AWS_REGION).toBe("us-east-1")
    expect(bedrock.GOOGLE_APPLICATION_CREDENTIALS).toBeUndefined()
    expect(bedrock.CYBERSTRIKE_CREDENTIALS_KEY).toBeUndefined()

    const vertex = buildHackbrowserWorkerEnvironment(source, "@ai-sdk/google-vertex")
    expect(vertex.GOOGLE_APPLICATION_CREDENTIALS).toBe("/secure/gcp.json")
    expect(vertex.GOOGLE_CLOUD_PROJECT).toBe("project-1")
    expect(vertex.AWS_ACCESS_KEY_ID).toBeUndefined()
    expect(vertex.AWS_SECRET_ACCESS_KEY).toBeUndefined()
  })
})
