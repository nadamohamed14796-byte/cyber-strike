import { describe, expect, test } from "bun:test"
import { parseScopeFileContents, parseScopeFileContentsDetailed, resolveScopeFilePath } from "./scope-file"

describe("parseScopeFileContents", () => {
  test("preserves valid wildcard suffix entries exactly as supplied", () => {
    expect(parseScopeFileContents("mercadolibreexperience.com.*\n*.mercadolibre.com\n")).toEqual([
      "mercadolibreexperience.com.*",
      "*.mercadolibre.com",
    ])
  })

  test("parses exact entries and explicit wildcards without broadening", () => {
    expect(parseScopeFileContents("# program scope\r\natt.com\n*.att.com\n192.0.2.0/24\n")).toEqual([
      "att.com",
      "*.att.com",
      "192.0.2.0/24",
    ])
  })

  test("preserves URL path scopes, service ports, and other compact scope identifiers", () => {
    expect(parseScopeFileContents("https://example.com/api/*\napi.example.com:8443\ncom.example.mobile\n2001:db8::1")).toEqual([
      "https://example.com/api/*",
      "api.example.com:8443",
      "com.example.mobile",
      "2001:db8::1",
    ])
  })

  test("ignores blank lines and full-line comments", () => {
    expect(parseScopeFileContents("\n  # comment\n // comment\napi.att.com  \n")).toEqual(["api.att.com"])
  })

  test("accepts a UTF-8 byte-order mark on the first entry", () => {
    expect(parseScopeFileContents("\uFEFFatt.com\napi.att.com")).toEqual(["att.com", "api.att.com"])
  })

  test("parses HackerOne TSV exports into typed scope entries", () => {
    expect(parseScopeFileContents([
      "identifier\tasset_type\tasset_tags",
      "*.example.com\tWildcard\t",
      "example.com\tDomain\t",
      "https://example.com/app1\tUrl\t",
      "192.0.2.0/24\tCidr\t",
      "com.example.mobile\tAndroidPlayStore\t",
      "com.example.ios\tIosAppStore\t",
      "com.example.ios.beta\tIosTestflight\t",
      "com.example.ios.ipa\tIosIpa\t",
      "com.example.windows\tWindowsMicrosoftStore\t",
      "https://github.com/acme/app\tSourceCode\t",
      "app-linux\tExecutable\t",
      "router-01\tHardware\t",
      "contract-address\tSmartContract\t",
      "model-endpoint\tAiModel\t",
      "https://api.example.com\tApi\t",
      "192.0.2.17\tIpAddress\t",
      "123456789012\tAwsAccount\t",
      "subscription-123\tAzureAccount\t",
      "123456789012\tAwsCloudConfig\t",
      "subscription-123\tAzureCloudConfig\t",
      "internal-system\tOtherAsset\t",
    ].join("\n"))).toEqual([
      "Wildcard: *.example.com",
      "Domain: example.com",
      "URL: https://example.com/app1",
      "CIDR: 192.0.2.0/24",
      "Android Play Store: com.example.mobile",
      "iOS: App Store: com.example.ios",
      "iOS: Testflight: com.example.ios.beta",
      "iOS: .ipa: com.example.ios.ipa",
      "Windows: Microsoft Store: com.example.windows",
      "Source Code: https://github.com/acme/app",
      "Executable: app-linux",
      "Hardware: router-01",
      "Smart Contract: contract-address",
      "AI Model: model-endpoint",
      "API: https://api.example.com",
      "IP Address: 192.0.2.17",
      "AWS Account: 123456789012",
      "Azure Account: subscription-123",
      "AWS Cloud Config: 123456789012",
      "Azure Cloud Config: subscription-123",
      "Other Asset: internal-system",
    ])
  })

  test("parses comma and semicolon HackerOne exports with display-name asset types", () => {
    expect(parseScopeFileContents([
      "identifier,asset_type,asset_tags",
      '"www.amazon.*",Wildcard,',
      '"com.example.mobile","Android: Play Store",',
      '"com.example.ios","iOS: .ipa",',
      '"router-01","Hardware/IoT",',
      '"internal-system",Other,',
    ].join("\n"))).toEqual([
      "Wildcard: www.amazon.*",
      "Android Play Store: com.example.mobile",
      "iOS: .ipa: com.example.ios",
      "Hardware: router-01",
      "Other Asset: internal-system",
    ])
    expect(parseScopeFileContents([
      "identifier;asset_type;asset_tags",
      "*.example.com;Wildcard;",
      "example.com;Domain;",
    ].join("\n"))).toEqual([
      "Wildcard: *.example.com",
      "Domain: example.com",
    ])
  })

  test("maps legacy HackerOne asset enum names without losing asset types", () => {
    expect(parseScopeFileContents([
      "identifier,asset_type",
      "com.example.app,APPLE_STORE_APP_ID",
      "com.example.beta,TESTFLIGHT",
      "builds/app.apk,OTHER_APK",
      "builds/app.ipa,OTHER_IPA",
      "app-id,WINDOWS_APP_STORE_APP_ID",
      "app-executable,DOWNLOADABLE_EXECUTABLES",
    ].join("\\n"))).toEqual([
      "iOS: App Store: com.example.app",
      "iOS: Testflight: com.example.beta",
      "Android: .apk: builds/app.apk",
      "iOS: .ipa: builds/app.ipa",
      "Windows: Microsoft Store: app-id",
      "Executable: app-executable",
    ])
  })

  test("preserves Google Play app IDs as non-web typed scope entries", () => {
    expect(parseScopeFileContents([
      "identifier,asset_type,instruction,eligible_for_bounty",
      "com.mercadopago.wallet,GOOGLE_PLAY_APP_ID,,true",
      "api.mercadopago.com,API,,true",
    ].join("\n"))).toEqual([
      "Google Play App ID: com.mercadopago.wallet",
      "API: api.mercadopago.com",
    ])
  })

  test("routes HackerOne rows with eligible_for_submission=false to exclusions", () => {
    const csv = [
      "identifier,asset_type,eligible_for_submission,eligible_for_bounty",
      "api.example.com,API,true,false",
      "admin.example.com,Domain,false,true",
    ].join("\\n")
    expect(parseScopeFileContentsDetailed(csv)).toEqual({
      include: ["API: api.example.com"],
      exclude: ["Domain: admin.example.com"],
    })
    // Bounty ineligibility does not mean out of scope when submissions are allowed.
    expect(parseScopeFileContentsDetailed(csv).include).toContain("API: api.example.com")
  })

  test("include-only parser refuses to silently discard explicit exclusions", () => {
    const csv = [
      "identifier,asset_type,eligible_for_submission",
      "example.com,Domain,true",
      "admin.example.com,Domain,false",
    ].join("\\n")
    expect(() => parseScopeFileContents(csv)).toThrow(/eligible_for_submission=false.*exclusions are preserved/i)
  })

  test("preserves unfamiliar typed scope entries instead of aborting the entire import", () => {
    expect(parseScopeFileContents("att.com\nAndroid application: com.example.mobile\n")).toEqual([
      "att.com",
      "Android application: com.example.mobile",
    ])
  })

  test("rejects files with no usable entries", () => {
    expect(() => parseScopeFileContents("# only comments\n\n// and blanks")).toThrow("no usable entries")
  })

  test("converts Windows Explorer WSL UNC paths to the matching Linux path", () => {
    expect(resolveScopeFilePath(String.raw`\\wsl.localhost\kali-linux\root\att.com.txt`, "/repo", "linux"))
      .toBe("/root/att.com.txt")
    expect(resolveScopeFilePath(String.raw`\\wsl$\kali-linux\root\att.com.txt`, "/repo", "linux"))
      .toBe("/root/att.com.txt")
  })

  test("keeps ordinary relative paths under the current working directory", () => {
    expect(resolveScopeFilePath("scope/att.com.txt", "/repo", "linux")).toBe("/repo/scope/att.com.txt")
  })
})
