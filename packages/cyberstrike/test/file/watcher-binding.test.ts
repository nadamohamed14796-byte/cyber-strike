import { expect, test } from "bun:test"
import { watcherBindingCandidates } from "../../src/file/watcher-binding"

test("tries the build-time Linux libc first, then the other supported libc", () => {
  expect(watcherBindingCandidates("linux", "x64", "glibc")).toEqual([
    "@parcel/watcher-linux-x64-glibc",
    "@parcel/watcher-linux-x64-musl",
  ])
  expect(watcherBindingCandidates("linux", "arm64", "musl")).toEqual([
    "@parcel/watcher-linux-arm64-musl",
    "@parcel/watcher-linux-arm64-glibc",
  ])
})

test("tries both Linux variants when running from source without a libc define", () => {
  expect(watcherBindingCandidates("linux", "x64")).toEqual([
    "@parcel/watcher-linux-x64-glibc",
    "@parcel/watcher-linux-x64-musl",
  ])
})

test("does not append a libc suffix on non-Linux platforms", () => {
  expect(watcherBindingCandidates("darwin", "arm64")).toEqual(["@parcel/watcher-darwin-arm64"])
  expect(watcherBindingCandidates("win32", "x64")).toEqual(["@parcel/watcher-win32-x64"])
})
