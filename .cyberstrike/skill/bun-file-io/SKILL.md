---
name: bun-file-io
description: "Use the repository’s preferred Bun file APIs and safe patterns for reading, writing, scanning, and deleting files."
category: developer-tooling
author: cyberstrike-official
version: "1.2.0"
tags: [bun, file-io, filesystem, glob, subprocess]
---

## Use this when

- Editing file I/O or scans in `packages/cyberstrike`
- Handling directory operations or external tools

## Bun file APIs (from Bun docs)

- `Bun.file(path)` is lazy; call `text`, `json`, `stream`, `arrayBuffer`, `bytes`, `exists` to read.
- Metadata: `file.size`, `file.type`, `file.name`.
- `Bun.write(dest, input)` writes strings, buffers, Blobs, Responses, or files.
- `Bun.file(...).delete()` deletes a file.
- `file.writer()` returns a FileSink for incremental writes.
- `Bun.Glob` + `Array.fromAsync(glob.scan({ cwd, absolute, onlyFiles, dot }))` for scans.
- Use `Bun.which` to find a binary, then `Bun.spawn` to run it.
- `Bun.readableStreamToText/Bytes/JSON` for stream output.

## When to use node:fs

- Use `node:fs/promises` for directories (`mkdir`, `readdir`, recursive operations).

## Repo patterns

- Prefer Bun APIs over Node `fs` for file access.
- Check `Bun.file(...).exists()` before reading.
- For binary/large files use `arrayBuffer()` and MIME checks via `file.type`.
- Use `Bun.Glob` + `Array.fromAsync` for scans.
- Decode tool stderr with `Bun.readableStreamToText`.
- For large writes, use `Bun.write(Bun.file(path), text)`.

NOTE: Bun.file(...).exists() will return `false` if the value is a directory.
Use Filesystem.exists(...) instead if path can be file or directory

## Path Safety and Test Coverage

- Treat file paths from HTTP requests, archives, repository metadata, and subprocess output as untrusted. Resolve against an explicit workspace root and reject paths that escape it after normalization; account for platform-specific separators and symlinks where applicable.
- For recursive scans, exclude generated output, dependency folders, VCS metadata, secrets, and files above a configured size limit unless the task explicitly needs them.
- Test missing files, directories passed as files, Unicode paths, symlinks, permission errors, very large files, empty files, and interrupted writes.
- When a function deletes or overwrites files, test that it refuses paths outside the intended workspace and that dry-run mode (if provided) makes no changes.
- Use temporary directories in tests; never use a developer home directory or real repository data as a destructive fixture.

## Safety and Error Handling

- Treat `Bun.file(path).exists()` as a convenience check, not a guarantee that a later read will succeed; the file can change between the check and the operation. Handle read/write errors at the operation site.
- If a path comes from user input or an external tool, resolve it with `path.resolve` and verify that it remains inside the intended workspace before reading, writing, or deleting it.
- Do not interpolate untrusted input into shell command strings. Prefer `Bun.spawn([binary, arg1, arg2], { ... })` with an argument array and a known executable path.
- Before deleting or overwriting files, confirm the destination is the intended artifact and not a directory, repository source file, or path outside the designated output area.
- For large files, prefer streams or byte APIs rather than loading the entire content into memory. Check MIME/type only as a hint; do not trust extension or `file.type` as a security boundary.
- For important outputs, write to a temporary file and rename it into place when the platform/filesystem supports atomic rename; do not assume every write is atomic.
- Capture and decode subprocess stdout/stderr, check the exit code, and apply a timeout/termination policy to processes that can hang.

## References

- [Bun file I/O](https://bun.sh/docs/api/file-io)
- [Bun subprocesses](https://bun.sh/docs/runtime/child-process)
## Quick checklist

- Use Bun APIs first.
- Use `path.join`/`path.resolve` for paths.
- Use `try/catch` for multi-step async flows and `.catch(...)` for local promise-chain recovery; choose the clearest control flow.
