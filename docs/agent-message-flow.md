# Agent Message and Event Flow

This document describes the maintained source-of-truth path for message delivery. Keep code and generated SDK types aligned with it.

## Message path

1. **Accept and persist input.** `SessionPrompt.prompt` creates the user message through `createUserMessage` and `Session.updateMessage`. The message record is the durable source of truth.
2. **Run the model.** The session loop creates an assistant message, then `SessionProcessor.process` consumes the model stream and checks the abort signal while processing events.
3. **Persist parts before streaming deltas.** `Session.updatePart` writes a complete part and publishes `message.part.updated`. Text chunks use `Session.updatePartDelta` and publish `message.part.delta`; a delta is incremental UI data, not a complete saved part. At `text-end`, the final transformed text is persisted again with `message.part.updated`.
4. **Publish without fail-fast local handlers.** `Bus.publish` invokes matching and wildcard local subscribers and emits the global event. A failed local subscriber must be logged but must not prevent other subscribers or global delivery.
5. **Update the client.** The global sync layer routes directory events into `applyDirectoryEvent`. `message.updated` upserts message metadata; `message.part.updated` upserts a full part; `message.part.delta` appends only to a known text part. Unknown fields are ignored. If a delta arrives before its part snapshot, request recovery via `session.message` and merge only missing parts by ID; never replace newer local text with an older snapshot.
6. **Keep IDs, ownership, and event schemas consistent.** The stable keys are `sessionID`, `messageID`, and `partID`; full part snapshots use `part.id`. Event schemas live in `session/message-v2.ts`; generated client declarations must be regenerated from the schema rather than manually drifting. Message removal must clear orphaned part cache. On reconnect, bootstrap/recovery restores snapshots before later deltas are relied upon.

## Retry, abort, and loop exits

1. Retry only errors classified as retryable. Retry sleep must immediately reject when its `AbortSignal` is already aborted and must be interruptible when abort happens during the wait.
2. A model turn with neither non-empty text nor any tool call is an error, not a successful empty reply.
3. The prompt loop's step cap is enforced in code: on the wrap-up step, remove regular tools so the model must finish; keep only `StructuredOutput` when structured mode requires it.
4. Repeated identical tool + argument signatures are detected by the shared `toolSig` helper. The within-turn guard, processor permission check, and cross-turn detector have distinct jobs. Do not treat different arguments as duplicate calls, and do not enable the generic no-progress monologue detector by default without tests proving it will not flag normal coordination.

## Validation checklist

- Test abort before retry sleep starts and abort during sleep.
- Test that a throwing local bus subscriber cannot stop global event delivery.
- Test event-reducer upsert, delta handling, missing-part recovery, and removal.
- Test repeat signatures with same args, reordered object keys, different args, and cross-turn repeats.
- Run package tests from their package directories; do not infer runtime delivery success from static inspection alone.
