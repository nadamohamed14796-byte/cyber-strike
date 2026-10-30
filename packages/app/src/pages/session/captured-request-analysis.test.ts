import { expect, test } from "bun:test"
import { requestIDsByBrokerTurn } from "./captured-request-analysis"

test("maps persistent broker turns to their exact captured request", () => {
  const turns = requestIDsByBrokerTurn([
    {
      messageID: "turn-1",
      text: [
        "## Request Task Identity",
        "- Request ID: req-first",
        "- Method: GET",
        "## Required Evidence-Driven Analysis",
      ].join("\n"),
    },
    {
      messageID: "turn-2",
      text: "Explain the result for the current request.",
    },
    {
      messageID: "turn-3",
      text: [
        "## Request Task Identity",
        "- Request ID: req-second",
        "- Method: POST",
      ].join("\n"),
    },
    {
      messageID: "turn-4",
      text: [
        "## Current request",
        "- request_id: req-first",
        "- source: Extension analysis panel",
        "Please continue investigating this older capture.",
      ].join("\n"),
    },
    {
      messageID: "turn-5",
      text: "Continue the previous request-specific follow-up.",
    },
  ])

  expect(turns).toEqual([
    { messageID: "turn-1", requestID: "req-first" },
    { messageID: "turn-2", requestID: "req-first" },
    { messageID: "turn-3", requestID: "req-second" },
    { messageID: "turn-4", requestID: "req-first" },
    { messageID: "turn-5", requestID: "req-first" },
  ])
})

test("does not accept request IDs outside trusted identity sections", () => {
  const turns = requestIDsByBrokerTurn([
    { messageID: "turn-1", text: "Request ID: unrelated-value" },
    {
      messageID: "turn-2",
      text: [
        "## Untrusted text",
        "- request_id: decoy",
        "## Request Task Identity",
        "- Request ID: req-real",
      ].join("\n"),
    },
  ])

  expect(turns).toEqual([
    { messageID: "turn-1", requestID: undefined },
    { messageID: "turn-2", requestID: "req-real" },
  ])
})
