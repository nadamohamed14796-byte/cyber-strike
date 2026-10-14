import { App } from "@slack/bolt"
import { createCyberstrike, type ToolPart } from "@cyberstrike-io/sdk"

const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  signingSecret: process.env.SLACK_SIGNING_SECRET,
  socketMode: true,
  appToken: process.env.SLACK_APP_TOKEN,
})

console.log("🔧 Bot configuration:")
console.log("- Bot token present:", !!process.env.SLACK_BOT_TOKEN)
console.log("- Signing secret present:", !!process.env.SLACK_SIGNING_SECRET)
console.log("- App token present:", !!process.env.SLACK_APP_TOKEN)

console.log("🚀 Starting cyberstrike server...")
const cyberstrike = await createCyberstrike({
  port: 0,
})
console.log("✅ Cyberstrike server ready")

const sessions = new Map<string, { client: any; server: any; sessionId: string; channel: string; thread: string }>()
;(async () => {
  const events = await cyberstrike.client.event.subscribe()
  for await (const event of events.stream) {
    if (event.type === "message.part.updated") {
      const part = event.properties.part
      if (part.type === "tool") {
        // Find the session for this tool update
        for (const [sessionKey, session] of sessions.entries()) {
          if (session.sessionId === part.sessionID) {
            handleToolUpdate(part, session.channel, session.thread)
            break
          }
        }
      }
    }
  }
})()

async function handleToolUpdate(part: ToolPart, channel: string, thread: string) {
  if (part.state.status !== "completed") return
  const toolMessage = `*${part.tool}* - ${part.state.title}`
  await app.client.chat
    .postMessage({
      channel,
      thread_ts: thread,
      text: toolMessage,
    })
    .catch(() => {})
}

app.use(async ({ next, context }) => {
  // Do not log raw Slack context: it may contain message content or credentials.
  await next()
})

app.message(async ({ message, say }) => {
  console.log("Received Slack message event", { subtype: message.subtype, hasText: "text" in message && Boolean(message.text) })

  if (message.subtype || !("text" in message) || !message.text) {
    console.log("⏭️ Skipping message - no text or has subtype")
    return
  }

  console.log("Processing Slack message")

  const channel = message.channel
  const thread = (message as any).thread_ts || message.ts
  const sessionKey = `${channel}-${thread}`

  let session = sessions.get(sessionKey)

  if (!session) {
    console.log("🆕 Creating new cyberstrike session...")
    const { client, server } = cyberstrike

    const createResult = await client.session.create({
      body: { title: `Slack thread ${thread}` },
    })

    if (createResult.error) {
      console.error("Failed to create CyberStrike session")
      await say({
        text: "Sorry, I had trouble creating a session. Please try again.",
        thread_ts: thread,
      })
      return
    }

    console.log("Created CyberStrike session")

    session = { client, server, sessionId: createResult.data.id, channel, thread }
    sessions.set(sessionKey, session)

    const shareResult = await client.session.share({ path: { id: createResult.data.id } })
    if (!shareResult.error && shareResult.data) {
      const sessionUrl = shareResult.data.share?.url!
      console.log("Shared CyberStrike session")
      await app.client.chat.postMessage({ channel, thread_ts: thread, text: sessionUrl })
    }
  }

  console.log("Sending Slack message to CyberStrike")
  const result = await session.client.session.prompt({
    path: { id: session.sessionId },
    body: { parts: [{ type: "text", text: message.text }] },
  })

  console.log("Received response from CyberStrike", { failed: Boolean(result.error) })

  if (result.error) {
    console.error("Failed to send Slack message to CyberStrike")
    await say({
      text: "Sorry, I had trouble processing your message. Please try again.",
      thread_ts: thread,
    })
    return
  }

  const response = result.data

  // Build response text
  const responseText =
    response.info?.content ||
    response.parts
      ?.filter((p: any) => p.type === "text")
      .map((p: any) => p.text)
      .join("\n") ||
    "I received your message but didn't have a response."

  console.log("Sending CyberStrike response to Slack")

  // Send main response (tool updates will come via live events)
  await say({ text: responseText, thread_ts: thread })
})

app.command("/test", async ({ command, ack, say }) => {
  await ack()
  console.log("Received Slack test command")
  await say("🤖 Bot is working! I can hear you loud and clear.")
})

await app.start()
console.log("⚡️ Slack bot is running!")
