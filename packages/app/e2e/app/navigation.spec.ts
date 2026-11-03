import { test, expect } from "../fixtures"
import { promptSelector } from "../selectors"
import { dirPath } from "../utils"

test("project route redirects to /session", async ({ page, directory, slug }) => {
  await page.goto(dirPath(directory))

  await expect(page).toHaveURL(new RegExp(`/${slug}/session`))

  // A URL redirect can complete before the session prompt finishes mounting.
  // Wait for the same readiness contract used by the shared session fixture.
  const dock = page.locator('[data-component="session-prompt-dock"]')
  await expect(dock).toBeVisible({ timeout: 30_000 })
  await expect(dock).toHaveAttribute("data-prompt-ready", "true", { timeout: 30_000 })
  await expect(dock).toHaveAttribute("data-blocked", "false", { timeout: 30_000 })
  await expect(page.locator(promptSelector)).toBeVisible({ timeout: 10_000 })
})
