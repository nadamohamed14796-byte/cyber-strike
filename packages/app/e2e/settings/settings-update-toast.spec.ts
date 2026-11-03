import { test, expect } from "../fixtures"

test("persistent update toast does not block underlying controls and keeps its action interactive", async ({ page, gotoSession }) => {
  await page.route("**/global/version-check", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ updateAvailable: true, latest: "1.1.17" }),
    }),
  )
  await gotoSession()

  const toast = page.locator('[data-component="toast"][data-nonblocking="true"]')
  await expect(toast).toBeVisible()
  await expect(toast).toContainText("1.1.17")
  const action = toast.locator('[data-slot="toast-action"]').first()
  await expect(action).toBeVisible()

  // Put a lower-layer button underneath the toast card. The card must pass
  // pointer events through while its explicitly interactive controls stay active.
  await page.evaluate(() => {
    const toast = document.querySelector('[data-component="toast"][data-nonblocking="true"]')
    if (!toast) throw new Error("Expected the persistent update toast")
    const rect = toast.getBoundingClientRect()
    const target = document.createElement("button")
    target.type = "button"
    target.textContent = "under-toast-target"
    target.dataset.testUnderToast = "true"
    Object.assign(target.style, {
      position: "fixed",
      left: `${rect.left + 8}px`,
      top: `${rect.top + 8}px`,
      width: "80px",
      height: "28px",
      zIndex: "999",
    })
    target.addEventListener("click", () => { target.dataset.clicked = "true" })
    document.body.append(target)
  })
  await page.getByRole("button", { name: "under-toast-target" }).click()
  await expect(page.locator('[data-test-under-toast="true"]')).toHaveAttribute("data-clicked", "true")

  await action.click()
  await expect(toast).toHaveCount(0)
})
