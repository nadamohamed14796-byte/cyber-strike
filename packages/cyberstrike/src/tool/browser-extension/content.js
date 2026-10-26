// Small visual indicator only. This file does not start, stop, or control a CyberStrike crawl.
;(function () {
  if (window !== window.top) return

  const bannerID = "cyberstrike-banner"
  let observer

  function dismissBanner() {
    document.getElementById(bannerID)?.remove()
    document.documentElement?.classList.remove("cyberstrike-indicator-active")
    observer?.disconnect()
  }

  function insertBanner() {
    if (!document.body || document.getElementById(bannerID)) return

    const banner = document.createElement("div")
    banner.id = bannerID

    const label = document.createElement("span")
    label.className = "cyberstrike-text"
    label.textContent = "CyberStrike browser indicator is active on this page"

    const dismiss = document.createElement("button")
    dismiss.type = "button"
    dismiss.className = "cyberstrike-btn"
    dismiss.textContent = "Dismiss"
    dismiss.setAttribute("aria-label", "Dismiss CyberStrike browser indicator")
    dismiss.addEventListener("click", dismissBanner)

    banner.append(label, dismiss)
    document.body.insertBefore(banner, document.body.firstChild)
    document.documentElement?.classList.add("cyberstrike-indicator-active")
    observer?.disconnect()
  }

  if (document.body) {
    insertBanner()
  } else {
    document.addEventListener("DOMContentLoaded", insertBanner, { once: true })
  }

  observer = new MutationObserver(() => {
    if (!document.body) return
    insertBanner()
    observer?.disconnect()
  })

  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true })
  }
})()
