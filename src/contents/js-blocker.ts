import type { PlasmoCSConfig } from "plasmo"

import { jsController } from "../modules/1.1-js-controller/JSController"
import { SUSPICIOUS_PATTERNS } from "../modules/1.1-js-controller/patterns"
import type { BlockedScript } from "../modules/1.1-js-controller/types"

/**
 * Content Script Configuration
 * This runs on ALL websites to monitor and block malicious JavaScript
 */
export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: true,
  run_at: "document_start" // Run before page scripts
}

/**
 * NOTE: eval/Function interception is handled by blocker-inject.ts
 * which runs in the MAIN world (page context) to bypass CSP restrictions
 */

/**
 * JavaScript Blocker Content Script
 */
class JSBlocker {
  private blockedScripts: BlockedScript[] = []
  private observer: MutationObserver | null = null

  constructor() {
    console.log("[JSBlocker] Initializing on:", window.location.href)
    this.addStyles()
    this.init()
  }

  /**
   * Add CSS animations for notifications
   */
  private addStyles(): void {
    // Skip if no document (empty page)
    if (!document || !document.documentElement) {
      console.log("[JSBlocker] Skipping styles - no document")
      return
    }

    // Use requestAnimationFrame to ensure DOM is ready
    const injectStyles = () => {
      if (!document.head) {
        requestAnimationFrame(injectStyles)
        return
      }

      try {
        const style = document.createElement("style")
        style.textContent = `
          @keyframes slideIn {
            from {
              transform: translateX(400px);
              opacity: 0;
            }
            to {
              transform: translateX(0);
              opacity: 1;
            }
          }
          
          @keyframes slideOut {
            from {
              transform: translateX(0);
              opacity: 1;
            }
            to {
              transform: translateX(400px);
              opacity: 0;
            }
          }
        `
        document.head.appendChild(style)
        console.log("[JSBlocker] Styles added successfully")
      } catch (error) {
        // Silently fail - styles are not critical
      }
    }

    // Use both requestAnimationFrame and setTimeout as fallback
    requestAnimationFrame(injectStyles)
  }

  /**
   * Initialize the blocker
   */
  private init(): void {
    // Load configuration from storage
    this.loadConfig().then(() => {
      // Start monitoring for script injections
      this.monitorScriptInjections()

      // Intercept inline scripts
      this.interceptInlineScripts()

      // Listen for eval/innerHTML blocks from MAIN world (blocker-inject.ts)
      this.listenForMainWorldBlocks()

      // Note: eval/Function interception is handled by blocker-inject.ts
      // which runs in MAIN world to avoid CSP violations
    })
  }

  /**
   * Load configuration from chrome.storage
   */
  private async loadConfig(): Promise<void> {
    try {
      const result = await chrome.storage.local.get(["jsControllerConfig"])
      if (result.jsControllerConfig) {
        jsController.updateConfig(result.jsControllerConfig)
        console.log("[JSBlocker] Config loaded from storage")
      }
    } catch (error) {
      console.error("[JSBlocker] Error loading config:", error)
    }
  }

  /**
   * Monitor for dynamically injected scripts using MutationObserver
   */
  private monitorScriptInjections(): void {
    this.observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeName === "SCRIPT") {
            this.checkScriptElement(node as HTMLScriptElement)
          }
        }
      }
    })

    // Start observing
    this.observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    })

    console.log("[JSBlocker] Script injection monitoring active")
  }

  /**
   * Check and potentially block a script element
   */
  private checkScriptElement(scriptElement: HTMLScriptElement): void {
    const scriptUrl = scriptElement.src || "inline"
    const scriptContent =
      scriptElement.textContent || scriptElement.innerHTML || ""

    // Skip empty scripts
    if (!scriptContent && !scriptUrl) return

    // Analyze the script
    const analysis = jsController.analyzeScript(scriptContent, scriptUrl)

    if (analysis.shouldBlock) {
      console.warn(
        `[JSBlocker] 🚫 BLOCKING SCRIPT: ${scriptUrl}`,
        analysis.matchedPatterns
      )

      // Remove the script element
      scriptElement.remove()

      // Record the block
      const blocked = jsController.recordBlockedScript(
        scriptUrl,
        scriptContent,
        analysis.matchedPatterns
      )

      this.blockedScripts.push(blocked)

      // Notify background worker
      this.notifyScriptBlocked(blocked)

      // Show warning overlay (optional)
      this.showBlockedWarning(blocked)
    }
  }

  /**
   * Intercept inline script execution
   */
  private interceptInlineScripts(): void {
    // Check all existing script tags
    const existingScripts = document.querySelectorAll("script")
    existingScripts.forEach((script) => {
      this.checkScriptElement(script as HTMLScriptElement)
    })
  }

  /**
   * Listen for eval/innerHTML blocks from MAIN world (blocker-inject.ts)
   */
  private listenForMainWorldBlocks(): void {
    window.addEventListener("message", (event) => {
      // Only accept messages from same origin
      if (event.source !== window) return

      // Check for our specific message type
      if (event.data?.type === "SECUREWEB_EVAL_BLOCKED") {
        const { method, pattern, severity, code, timestamp } = event.data.data

        console.log(
          `[JSBlocker] Received ${method} block notification from MAIN world:`,
          pattern
        )

        const blockedScript: BlockedScript = {
          url: "inline",
          reason: pattern,
          pattern,
          timestamp: timestamp || Date.now(),
          severity: severity.toLowerCase() as
            | "low"
            | "medium"
            | "high"
            | "critical",
          content: (code || "").substring(0, 200)
        }

        // Notify background worker about the block
        this.notifyScriptBlocked(blockedScript)

        // Show warning overlay for high/critical severity
        this.showBlockedWarning(blockedScript)
      }
    })
  }

  /**
   * Notify background worker about blocked script
   */
  private async notifyScriptBlocked(blocked: BlockedScript): Promise<void> {
    try {
      await chrome.runtime.sendMessage({
        type: "SCRIPT_BLOCKED",
        data: blocked
      })
    } catch (error) {
      console.error("[JSBlocker] Error notifying background:", error)
    }
  }

  /**
   * Show a warning overlay when script is blocked
   */
  private showBlockedWarning(blocked: BlockedScript): void {
    // Only show warning for high/critical severity
    if (blocked.severity !== "high" && blocked.severity !== "critical") {
      return
    }

    // Wait for body to be available
    const showWarning = () => {
      if (!document.body) {
        setTimeout(showWarning, 100)
        return
      }

      // Create warning element
      const warning = document.createElement("div")
      warning.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
        color: white;
        padding: 16px 20px;
        border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        max-width: 320px;
        animation: slideIn 0.3s ease-out;
      `

      warning.innerHTML = `
        <div style="display: flex; align-items: center; margin-bottom: 8px;">
          <span style="font-size: 20px; margin-right: 10px;">🛡️</span>
          <strong style="font-size: 15px;">SecureWeb Protection</strong>
        </div>
        <div style="font-size: 13px; opacity: 0.95; line-height: 1.4;">
          Blocked malicious script: <strong>${blocked.reason}</strong>
        </div>
      `

      document.body.appendChild(warning)

      // Auto-remove after 5 seconds
      setTimeout(() => {
        warning.style.animation = "slideOut 0.3s ease-in"
        setTimeout(() => warning.remove(), 300)
      }, 5000)
    }

    showWarning()
  }

  /**
   * Cleanup when content script unloads
   */
  destroy(): void {
    if (this.observer) {
      this.observer.disconnect()
      this.observer = null
    }
    console.log("[JSBlocker] Cleanup complete")
  }
}

// Initialize blocker when content script loads
let blocker: JSBlocker | null = null

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    blocker = new JSBlocker()
  })
} else {
  blocker = new JSBlocker()
}

// Cleanup on unload
window.addEventListener("beforeunload", () => {
  if (blocker) {
    blocker.destroy()
  }
})

export {}
