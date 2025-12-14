import { urlAnalyzer } from "../modules/1.2-url-analyzer/URLAnalyzer"
import { isKnownPhishing, loadThreatDB } from "../shared/utils/threat-db"
import { WebsiteBehaviorMonitor } from "../modules/2.3-behavior-monitor/WebsiteBehaviorMonitor"
import { ExtensionScanner } from "../modules/1.3-extension-scanner/ExtensionScanner"
import { AnomalyEngine } from "../modules/shared/AnomalyEngine"

/**
 * Background Service Worker
 * Coordinates all extension functionality
 */

console.log("[Background] SecureWeb background worker started")

// Initialize anomaly detection system
const behaviorMonitor = new WebsiteBehaviorMonitor()
const extensionScanner = new ExtensionScanner()
const anomalyEngine = new AnomalyEngine()

console.log("[Background] ✅ Anomaly detection system initialized")

// Initialize storage with defaults
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[Background] Extension installed, initializing defaults...")

  const defaults = {
    stats: {
      threatsBlocked: 0,
      scriptsBlocked: 0,
      lastReset: Date.now()
    },
    config: {
      isEnabled: true,
      mode: "moderate",
      whitelist: []
    },
    jsControllerConfig: {
      enabled: true,
      mode: "moderate",
      whitelist: ["google.com", "youtube.com", "github.com"]
    },
    recentThreats: []
  }

  await chrome.storage.local.set(defaults)
  console.log("[Background] Default configuration set")
  // Preload threat DB lazily (non-blocking)
  try {
    loadThreatDB()
  } catch {}
})

/**
 * Handle messages from content scripts and popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("[Background] Received message:", message.type)

  switch (message.type) {
    case "SCRIPT_BLOCKED":
      handleScriptBlocked(message.data).then(sendResponse)
      return true // Keep channel open for async response

    case "GET_STATS":
      handleGetStats().then(sendResponse)
      return true

    case "CONFIG_UPDATE":
      handleConfigUpdate(message.data).then(sendResponse)
      return true

    case "GET_CONFIG":
      handleGetConfig().then(sendResponse)
      return true

    case "CHECK_URL":
      handleCheckUrl(message.data?.url).then(sendResponse)
      return true

    default:
      console.warn("[Background] Unknown message type:", message.type)
      sendResponse({ success: false, error: "Unknown message type" })
  }
})

/**
 * Handle script blocked notification from content script
 */
async function handleScriptBlocked(data: any) {
  console.log("[Background] Script blocked:", data)

  try {
    // Update stats
    const result = await chrome.storage.local.get(["stats", "recentThreats"])
    const stats = result.stats || {
      threatsBlocked: 0,
      scriptsBlocked: 0,
      lastReset: Date.now()
    }

    stats.scriptsBlocked++

    // Store recent threat
    const recentThreats = result.recentThreats || []
    recentThreats.unshift({
      url: data.url,
      type: "malicious-js",
      reason: data.reason,
      timestamp: data.timestamp,
      severity: data.severity
    })

    // Keep only last 20 threats
    if (recentThreats.length > 20) {
      recentThreats.pop()
    }

    await chrome.storage.local.set({ stats, recentThreats })

    // Update badge to show blocked count
    const badgeText =
      stats.scriptsBlocked > 0 ? stats.scriptsBlocked.toString() : ""
    await chrome.action.setBadgeText({ text: badgeText })
    await chrome.action.setBadgeBackgroundColor({ color: "#dc2626" })

    console.log(
      "[Background] Stats updated, scripts blocked:",
      stats.scriptsBlocked
    )

    return { success: true, stats }
  } catch (error) {
    console.error("[Background] Error handling script blocked:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle stats request
 */
async function handleGetStats() {
  try {
    const result = await chrome.storage.local.get(["stats", "recentThreats"])
    return {
      success: true,
      stats: result.stats || {
        threatsBlocked: 0,
        scriptsBlocked: 0,
        lastReset: Date.now()
      },
      recentThreats: result.recentThreats || []
    }
  } catch (error) {
    console.error("[Background] Error getting stats:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle config update
 */
async function handleConfigUpdate(config: any) {
  try {
    console.log("[Background] Updating config:", config)

    // Update jsControllerConfig if it's a JS controller update
    if (config.mode || config.whitelist !== undefined) {
      const result = await chrome.storage.local.get(["jsControllerConfig"])
      const jsConfig = result.jsControllerConfig || {}

      await chrome.storage.local.set({
        jsControllerConfig: { ...jsConfig, ...config }
      })
    }

    // Update main config
    const result = await chrome.storage.local.get(["config"])
    const mainConfig = result.config || {}

    await chrome.storage.local.set({
      config: { ...mainConfig, ...config }
    })

    console.log("[Background] Config updated successfully")
    return { success: true }
  } catch (error) {
    console.error("[Background] Error updating config:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle get config request
 */
async function handleGetConfig() {
  try {
    const result = await chrome.storage.local.get([
      "config",
      "jsControllerConfig"
    ])
    return {
      success: true,
      config: result.config,
      jsControllerConfig: result.jsControllerConfig
    }
  } catch (error) {
    console.error("[Background] Error getting config:", error)
    return { success: false, error: error.message }
  }
}

async function handleCheckUrl(url?: string) {
  if (!url) return { success: false, error: "No URL provided" }
  try {
    await loadThreatDB()
    const known = isKnownPhishing(url)
    let result = await urlAnalyzer.analyzeURL(url)
    if (known.match) {
      // Elevate to malicious with high confidence
      result = {
        ...result,
        verdict: "malicious",
        confidence: Math.max(result.confidence, 0.95),
        reason: `Known phishing ${known.match}: ${known.value}`
      }
    }

    // Persist a condensed record into recentThreats
    const store = await chrome.storage.local.get(["stats", "recentThreats"])
    const stats = store.stats || {
      threatsBlocked: 0,
      scriptsBlocked: 0,
      lastReset: Date.now()
    }
    const recentThreats = store.recentThreats || []

    if (result.verdict !== "safe") {
      stats.threatsBlocked++
      recentThreats.unshift({
        url: result.url,
        type: "url-analysis",
        reason: result.reason,
        timestamp: Date.now(),
        severity: result.verdict === "malicious" ? "critical" : "high",
        indicators: result.indicators,
        confidence: result.confidence
      })
      if (recentThreats.length > 20) recentThreats.pop()
      await chrome.storage.local.set({ stats, recentThreats })
      const badgeText = String(
        (stats.scriptsBlocked || 0) + (stats.threatsBlocked || 0)
      )
      await chrome.action.setBadgeText({ text: badgeText })
      await chrome.action.setBadgeBackgroundColor({ color: "#dc2626" })
    }

    return { success: true, data: result }
  } catch (error: any) {
    console.error("[Background] Error checking URL:", error)
    return { success: false, error: error?.message || String(error) }
  }
}

/**
 * Monitor tab navigation (for future URL analysis + behavior monitoring)
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    console.log(`[Background] Tab ${tabId} navigating to: ${changeInfo.url}`)
    // Analyze URL on navigation
    try {
      const cfg = await chrome.storage.local.get(["config"])
      if (cfg?.config?.isEnabled === false) return
      // Skip whitelisted
      const whitelist: string[] = cfg?.config?.whitelist || []
      const host = new URL(changeInfo.url).hostname
      if (whitelist.some((w) => host.endsWith(w))) return
      await handleCheckUrl(changeInfo.url)
    } catch (e) {
      console.warn("[Background] URL analysis skipped:", e)
    }
  }
  
  // Monitor website behavior after page loads
  if (changeInfo.status === "complete" && tab.url) {
    console.log(`[Background] Tab ${tabId} completed loading: ${tab.url}`)
    
    try {
      const cfg = await chrome.storage.local.get(["config"])
      if (cfg?.config?.isEnabled === false) {
        console.log('[Background] Extension disabled, skipping behavior analysis')
        return
      }
      
      // Skip chrome:// and extension:// URLs
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        console.log('[Background] Skipping restricted URL:', tab.url)
        return
      }
      
      console.log(`[Background] 🔍 Starting behavior analysis for ${tab.url}`)
      
      // Analyze page behavior
      const anomaly = await behaviorMonitor.analyzePageLoad(tab.url, tabId)
      
      if (anomaly) {
        console.log(`[Background] ⚠️ Website anomaly detected on ${tab.url}`)
        await anomalyEngine.handleAnomaly(anomaly)
      } else {
        console.log(`[Background] ✅ No anomalies detected for ${tab.url}`)
      }
    } catch (e) {
      // Silently fail - page might have navigated away
      console.debug("[Background] Behavior analysis skipped:", e)
    }
  }
})

console.log("[Background] All listeners registered")
