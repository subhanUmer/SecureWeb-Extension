import { useEffect, useState } from "react"

import "../styles/popup.css"

interface Stats {
  threatsBlocked: number
  scriptsBlocked: number
  lastReset: number
}

interface Threat {
  url: string
  type: string
  reason: string
  timestamp: number
  severity: string
  indicators?: Array<{
    category: string
    description: string
    deviationScore: number
    evidence: any
  }>
  confidence?: number
}

interface Config {
  enabled: boolean
  mode: "strict" | "moderate" | "permissive"
  whitelist: string[]
}

function IndexPopup() {
  const [stats, setStats] = useState<Stats>({
    threatsBlocked: 0,
    scriptsBlocked: 0,
    lastReset: Date.now()
  })
  const [recentThreats, setRecentThreats] = useState<Threat[]>([])
  const [anomalyHistory, setAnomalyHistory] = useState<any[]>([])
  const [config, setConfig] = useState<Config>({
    enabled: true,
    mode: "moderate",
    whitelist: []
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<
    "dashboard" | "threats" | "anomalies" | "settings"
  >("dashboard")
  const [newDomain, setNewDomain] = useState("")

  // Load stats and config on mount
  useEffect(() => {
    loadData()
    // Refresh every 2 seconds
    const interval = setInterval(loadData, 2000)
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      const result = await chrome.storage.local.get([
        "stats",
        "recentThreats",
        "config",
        "jsControllerConfig",
        "anomaly_history"
      ])

      if (result.stats) setStats(result.stats)
      if (result.recentThreats) {
        // Filter out any null/undefined entries
        const validThreats = (result.recentThreats || []).filter(
          (t: any) => t && typeof t === "object"
        )
        setRecentThreats(validThreats)
      }
      if (result.anomaly_history) {
        setAnomalyHistory(result.anomaly_history || [])
      }
      if (result.jsControllerConfig) {
        setConfig({
          enabled: result.jsControllerConfig.enabled ?? true,
          mode: result.jsControllerConfig.mode ?? "moderate",
          whitelist: result.jsControllerConfig.whitelist ?? []
        })
      }

      setLoading(false)
      setError(null)
    } catch (error) {
      console.error("Error loading data:", error)
      setError("Failed to load extension data")
      setLoading(false)
    }
  }

  const toggleEnabled = async () => {
    const newEnabled = !config.enabled
    setConfig({ ...config, enabled: newEnabled })

    await chrome.storage.local.set({
      jsControllerConfig: { ...config, enabled: newEnabled }
    })
  }

  const changeMode = async (mode: "strict" | "moderate" | "permissive") => {
    setConfig({ ...config, mode })

    await chrome.storage.local.set({
      jsControllerConfig: { ...config, mode }
    })
  }

  const addToWhitelist = async () => {
    if (!newDomain.trim()) return

    const domain = newDomain.trim().toLowerCase()
    if (config.whitelist.includes(domain)) {
      alert("Domain already whitelisted")
      return
    }

    const newWhitelist = [...config.whitelist, domain]
    setConfig({ ...config, whitelist: newWhitelist })
    setNewDomain("")

    await chrome.storage.local.set({
      jsControllerConfig: { ...config, whitelist: newWhitelist }
    })
  }

  const removeFromWhitelist = async (domain: string) => {
    const newWhitelist = config.whitelist.filter((d) => d !== domain)
    setConfig({ ...config, whitelist: newWhitelist })

    await chrome.storage.local.set({
      jsControllerConfig: { ...config, whitelist: newWhitelist }
    })
  }

  const resetStats = async () => {
    const newStats = {
      threatsBlocked: 0,
      scriptsBlocked: 0,
      lastReset: Date.now()
    }

    setStats(newStats)
    setRecentThreats([])

    await chrome.storage.local.set({
      stats: newStats,
      recentThreats: []
    })

    await chrome.action.setBadgeText({ text: "" })
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "#dc2626"
      case "high":
        return "#ea580c"
      case "medium":
        return "#eab308"
      case "low":
        return "#22c55e"
      default:
        return "#6b7280"
    }
  }

  const formatTime = (timestamp: number) => {
    try {
      if (!timestamp || isNaN(timestamp)) return "Unknown"
      const date = new Date(timestamp)
      const now = new Date()
      const diffMs = now.getTime() - date.getTime()
      const diffMins = Math.floor(diffMs / 60000)

      if (diffMins < 1) return "Just now"
      if (diffMins < 60) return `${diffMins}m ago`
      if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`
      return date.toLocaleDateString()
    } catch (e) {
      return "Unknown"
    }
  }

  const getHostname = (url: string): string => {
    try {
      if (!url) return "Unknown"
      // Handle cases where URL might not be a full URL
      if (url.startsWith("http://") || url.startsWith("https://")) {
        return new URL(url).hostname
      }
      // If it's just "inline" or other non-URL strings
      return url
    } catch (e) {
      return url || "Unknown"
    }
  }

  if (loading) {
    return (
      <div className="popup-container loading">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="popup-container loading">
        <div style={{ textAlign: "center", padding: "20px", color: "#dc2626" }}>
          <div style={{ fontSize: "48px", marginBottom: "12px" }}>⚠️</div>
          <p style={{ fontWeight: 600, marginBottom: "8px" }}>
            Error Loading Extension
          </p>
          <p style={{ fontSize: "12px", color: "#6b7280" }}>{error}</p>
          <button
            onClick={() => {
              setError(null)
              setLoading(true)
              loadData()
            }}
            style={{
              marginTop: "16px",
              padding: "8px 16px",
              background: "#667eea",
              color: "white",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer"
            }}>
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="popup-container">
      {/* Header */}
      <div className="header">
        <div className="header-content">
          <div className="logo-section">
            <div className="logo-icon">🛡️</div>
            <div>
              <h1>SecureWeb</h1>
              <p className="subtitle">Browser Protection</p>
            </div>
          </div>
          <div
            className={`status-badge ${config.enabled ? "active" : "disabled"}`}>
            {config.enabled ? "Active" : "Disabled"}
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="tab-nav">
        <button
          className={`tab-btn ${activeTab === "dashboard" ? "active" : ""}`}
          onClick={() => setActiveTab("dashboard")}>
          Dashboard
        </button>
        <button
          className={`tab-btn ${activeTab === "threats" ? "active" : ""}`}
          onClick={() => setActiveTab("threats")}>
          Threats ({recentThreats.length})
        </button>
        <button
          className={`tab-btn ${activeTab === "anomalies" ? "active" : ""}`}
          onClick={() => setActiveTab("anomalies")}>
          Anomalies ({anomalyHistory.length})
        </button>
        <button
          className={`tab-btn ${activeTab === "settings" ? "active" : ""}`}
          onClick={() => setActiveTab("settings")}>
          Settings
        </button>
      </div>

      {/* Dashboard Tab */}
      {activeTab === "dashboard" && (
        <div className="tab-content">
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-icon">🚫</div>
              <div className="stat-info">
                <div className="stat-value">{stats.scriptsBlocked}</div>
                <div className="stat-label">Scripts Blocked</div>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">⚠️</div>
              <div className="stat-info">
                <div className="stat-value">{stats.threatsBlocked}</div>
                <div className="stat-label">Threats Detected</div>
              </div>
            </div>
          </div>

          <div className="section">
            <h3>Protection Status</h3>
            <div className="status-grid">
              <div className="status-item">
                <span>JavaScript Protection</span>
                <span className="status-indicator active">Active</span>
              </div>
              <div className="status-item">
                <span>XSS Prevention</span>
                <span className="status-indicator active">Active</span>
              </div>
              <div className="status-item">
                <span>Crypto Miner Block</span>
                <span className="status-indicator active">Active</span>
              </div>
            </div>
          </div>

          <div className="section">
            <div className="section-header">
              <h3>Recent Activity</h3>
              {recentThreats.length > 0 && (
                <button className="btn-link" onClick={resetStats}>
                  Clear
                </button>
              )}
            </div>
            {recentThreats.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">✓</div>
                <p>No threats detected</p>
                <small>You're protected!</small>
              </div>
            ) : (
              <div className="threats-list">
                {recentThreats.slice(0, 3).map((threat, idx) => {
                  if (!threat) return null
                  return (
                    <div key={idx} className="threat-item">
                      <div
                        className="threat-severity"
                        style={{
                          backgroundColor: getSeverityColor(
                            threat.severity || "medium"
                          )
                        }}
                      />
                      <div className="threat-info">
                        <div className="threat-title">
                          {threat.reason || threat.type || "Unknown threat"}
                        </div>
                        <div className="threat-meta">
                          <span className="threat-domain">
                            {getHostname(threat.url)}
                          </span>
                          <span className="threat-time">
                            {formatTime(threat.timestamp)}
                          </span>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Threats Tab */}
      {activeTab === "threats" && (
        <div className="tab-content">
          <div className="section">
            <div className="section-header">
              <h3>All Threats</h3>
              {recentThreats.length > 0 && (
                <button className="btn-link" onClick={resetStats}>
                  Clear All
                </button>
              )}
            </div>
            {recentThreats.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">✓</div>
                <p>No threats detected</p>
                <small>Your browsing is secure</small>
              </div>
            ) : (
              <div className="threats-list-full">
                {recentThreats.map((threat, idx) => {
                  if (!threat) return null
                  return (
                    <div key={idx} className="threat-card">
                      <div className="threat-card-header">
                        <span
                          className="severity-badge"
                          style={{
                            backgroundColor: getSeverityColor(
                              threat.severity || "medium"
                            )
                          }}>
                          {threat.severity || "medium"}
                        </span>
                        <span className="threat-time">
                          {formatTime(threat.timestamp)}
                        </span>
                      </div>
                      <div className="threat-card-body">
                        <div className="threat-type">
                          {threat.reason || threat.type || "Unknown threat"}
                        </div>
                        <div className="threat-url">
                          {threat.url || "Unknown URL"}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Anomalies Tab */}
      {activeTab === "anomalies" && (
        <div className="tab-content">
          <div className="section">
            <div className="section-header">
              <h3>Behavioral Anomalies</h3>
              <small style={{ color: "#6b7280" }}>
                Statistical anomaly detection (non-ML)
              </small>
            </div>
            {anomalyHistory.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">✓</div>
                <p>No anomalies detected</p>
                <small>Normal website behavior</small>
              </div>
            ) : (
              <div className="threats-list-full">
                {anomalyHistory.map((anomaly, idx) => (
                  <div key={idx} className="threat-card">
                    <div className="threat-card-header">
                      <span
                        className="severity-badge"
                        style={{
                          backgroundColor: getSeverityColor(
                            anomaly.severity || "medium"
                          )
                        }}>
                        {anomaly.severity || "medium"}
                      </span>
                      <span className="threat-time">
                        {formatTime(anomaly.detectedAt || anomaly.timestamp)}
                      </span>
                    </div>
                    <div className="threat-card-body">
                      <div className="threat-type">
                        <strong>{anomaly.targetName || "Unknown"}</strong>
                        {anomaly.confidence && (
                          <span
                            style={{
                              marginLeft: "8px",
                              fontSize: "11px",
                              color: "#6b7280"
                            }}>
                            {Math.round(anomaly.confidence * 100)}% confidence
                          </span>
                        )}
                      </div>
                      <div className="threat-url" style={{ marginTop: "8px" }}>
                        Type: {anomaly.type} | Recommendation:{" "}
                        {anomaly.recommendation}
                      </div>
                      {anomaly.indicators && anomaly.indicators.length > 0 && (
                        <div
                          style={{
                            marginTop: "12px",
                            paddingTop: "12px",
                            borderTop: "1px solid #e5e7eb"
                          }}>
                          <div
                            style={{
                              fontSize: "11px",
                              fontWeight: 600,
                              color: "#6b7280",
                              marginBottom: "6px"
                            }}>
                            DETECTED INDICATORS:
                          </div>
                          {anomaly.indicators.map((ind: any, i: number) => (
                            <div
                              key={i}
                              style={{
                                fontSize: "11px",
                                padding: "6px 8px",
                                background: "#f9fafb",
                                borderRadius: "4px",
                                marginBottom: "4px"
                              }}>
                              <div style={{ fontWeight: 600, color: "#374151" }}>
                                [{ind.category}] {ind.description}
                              </div>
                              <div style={{ color: "#6b7280", marginTop: "2px" }}>
                                Deviation Score: {ind.deviationScore.toFixed(2)}
                              </div>
                              {ind.evidence && (
                                <div
                                  style={{
                                    color: "#9ca3af",
                                    marginTop: "2px",
                                    fontSize: "10px"
                                  }}>
                                  Evidence:{" "}
                                  {typeof ind.evidence === "string"
                                    ? ind.evidence
                                    : Array.isArray(ind.evidence)
                                      ? ind.evidence.join(", ")
                                      : JSON.stringify(ind.evidence)}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Settings Tab */}
      {activeTab === "settings" && (
        <div className="tab-content">
          <div className="section">
            <h3>Protection</h3>
            <div className="setting-item">
              <div className="setting-info">
                <div className="setting-label">Enable Protection</div>
                <div className="setting-description">
                  Turn SecureWeb protection on/off
                </div>
              </div>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={config.enabled}
                  onChange={toggleEnabled}
                />
                <span className="toggle-slider"></span>
              </label>
            </div>
          </div>

          <div className="section">
            <h3>Security Mode</h3>
            <div className="mode-selector">
              <button
                className={`mode-btn ${config.mode === "permissive" ? "active" : ""}`}
                onClick={() => changeMode("permissive")}>
                <div className="mode-icon">🟢</div>
                <div className="mode-label">Permissive</div>
                <div className="mode-desc">Only critical threats</div>
              </button>
              <button
                className={`mode-btn ${config.mode === "moderate" ? "active" : ""}`}
                onClick={() => changeMode("moderate")}>
                <div className="mode-icon">🟡</div>
                <div className="mode-label">Moderate</div>
                <div className="mode-desc">Balanced protection</div>
              </button>
              <button
                className={`mode-btn ${config.mode === "strict" ? "active" : ""}`}
                onClick={() => changeMode("strict")}>
                <div className="mode-icon">🔴</div>
                <div className="mode-label">Strict</div>
                <div className="mode-desc">Maximum security</div>
              </button>
            </div>
          </div>

          <div className="section">
            <h3>Whitelist</h3>
            <div className="whitelist-input">
              <input
                type="text"
                placeholder="Enter domain (e.g., example.com)"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && addToWhitelist()}
              />
              <button className="btn-primary" onClick={addToWhitelist}>
                Add
              </button>
            </div>
            {config.whitelist.length === 0 ? (
              <div className="empty-state-small">
                <p>No whitelisted domains</p>
              </div>
            ) : (
              <div className="whitelist-list">
                {config.whitelist.map((domain, idx) => (
                  <div key={idx} className="whitelist-item">
                    <span className="domain-name">{domain}</span>
                    <button
                      className="btn-remove"
                      onClick={() => removeFromWhitelist(domain)}>
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="section">
            <h3>About</h3>
            <div className="about-info">
              <div className="about-item">
                <span>Version</span>
                <span>0.1.0</span>
              </div>
              <div className="about-item">
                <span>Authors</span>
                <span>Subhan, Ahmed, Shameer</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default IndexPopup
