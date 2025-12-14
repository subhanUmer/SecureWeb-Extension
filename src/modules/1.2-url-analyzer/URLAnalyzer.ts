// Main Analyzer Class
import { analyzeURLHeuristics, calculateThreatScore } from "./heuristics"
import type {
  AnalyzerStats,
  ThreatIndicator,
  URLAnalysisResult,
  URLAnalyzerConfig
} from "./types"

export class URLAnalyzer {
  private cache: Map<string, CachedResult> = new Map()
  private config: URLAnalyzerConfig
  private stats: AnalyzerStats

  constructor() {
    this.config = {
      cacheEnabled: true,
      cacheTTL: 3600000,
      blockThreshold: 0.7,
      sensitivityLevel: "medium"
    }
    this.stats = {
      totalAnalyzed: 0,
      safeCount: 0,
      suspiciousCount: 0,
      maliciousCount: 0,
      cacheHits: 0,
      cacheMisses: 0,
      averageAnalysisTime: 0
    }
  }

  async analyzeURL(url: string): Promise<URLAnalysisResult> {
    const start = performance.now()
    if (this.config.cacheEnabled) {
      const cached = this.getCached(url)
      if (cached) {
        this.stats.cacheHits++
        return cached
      }
      this.stats.cacheMisses++
    }

    const normalized = this.normalizeURL(url)
    const quickSafe = this.quickSafetyCheck(normalized)
    if (quickSafe) {
      const result = this.createSafeResult(
        normalized,
        "Passed quick safety checks"
      )
      this.updateStats(result, start)
      if (this.config.cacheEnabled) this.setCached(normalized, result)
      return result
    }

    const indicators = analyzeURLHeuristics(normalized)
    const score = calculateThreatScore(indicators)
    const adjusted = this.adjustScoreBySensitivity(score)
    const verdict = this.determineVerdict(adjusted, indicators)
    const reason = this.generateReason(verdict, indicators)

    const result: URLAnalysisResult = {
      url: normalized,
      verdict,
      confidence: adjusted,
      reason,
      indicators,
      timestamp: Date.now()
    }
    this.updateStats(result, start)
    if (this.config.cacheEnabled) this.setCached(normalized, result)
    return result
  }

  private createSafeResult(url: string, reason: string): URLAnalysisResult {
    return {
      url,
      verdict: "safe",
      confidence: 0.0,
      reason,
      indicators: [],
      timestamp: Date.now()
    }
  }

  private normalizeURL(url: string): string {
    try {
      const u = new URL(url)
      let normalized = u.href.replace(/\/$/, "")
      const parts = normalized.split("://")
      if (parts.length === 2) {
        const [protocol, rest] = parts
        const [domain, ...pathParts] = rest.split("/")
        normalized = `${protocol}://${domain.toLowerCase()}${pathParts.length ? "/" + pathParts.join("/") : ""}`
      }
      return normalized
    } catch {
      return url.toLowerCase()
    }
  }

  private quickSafetyCheck(url: string): boolean {
    try {
      const u = new URL(url)
      const h = u.hostname.toLowerCase()
      const knownSafe = [
        "google.com",
        "www.google.com",
        "youtube.com",
        "www.youtube.com",
        "facebook.com",
        "www.facebook.com",
        "github.com",
        "www.github.com",
        "stackoverflow.com",
        "www.stackoverflow.com",
        "wikipedia.org",
        "en.wikipedia.org",
        "reddit.com",
        "www.reddit.com",
        "twitter.com",
        "www.twitter.com",
        "amazon.com",
        "www.amazon.com",
        "microsoft.com",
        "www.microsoft.com",
        "apple.com",
        "www.apple.com",
        "linkedin.com",
        "www.linkedin.com"
      ]
      if (knownSafe.includes(h)) return true
      for (const safe of knownSafe) if (h.endsWith(`.${safe}`)) return true
      return false
    } catch {
      return false
    }
  }

  private adjustScoreBySensitivity(score: number): number {
    switch (this.config.sensitivityLevel) {
      case "low":
        return score * 0.8
      case "high":
        return Math.min(score * 1.2, 1)
      default:
        return score
    }
  }

  private determineVerdict(
    score: number,
    indicators: ThreatIndicator[]
  ): "safe" | "suspicious" | "malicious" {
    const hasCritical = indicators.some((i) => i.severity === "critical")
    if (hasCritical) return "malicious"
    const highs = indicators.filter((i) => i.severity === "high").length
    if (highs >= 2) return "malicious"
    if (score >= this.config.blockThreshold) return "malicious"
    if (score >= 0.4) return "suspicious"
    return "safe"
  }

  private generateReason(
    verdict: "safe" | "suspicious" | "malicious",
    indicators: ThreatIndicator[]
  ): string {
    if (verdict === "safe") return "No suspicious patterns detected"
    if (indicators.length === 0) return "Suspicious characteristics detected"
    const order = { critical: 4, high: 3, medium: 2, low: 1 } as const
    const top = [...indicators]
      .sort((a, b) => order[b.severity] - order[a.severity])
      .slice(0, 3)
      .map((i) => i.description)
    if (top.length === 1) return top[0]
    if (top.length === 2) return `${top[0]} and ${top[1].toLowerCase()}`
    return `${top[0]}, ${top[1].toLowerCase()}, and ${top[2].toLowerCase()}`
  }

  private updateStats(result: URLAnalysisResult, start: number) {
    this.stats.totalAnalyzed++
    if (result.verdict === "safe") this.stats.safeCount++
    else if (result.verdict === "suspicious") this.stats.suspiciousCount++
    else this.stats.maliciousCount++
    const t = performance.now() - start
    this.stats.averageAnalysisTime =
      (this.stats.averageAnalysisTime * (this.stats.totalAnalyzed - 1) + t) /
      this.stats.totalAnalyzed
  }

  private getCached(url: string): URLAnalysisResult | null {
    const c = this.cache.get(url)
    if (!c) return null
    if (Date.now() - c.timestamp > this.config.cacheTTL) {
      this.cache.delete(url)
      return null
    }
    return c.result
  }

  private setCached(url: string, result: URLAnalysisResult): void {
    if (this.cache.size >= 1000) {
      const firstKey = this.cache.keys().next().value
      if (firstKey !== undefined) this.cache.delete(firstKey)
    }
    this.cache.set(url, { result, timestamp: Date.now() })
  }

  getStats(): AnalyzerStats {
    return { ...this.stats }
  }
  updateConfig(newConfig: Partial<URLAnalyzerConfig>) {
    this.config = { ...this.config, ...newConfig }
  }
  getConfig(): URLAnalyzerConfig {
    return { ...this.config }
  }
  resetStats() {
    this.stats = {
      totalAnalyzed: 0,
      safeCount: 0,
      suspiciousCount: 0,
      maliciousCount: 0,
      cacheHits: 0,
      cacheMisses: 0,
      averageAnalysisTime: 0
    }
  }
}

interface CachedResult {
  result: URLAnalysisResult
  timestamp: number
}

export const urlAnalyzer = new URLAnalyzer()
