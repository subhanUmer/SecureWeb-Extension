import { SUSPICIOUS_PATTERNS } from "./patterns";
import type {
  BlockedScript,
  JSControllerConfig,
  ScriptAnalysisResult,
  SuspiciousPattern,
} from "./types";

/**
 * JavaScript Controller
 * Analyzes and blocks malicious JavaScript patterns
 */
export class JSController {
  private config: JSControllerConfig;
  private blockedScripts: BlockedScript[] = [];

  constructor(config?: Partial<JSControllerConfig>) {
    this.config = {
      enabled: true,
      mode: "moderate",
      whitelist: ["google.com", "youtube.com", "github.com"],
      patterns: SUSPICIOUS_PATTERNS,
      ...config,
    };
  }

  /**
   * Update controller configuration
   */
  updateConfig(config: Partial<JSControllerConfig>): void {
    this.config = { ...this.config, ...config };
    console.log("[JSController] Config updated:", this.config);
  }

  /**
   * Check if domain is whitelisted
   */
  private isWhitelisted(url: string): boolean {
    try {
      const hostname = new URL(url).hostname;
      return this.config.whitelist.some((domain) => hostname.includes(domain));
    } catch (error) {
      return false;
    }
  }

  /**
   * Analyze script content for suspicious patterns
   */
  analyzeScript(
    scriptContent: string,
    scriptUrl: string = "inline"
  ): ScriptAnalysisResult {
    // Skip if controller is disabled
    if (!this.config.enabled) {
      return {
        isSuspicious: false,
        matchedPatterns: [],
        shouldBlock: false,
        confidence: 0,
      };
    }

    // Skip whitelisted domains
    if (this.isWhitelisted(scriptUrl)) {
      console.log(`[JSController] Whitelisted: ${scriptUrl}`);
      return {
        isSuspicious: false,
        matchedPatterns: [],
        shouldBlock: false,
        confidence: 0,
      };
    }

    const matchedPatterns: SuspiciousPattern[] = [];

    // Check against all patterns
    for (const pattern of this.config.patterns) {
      if (pattern.pattern.test(scriptContent)) {
        matchedPatterns.push(pattern);
        console.log(
          `[JSController] ⚠️ Pattern matched: ${pattern.name} in ${scriptUrl}`
        );
      }
    }

    if (matchedPatterns.length === 0) {
      return {
        isSuspicious: false,
        matchedPatterns: [],
        shouldBlock: false,
        confidence: 0,
      };
    }

    // Calculate confidence based on severity and number of matches
    const confidence = this.calculateConfidence(matchedPatterns);

    // Determine if should block based on mode and confidence
    const shouldBlock = this.shouldBlockScript(matchedPatterns, confidence);

    return {
      isSuspicious: true,
      matchedPatterns,
      shouldBlock,
      confidence,
    };
  }

  /**
   * Calculate confidence score based on matched patterns
   */
  private calculateConfidence(patterns: SuspiciousPattern[]): number {
    const severityScores = {
      low: 0.25,
      medium: 0.5,
      high: 0.75,
      critical: 1.0,
    };

    if (patterns.length === 0) return 0;

    // Get highest severity score
    const maxScore = Math.max(
      ...patterns.map((p) => severityScores[p.severity])
    );

    // Add bonus for multiple matches (but cap at 1.0)
    const bonus = Math.min(patterns.length * 0.1, 0.3);

    return Math.min(maxScore + bonus, 1.0);
  }

  /**
   * Determine if script should be blocked based on mode and patterns
   */
  private shouldBlockScript(
    patterns: SuspiciousPattern[],
    confidence: number
  ): boolean {
    const { mode } = this.config;

    // Get highest severity
    const hasCritical = patterns.some((p) => p.severity === "critical");
    const hasHigh = patterns.some((p) => p.severity === "high");
    const hasMedium = patterns.some((p) => p.severity === "medium");

    switch (mode) {
      case "strict":
        // Block everything suspicious
        return patterns.length > 0;

      case "moderate":
        // Block high and critical threats
        return hasCritical || hasHigh;

      case "permissive":
        // Only block critical threats
        return hasCritical;

      default:
        return false;
    }
  }

  /**
   * Record a blocked script
   */
  recordBlockedScript(
    url: string,
    content: string,
    matchedPatterns: SuspiciousPattern[]
  ): BlockedScript {
    const blocked: BlockedScript = {
      url,
      reason: matchedPatterns.map((p) => p.name).join(", "),
      pattern: matchedPatterns[0]?.id || "unknown",
      timestamp: Date.now(),
      content: content.substring(0, 100) + "...",
      severity: matchedPatterns[0]?.severity || "medium",
    };

    this.blockedScripts.push(blocked);

    // Keep only last 100 blocked scripts
    if (this.blockedScripts.length > 100) {
      this.blockedScripts.shift();
    }

    console.log(`[JSController] 🚫 Blocked script from ${url}`);
    return blocked;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      totalBlocked: this.blockedScripts.length,
      recentBlocks: this.blockedScripts.slice(-10).reverse(),
      severityCounts: {
        critical: this.blockedScripts.filter((s) => s.severity === "critical")
          .length,
        high: this.blockedScripts.filter((s) => s.severity === "high").length,
        medium: this.blockedScripts.filter((s) => s.severity === "medium")
          .length,
        low: this.blockedScripts.filter((s) => s.severity === "low").length,
      },
    };
  }

  /**
   * Clear blocked scripts history
   */
  clearHistory(): void {
    this.blockedScripts = [];
    console.log("[JSController] History cleared");
  }

  /**
   * Get current configuration
   */
  getConfig(): JSControllerConfig {
    return { ...this.config };
  }
}

// Export singleton instance
export const jsController = new JSController();
