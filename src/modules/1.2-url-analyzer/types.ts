// TypeScript Interfaces

export interface URLAnalysisResult {
  url: string
  verdict: "safe" | "suspicious" | "malicious"
  confidence: number // 0.0 - 1.0
  reason: string // Human-readable explanation
  indicators: ThreatIndicator[] // What patterns we found
  timestamp: number
}

export interface ThreatIndicator {
  type: IndicatorType
  severity: "low" | "medium" | "high" | "critical"
  description: string
  value?: string
}

export type IndicatorType =
  | "ip_address"
  | "suspicious_tld"
  | "excessive_subdomains"
  | "typosquatting"
  | "suspicious_path"
  | "suspicious_params"
  | "homograph_attack"
  | "url_shortener"
  | "suspicious_port"
  | "suspicious_keywords"
  | "excessive_dashes"

export interface URLAnalyzerConfig {
  cacheEnabled: boolean
  cacheTTL: number
  blockThreshold: number
  sensitivityLevel: "low" | "medium" | "high"
}

export interface AnalyzerStats {
  totalAnalyzed: number
  safeCount: number
  suspiciousCount: number
  maliciousCount: number
  cacheHits: number
  cacheMisses: number
  averageAnalysisTime: number
}
