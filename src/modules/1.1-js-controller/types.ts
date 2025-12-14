/**
 * Type definitions for JavaScript Controller Module
 */

export interface BlockedScript {
  url: string;
  reason: string;
  pattern: string;
  timestamp: number;
  content?: string; // First 100 chars of script
  severity: "low" | "medium" | "high" | "critical";
}

export interface JSControllerConfig {
  enabled: boolean;
  mode: "strict" | "moderate" | "permissive";
  whitelist: string[];
  patterns: SuspiciousPattern[];
}

export interface SuspiciousPattern {
  id: string;
  name: string;
  pattern: RegExp;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  category: "cryptomining" | "injection" | "obfuscation" | "malware" | "tracking";
}

export interface ScriptAnalysisResult {
  isSuspicious: boolean;
  matchedPatterns: SuspiciousPattern[];
  shouldBlock: boolean;
  confidence: number;
}
