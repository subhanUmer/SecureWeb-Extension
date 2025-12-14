/**
 * Module 2.3: Website Behavior Monitor
 * Type definitions for anomaly detection in websites
 */

export interface WebsiteBehaviorProfile {
  domain: string;
  firstSeen: number;
  lastVisit: number;
  visitCount: number;
  baselineLocked: boolean;         // True after initial 5 visits - prevents baseline drift
  
  // Script behavior tracking
  scriptHashes: string[];              // SHA-256 of scripts seen
  scriptDomains: string[];             // External script sources
  scriptUrls?: string[];               // Full external script URLs seen (path-level granularity)
  inlineScriptCount: number;           // Average inline scripts
  
  // Network behavior tracking
  networkDomains: string[];            // Domains contacted
  apiEndpoints: string[];              // API URLs called
  averageRequestCount: number;
  
  // DOM behavior
  domModificationRate: number;         // DOM changes per second
  formSubmissions: string[];           // Form action URLs
  
  // Storage behavior
  cookieAccess: {
    read: number;
    write: number;
    delete: number;
  };
  localStorageKeys: string[];
  
  // Resource loading
  resourceTypes: Record<string, number>; // image, font, media, etc.
  
  // Calculated baselines
  baseline: {
    scriptCount: { mean: number; stdDev: number };
    requestCount: { mean: number; stdDev: number };
    domModRate: { mean: number; stdDev: number };
    updatedAt: number;
  };
}

export interface BehaviorAnomaly {
  type: 'website';
  targetId: string;               // domain
  targetName: string;
  detectedAt: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  indicators: AnomalyIndicator[];
  confidence: number;             // 0-1
  recommendation: 'monitor' | 'warn' | 'block';
}

export interface AnomalyIndicator {
  category: 'script' | 'network' | 'dom' | 'storage' | 'crypto' | 'keylogger';
  description: string;
  deviationScore: number;         // Standard deviations from baseline
  evidence: any;                  // Supporting data
}

export interface PageBehaviorData {
  scripts: Array<{
    type: 'external' | 'inline';
    src?: string;
    domain?: string;
    hash?: string;
    length?: number;
  }>;
  networkRequests: Array<{
    domain: string;
    type: string;
    url: string;
  }>;
  domModifications: number;
  storageAccess: {
    read: number;
    write: number;
    delete: number;
  };
  suspiciousAPIs: {
    hasWebGL: boolean;
    hasAudioContext: boolean;
    hasRTC: boolean;
    hasCrypto: boolean;
  };
}
