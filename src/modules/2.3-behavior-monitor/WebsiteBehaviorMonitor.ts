/**
 * Module 2.3: Website Behavior Monitor
 * Detects anomalous behavior in websites (compromised sites, injected malware, etc.)
 */

import type { 
  WebsiteBehaviorProfile, 
  BehaviorAnomaly, 
  AnomalyIndicator,
  PageBehaviorData 
} from './types';

export class WebsiteBehaviorMonitor {
  private profiles: Map<string, WebsiteBehaviorProfile> = new Map();
  private readonly MIN_VISITS_FOR_BASELINE = 5;
  private readonly ANOMALY_THRESHOLD = 2.5; // Standard deviations
  private initialized = false;
  
  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    if (this.initialized) return;
    
    await this.loadProfiles();
    this.initialized = true;
    console.log('[BehaviorMonitor] Initialized with', this.profiles.size, 'profiles');
  }

  /**
   * Called when page loads - analyze current behavior vs baseline
   */
  async analyzePageLoad(url: string, tabId: number): Promise<BehaviorAnomaly | null> {
    try {
      const domain = new URL(url).hostname;
      const profile = this.getOrCreateProfile(domain);
      
      // Collect current behavior
      const currentBehavior = await this.collectBehavior(tabId);
      
      if (!currentBehavior) {
        console.log('[BehaviorMonitor] Could not collect behavior for', domain);
        return null;
      }
      
      // Check for anomalies BEFORE updating profile (only if we have enough baseline data)
      let anomaly: BehaviorAnomaly | null = null;
      
      if (profile.visitCount >= this.MIN_VISITS_FOR_BASELINE) {
        console.log(`[BehaviorMonitor] 🔍 Checking for anomalies on ${domain} (visit ${profile.visitCount + 1})`);
        console.log(`[BehaviorMonitor] Current scripts:`, currentBehavior.scripts.length);
        console.log(`[BehaviorMonitor] Baseline scripts:`, profile.scriptDomains.length, 'domains,', profile.scriptHashes.length, 'hashes');
        anomaly = this.detectAnomalies(profile, currentBehavior);
      } else {
        console.log(`[BehaviorMonitor] Building baseline for ${domain} (${profile.visitCount + 1}/${this.MIN_VISITS_FOR_BASELINE})`);
      }
      
      // Update profile AFTER anomaly detection
      this.updateProfile(profile, currentBehavior);
      
      return anomaly;
    } catch (error) {
      console.error('[BehaviorMonitor] Error analyzing page:', error);
      return null;
    }
  }

  /**
   * Collect real-time behavior from a tab
   */
  private async collectBehavior(tabId: number): Promise<PageBehaviorData | null> {
    try {
      // Inject behavior collector script
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: collectPageBehaviorFunc,
      });
      
      return results[0]?.result || null;
    } catch (error: any) {
      // Silently ignore common errors that don't affect functionality
      const errorMessage = error?.message || String(error);
      
      // These are expected errors and don't need to be logged
      if (
        errorMessage.includes('error page') ||
        errorMessage.includes('Cannot access') ||
        errorMessage.includes('Extensions cannot') ||
        errorMessage.includes('chrome://') ||
        errorMessage.includes('chrome-extension://')
      ) {
        return null;
      }
      
      // Log unexpected errors
      console.error('[BehaviorMonitor] Error collecting behavior:', error);
      return null;
    }
  }

  /**
   * Update profile with new behavioral data
   * Only updates baseline during initial learning phase (first 5 visits)
   */
  private updateProfile(profile: WebsiteBehaviorProfile, behavior: PageBehaviorData): void {
    profile.lastVisit = Date.now();
    profile.visitCount++;

    // Lock baseline after initial learning phase
    if (profile.visitCount >= this.MIN_VISITS_FOR_BASELINE && !profile.baselineLocked) {
      profile.baselineLocked = true;
      console.log(`[BehaviorMonitor] 🔒 Baseline locked for ${profile.domain} - learned normal behavior`);
    }

    // Only update baseline during learning phase (NOT locked)
    if (!profile.baselineLocked) {
      // Update script tracking
      behavior.scripts.forEach((script) => {
        if (script.type === 'external' && script.domain) {
          if (!profile.scriptDomains.includes(script.domain)) {
            profile.scriptDomains.push(script.domain);
          }
          // Track full script URLs for finer-grained detection (path-level)
          if (script.src) {
            if (!profile.scriptUrls) profile.scriptUrls = []
            if (!profile.scriptUrls.includes(script.src)) {
              profile.scriptUrls.push(script.src)
            }
          }
        } else if (script.type === 'inline' && script.hash) {
          if (!profile.scriptHashes.includes(script.hash)) {
            profile.scriptHashes.push(script.hash);
          }
        }
      });

      // Update network tracking
      behavior.networkRequests.forEach((req) => {
        if (!profile.networkDomains.includes(req.domain)) {
          profile.networkDomains.push(req.domain);
        }
      });

      // Calculate running averages using exponential moving average
      const alpha = 0.3; // Smoothing factor
      const newScriptCount = behavior.scripts.length;
      const newRequestCount = behavior.networkRequests.length;
      
      if (!profile.baseline.scriptCount.mean) {
        profile.baseline.scriptCount.mean = newScriptCount;
        profile.baseline.requestCount.mean = newRequestCount;
      } else {
        profile.baseline.scriptCount.mean = 
          alpha * newScriptCount + (1 - alpha) * profile.baseline.scriptCount.mean;
        profile.baseline.requestCount.mean = 
          alpha * newRequestCount + (1 - alpha) * profile.baseline.requestCount.mean;
      }

      // Update standard deviations
  // Update standard deviations with floor to avoid near-zero causing huge z-scores
  const rawScriptStd = Math.sqrt(Math.abs(newScriptCount - profile.baseline.scriptCount.mean));
  const rawRequestStd = Math.sqrt(Math.abs(newRequestCount - profile.baseline.requestCount.mean));
  profile.baseline.scriptCount.stdDev = Math.max(rawScriptStd, 0.5);
  profile.baseline.requestCount.stdDev = Math.max(rawRequestStd, 0.5);

      profile.baseline.updatedAt = Date.now();
    }

    // Always save to storage (to update visitCount and lastVisit)
    this.saveProfile(profile);
  }

  /**
   * Detect anomalies by comparing current behavior to baseline
   */
  private detectAnomalies(
    profile: WebsiteBehaviorProfile,
    currentBehavior: PageBehaviorData
  ): BehaviorAnomaly | null {
    const indicators: AnomalyIndicator[] = [];

    console.log(`[BehaviorMonitor] 🔎 Detecting anomalies for ${profile.domain}...`);

    // 1. Check for new scripts
    const newScripts = currentBehavior.scripts.filter((script) => {
      if (script.type === 'external') {
        // Detect new by URL if available, fallback to domain
        if (script.src && profile.scriptUrls && profile.scriptUrls.length > 0) {
          return !profile.scriptUrls.includes(script.src)
        }
        if (script.domain) {
          return !profile.scriptDomains.includes(script.domain)
        }
      } else if (script.type === 'inline' && script.hash) {
        return !profile.scriptHashes.includes(script.hash);
      }
      return false;
    });

    console.log(`[BehaviorMonitor]   - New scripts found: ${newScripts.length}`);
    if (newScripts.length > 0) {
      console.log(`[BehaviorMonitor]   - New script details:`, newScripts.map(s => s.src || `inline-${s.hash?.substring(0, 8)}`));
      indicators.push({
        category: 'script',
        description: `${newScripts.length} new script(s) detected that were not seen before`,
        deviationScore: newScripts.length * 2, // Higher weight for new scripts
        evidence: newScripts.map((s) => {
          if (s.src) return s.src;
          if (s.hash) return `inline-${s.hash.substring(0, 8)}`;
          return 'inline-unknown';
        }),
      });
    }

    // 2. Check for new network domains
    const newDomains = currentBehavior.networkRequests
      .filter((req) => !profile.networkDomains.includes(req.domain))
      .map((req) => req.domain);

    console.log(`[BehaviorMonitor]   - New domains found: ${newDomains.length}`);
    if (newDomains.length > 0) {
      const uniqueDomains = [...new Set(newDomains)];
      console.log(`[BehaviorMonitor]   - New domain details:`, uniqueDomains);
      indicators.push({
        category: 'network',
        description: `Contacting ${uniqueDomains.length} new domain(s)`,
        deviationScore: uniqueDomains.length,
        evidence: uniqueDomains,
      });
    }

    // 3. Check statistical deviations
    const scriptCount = currentBehavior.scripts.length;
    let scriptDeviation = Math.abs(
      (scriptCount - profile.baseline.scriptCount.mean) /
      (profile.baseline.scriptCount.stdDev || 1)
    );
    // Cap deviation to avoid absurd scores due to any residual edge cases
    scriptDeviation = Math.min(scriptDeviation, 10);

    if (scriptDeviation > this.ANOMALY_THRESHOLD) {
      indicators.push({
        category: 'script',
        description: `Abnormal script count: ${scriptCount} (expected ~${Math.round(profile.baseline.scriptCount.mean)})`,
        deviationScore: scriptDeviation,
        evidence: { current: scriptCount, baseline: profile.baseline.scriptCount.mean },
      });
    }

    // 4. Check for cryptocurrency mining indicators
    if (this.detectCryptoMining(currentBehavior)) {
      indicators.push({
        category: 'crypto',
        description: 'Cryptocurrency mining activity detected',
        deviationScore: 10, // High severity
        evidence: 'WebGL + suspicious script patterns',
      });
    }

    // 5. Check for suspicious API usage patterns (ONLY if other anomalies exist)
    // WebRTC and AudioContext are normal, only suspicious with other red flags
    if (indicators.length > 0) {
      const suspiciousAPIs = this.detectSuspiciousAPIs(currentBehavior);
      if (suspiciousAPIs.length > 0) {
        indicators.push({
          category: 'script',
          description: `Suspicious API usage: ${suspiciousAPIs.join(', ')}`,
          deviationScore: suspiciousAPIs.length * 1, // Lower score - supplementary indicator
          evidence: suspiciousAPIs,
        });
      }
    }

    // No anomalies found
    if (indicators.length === 0) {
      console.log(`[BehaviorMonitor]   ✅ No anomalies detected`);
      return null;
    }

    // Calculate overall confidence and severity
    const maxDeviation = Math.max(...indicators.map((i) => i.deviationScore));
    const severity = this.calculateSeverity(indicators);
    const confidence = Math.min(maxDeviation / 10, 1.0);

    console.log(`[BehaviorMonitor] ⚠️ Anomaly detected on ${profile.domain}:`, {
      severity,
      indicators: indicators.length,
      confidence,
      indicatorDetails: indicators.map(i => ({ category: i.category, score: i.deviationScore }))
    });

    return {
      type: 'website',
      targetId: profile.domain,
      targetName: profile.domain,
      detectedAt: Date.now(),
      severity,
      indicators,
      confidence,
      recommendation: severity === 'critical' ? 'block' : severity === 'high' ? 'warn' : 'monitor',
    };
  }

  /**
   * Detect cryptocurrency mining patterns
   */
  private detectCryptoMining(behavior: PageBehaviorData): boolean {
    const indicators: string[] = [];

    // WebGL is used for GPU mining
    if (behavior.suspiciousAPIs?.hasWebGL) {
      indicators.push('webgl');
    }
    
    // Check for known mining script patterns
    const hasMiningScript = behavior.scripts.some((script) => 
      script.src && (
        script.src.includes('coinhive') ||
        script.src.includes('coin-hive') ||
        script.src.includes('cryptoloot') ||
        script.src.includes('jsecoin') ||
        script.src.includes('crypto-loot')
      )
    );
    if (hasMiningScript) {
      indicators.push('known-miner-script');
    }

    // Check for mining domains in network requests
    const miningDomains = ['coinhive', 'coin-hive', 'cryptoloot', 'jsecoin', 'crypto-loot'];
    const hasMiningDomain = behavior.networkRequests.some((req) =>
      miningDomains.some((md) => req.domain.includes(md))
    );
    if (hasMiningDomain) {
      indicators.push('known-miner-domain');
    }

    // WebSocket connections are often used for mining pools
    const hasWebSocket = behavior.networkRequests.some((req) => 
      req.url.startsWith('ws://') || req.url.startsWith('wss://')
    );
    if (hasWebSocket && behavior.suspiciousAPIs?.hasWebGL) {
      indicators.push('websocket-webgl-combo');
    }

    return indicators.length >= 2;
  }

  /**
   * Detect suspicious API usage
   */
  private detectSuspiciousAPIs(behavior: PageBehaviorData): string[] {
    const suspicious: string[] = [];

    // WebRTC can be used for IP leaking
    if (behavior.suspiciousAPIs?.hasRTC) {
      suspicious.push('WebRTC');
    }

    // Audio context without user interaction is suspicious
    if (behavior.suspiciousAPIs?.hasAudioContext) {
      suspicious.push('AudioContext');
    }

    // Crypto API used excessively
    if (behavior.suspiciousAPIs?.hasCrypto) {
      // This is actually normal, only flag if combined with other factors
    }

    return suspicious;
  }

  /**
   * Calculate severity based on indicators
   */
  private calculateSeverity(indicators: AnomalyIndicator[]): 'low' | 'medium' | 'high' | 'critical' {
    const maxDeviation = Math.max(...indicators.map((i) => i.deviationScore));
    const criticalCategories = indicators.filter((i) => 
      i.category === 'crypto' || i.category === 'keylogger'
    );

    if (criticalCategories.length > 0) return 'critical';
    if (maxDeviation > 5) return 'high';
    if (maxDeviation > 3) return 'medium';
    return 'low';
  }

  /**
   * Get or create profile for a domain
   */
  private getOrCreateProfile(domain: string): WebsiteBehaviorProfile {
    if (!this.profiles.has(domain)) {
      const profile: WebsiteBehaviorProfile = {
        domain,
        firstSeen: Date.now(),
        lastVisit: Date.now(),
        visitCount: 0,
        baselineLocked: false,        // Baseline unlocked initially
        scriptHashes: [],
        scriptDomains: [],
        inlineScriptCount: 0,
        networkDomains: [],
        apiEndpoints: [],
        averageRequestCount: 0,
        domModificationRate: 0,
        formSubmissions: [],
        cookieAccess: { read: 0, write: 0, delete: 0 },
        localStorageKeys: [],
        resourceTypes: {},
        baseline: {
          scriptCount: { mean: 0, stdDev: 0 },
          requestCount: { mean: 0, stdDev: 0 },
          domModRate: { mean: 0, stdDev: 0 },
          updatedAt: 0,
        },
      };
      this.profiles.set(domain, profile);
    }
    return this.profiles.get(domain)!;
  }

  /**
   * Persist profile to storage
   */
  private async saveProfile(profile: WebsiteBehaviorProfile): Promise<void> {
    try {
      await chrome.storage.local.set({
        [`behavior_profile_${profile.domain}`]: profile,
      });
    } catch (error) {
      console.error('[BehaviorMonitor] Error saving profile:', error);
    }
  }

  /**
   * Load all profiles from storage
   */
  private async loadProfiles(): Promise<void> {
    try {
      chrome.storage.local.get(null, (stored) => {
        if (stored && Object.keys(stored).length > 0) {
          Object.entries(stored).forEach(([key, value]) => {
            if (key.startsWith('behavior_profile_')) {
              const profile = value as WebsiteBehaviorProfile;
              this.profiles.set(profile.domain, profile);
            }
          });
          console.log('[BehaviorMonitor] Loaded', this.profiles.size, 'profiles from storage');
        }
      });
    } catch (error) {
      console.error('[BehaviorMonitor] Error loading profiles:', error);
    }
  }

  /**
   * Clear old profiles (>90 days inactive)
   */
  async cleanupOldProfiles(): Promise<void> {
    const now = Date.now();
    const maxAge = 90 * 24 * 60 * 60 * 1000; // 90 days
    let removed = 0;

    for (const [domain, profile] of this.profiles) {
      if (now - profile.lastVisit > maxAge) {
        this.profiles.delete(domain);
        await chrome.storage.local.remove(`behavior_profile_${domain}`);
        removed++;
      }
    }

    if (removed > 0) {
      console.log(`[BehaviorMonitor] Cleaned up ${removed} old profiles`);
    }
  }
}

/**
 * Function that runs in page context to collect behavioral data
 * This gets injected via chrome.scripting.executeScript
 */
function collectPageBehaviorFunc(): PageBehaviorData {
  const behavior: PageBehaviorData = {
    scripts: [],
    networkRequests: [],
    domModifications: 0,
    storageAccess: { read: 0, write: 0, delete: 0 },
    suspiciousAPIs: {
      hasWebGL: false,
      hasAudioContext: false,
      hasRTC: false,
      hasCrypto: false,
    },
  };

  // Simple hash function (for inline scripts)
  function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  try {
    // 1. Analyze all scripts
    const scripts = document.querySelectorAll('script');
    scripts.forEach((script) => {
      if (script.src) {
        // External script
        try {
          // Resolve relative URLs against document.baseURI
          const url = new URL(script.getAttribute('src')!, document.baseURI);
          behavior.scripts.push({
            type: 'external',
            src: url.href,
            domain: url.hostname,
          });
        } catch (e) {
          // Invalid URL
        }
      } else if (script.textContent && script.textContent.trim()) {
        // Inline script - hash it
        behavior.scripts.push({
          type: 'inline',
          hash: simpleHash(script.textContent),
          length: script.textContent.length,
        });
      }
    });

    // 2. Monitor network requests (via Performance API)
    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
    resources.forEach((resource) => {
      try {
        const url = new URL(resource.name, document.baseURI);
        behavior.networkRequests.push({
          domain: url.hostname,
          type: resource.initiatorType,
          url: url.href,
        });
      } catch (e) {
        // Invalid URL
      }
    });

    // 3. Check for suspicious APIs
    behavior.suspiciousAPIs.hasWebGL = (() => {
      try {
        const canvas = document.createElement('canvas');
        return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
      } catch (e) {
        return false;
      }
    })();

    behavior.suspiciousAPIs.hasAudioContext = typeof AudioContext !== 'undefined' || 
                                               typeof (window as any).webkitAudioContext !== 'undefined';
    
    behavior.suspiciousAPIs.hasRTC = typeof RTCPeerConnection !== 'undefined';
    
    behavior.suspiciousAPIs.hasCrypto = typeof crypto !== 'undefined' && 
                                         typeof crypto.subtle !== 'undefined';

  } catch (error) {
    console.error('[BehaviorCollector] Error:', error);
  }

  return behavior;
}
