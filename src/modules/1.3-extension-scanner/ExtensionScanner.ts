/**
 * Module 1.3: Extension Scanner & Monitor
 * Detects anomalous behavior in browser extensions (permission changes, code updates, etc.)
 */

import type { ExtensionProfile, ExtensionAnomaly, ExtensionChange } from './types';

export class ExtensionScanner {
  private profiles: Map<string, ExtensionProfile> = new Map();
  private initialized = false;
  
  private readonly RISKY_PERMISSIONS = [
    'cookies',
    'webRequest',
    'webRequestBlocking',
    'proxy',
    'debugger',
    'management',
    'nativeMessaging',
    'desktopCapture',
    'tabCapture',
  ];

  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    if (this.initialized) return;
    
    await this.loadProfiles();
    await this.scanAllExtensions();
    
    // Monitor extension changes
    chrome.management.onInstalled.addListener((ext) => this.onExtensionInstalled(ext));
    chrome.management.onUninstalled.addListener((id) => this.onExtensionUninstalled(id));
    chrome.management.onEnabled.addListener((ext) => this.onExtensionEnabled(ext));
    
    // Periodic re-scan every 6 hours
    setInterval(() => this.scanAllExtensions(), 6 * 60 * 60 * 1000);
    
    this.initialized = true;
    console.log('[ExtensionScanner] Initialized, monitoring', this.profiles.size, 'extensions');
  }

  /**
   * Scan all installed extensions
   */
  async scanAllExtensions(): Promise<ExtensionAnomaly[]> {
    const anomalies: ExtensionAnomaly[] = [];

    try {
      const extensions = await chrome.management.getAll();
      
      for (const ext of extensions) {
        // Skip our own extension
        if (ext.id === chrome.runtime.id) continue;
        
        // Skip Chrome system extensions and themes
        if (ext.type === 'theme') continue;

        const anomaly = await this.scanExtension(ext);
        if (anomaly) {
          anomalies.push(anomaly);
        }
      }
    } catch (error) {
      console.error('[ExtensionScanner] Error scanning extensions:', error);
    }

    return anomalies;
  }

  /**
   * Scan a single extension for anomalies
   */
  async scanExtension(ext: chrome.management.ExtensionInfo): Promise<ExtensionAnomaly | null> {
    const profile = this.getOrCreateProfile(ext);
    const changes: ExtensionChange[] = [];

    // 1. Check for permission changes
    const currentPermissions = ext.permissions || [];
    const newPermissions = currentPermissions.filter((p) => !profile.permissions.includes(p));
    const removedPermissions = profile.permissions.filter((p) => !currentPermissions.includes(p));

    if (newPermissions.length > 0) {
      changes.push({
        type: 'permission',
        description: `Requested ${newPermissions.length} new permission(s): ${newPermissions.join(', ')}`,
        oldValue: profile.permissions,
        newValue: currentPermissions,
        riskLevel: this.calculatePermissionRisk(newPermissions),
      });
    }

    // 2. Check for version changes (possible code update)
    if (profile.version && ext.version !== profile.version) {
      changes.push({
        type: 'code',
        description: `Extension updated from v${profile.version} to v${ext.version}`,
        oldValue: profile.version,
        newValue: ext.version,
        riskLevel: 3, // Medium risk - need to verify new code
      });
    }

    // 3. Check host permissions (which websites can access)
    const currentHosts = ext.hostPermissions || [];
    const newHosts = currentHosts.filter((h) => !profile.hostPermissions.includes(h));

    if (newHosts.length > 0) {
      const hasAllUrls = newHosts.includes('<all_urls>');
      changes.push({
        type: 'permission',
        description: `Can now access ${newHosts.length} new website(s): ${newHosts.join(', ')}`,
        oldValue: profile.hostPermissions,
        newValue: currentHosts,
        riskLevel: hasAllUrls ? 10 : 5,
      });
    }

    // 4. Calculate current risk score
    const currentRiskScore = this.calculateRiskScore(ext);
    if (currentRiskScore > profile.riskScore + 20) {
      changes.push({
        type: 'behavior',
        description: `Risk score increased significantly: ${profile.riskScore} → ${currentRiskScore}`,
        oldValue: profile.riskScore,
        newValue: currentRiskScore,
        riskLevel: 8,
      });
    }

    // Update profile
    this.updateProfile(profile, ext);

    // No changes detected
    if (changes.length === 0) {
      return null;
    }

    // Calculate severity
    const maxRisk = Math.max(...changes.map((c) => c.riskLevel));
    const severity = this.calculateSeverity(maxRisk);

    console.log(`[ExtensionScanner] ⚠️ Anomaly detected in ${ext.name}:`, {
      severity,
      changes: changes.length,
      maxRisk,
    });

    return {
      type: 'extension',
      extensionId: ext.id,
      extensionName: ext.name,
      targetId: ext.id,
      targetName: ext.name,
      detectedAt: Date.now(),
      severity,
      changes,
      confidence: Math.min(maxRisk / 10, 1.0),
      recommendation: this.getRecommendation(severity, changes),
    };
  }

  /**
   * Calculate risk score for an extension
   */
  private calculateRiskScore(ext: chrome.management.ExtensionInfo): number {
    let score = 0;

    // Check for risky permissions
    const permissions = ext.permissions || [];
    permissions.forEach((perm) => {
      if (this.RISKY_PERMISSIONS.includes(perm)) {
        score += 20;
      }
    });

    // All URLs access
    const hostPermissions = ext.hostPermissions || [];
    if (hostPermissions.includes('<all_urls>')) {
      score += 30;
    }

    // Lots of host permissions
    if (hostPermissions.length > 10) {
      score += 15;
    }

    // Check if extension is from Chrome Web Store
    if (!ext.updateUrl || !ext.updateUrl.includes('clients2.google.com')) {
      score += 25; // Not from official store (side-loaded)
    }

    // Remotely hosted code (very risky)
    if (permissions.includes('webRequest') && permissions.includes('tabs')) {
      score += 20; // Can intercept all traffic
    }

    return Math.min(score, 100);
  }

  /**
   * Calculate risk level of new permissions
   */
  private calculatePermissionRisk(permissions: string[]): number {
    let risk = 0;
    
    permissions.forEach((perm) => {
      if (this.RISKY_PERMISSIONS.includes(perm)) {
        risk += 3;
      } else {
        risk += 1;
      }
    });

    return Math.min(risk, 10);
  }

  /**
   * Calculate severity from max risk level
   */
  private calculateSeverity(maxRisk: number): 'low' | 'medium' | 'high' | 'critical' {
    if (maxRisk >= 9) return 'critical';
    if (maxRisk >= 7) return 'high';
    if (maxRisk >= 4) return 'medium';
    return 'low';
  }

  /**
   * Get recommendation based on severity and changes
   */
  private getRecommendation(
    severity: 'low' | 'medium' | 'high' | 'critical',
    changes: ExtensionChange[]
  ): 'monitor' | 'warn' | 'disable' | 'uninstall' {
    const hasPermissionChanges = changes.some((c) => c.type === 'permission');
    const hasCriticalPermissions = changes.some((c) => c.riskLevel >= 9);

    if (severity === 'critical' || hasCriticalPermissions) {
      return 'uninstall';
    }
    if (severity === 'high') {
      return hasPermissionChanges ? 'disable' : 'warn';
    }
    if (severity === 'medium') {
      return 'warn';
    }
    return 'monitor';
  }

  /**
   * Get or create profile for extension
   */
  private getOrCreateProfile(ext: chrome.management.ExtensionInfo): ExtensionProfile {
    if (!this.profiles.has(ext.id)) {
      const profile: ExtensionProfile = {
        id: ext.id,
        name: ext.name,
        version: ext.version,
        firstSeen: Date.now(),
        lastChecked: Date.now(),
        permissions: ext.permissions || [],
        hostPermissions: ext.hostPermissions || [],
        optionalPermissions: [],
        contentScriptInjections: {},
        backgroundRequests: [],
        storageKeys: [],
        manifestHash: '',
        contentScriptHashes: [],
        backgroundScriptHash: '',
        riskScore: this.calculateRiskScore(ext),
        riskFactors: [],
        baseline: {
          networkActivityPerHour: 0,
          storageWritesPerDay: 0,
          updatedAt: Date.now(),
        },
      };
      this.profiles.set(ext.id, profile);
    }
    return this.profiles.get(ext.id)!;
  }

  /**
   * Update profile with new data
   */
  private updateProfile(
    profile: ExtensionProfile,
    ext: chrome.management.ExtensionInfo
  ): void {
    profile.name = ext.name;
    profile.version = ext.version;
    profile.lastChecked = Date.now();
    profile.permissions = ext.permissions || [];
    profile.hostPermissions = ext.hostPermissions || [];
    profile.optionalPermissions = [];
    profile.riskScore = this.calculateRiskScore(ext);

    // Save to storage (async, don't await)
    this.saveProfile(profile);
  }

  /**
   * Event handlers
   */
  private async onExtensionInstalled(ext: chrome.management.ExtensionInfo): Promise<void> {
    console.log(`[ExtensionScanner] 🆕 New extension installed: ${ext.name}`);
    
    const anomaly = await this.scanExtension(ext);
    if (anomaly && anomaly.severity !== 'low') {
      this.notifyUser(anomaly);
    }
  }

  private onExtensionUninstalled(id: string): void {
    const profile = this.profiles.get(id);
    console.log(`[ExtensionScanner] 🗑️ Extension uninstalled: ${profile?.name || id}`);
    
    this.profiles.delete(id);
    chrome.storage.local.remove(`ext_profile_${id}`);
  }

  private async onExtensionEnabled(ext: chrome.management.ExtensionInfo): Promise<void> {
    console.log(`[ExtensionScanner] ✅ Extension enabled: ${ext.name}`);
    await this.scanExtension(ext);
  }

  /**
   * Notify user of suspicious extension
   */
  private notifyUser(anomaly: ExtensionAnomaly): void {
    const severityEmoji = {
      low: 'ℹ️',
      medium: '⚠️',
      high: '⚠️',
      critical: '🚨',
    };

    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('assets/icon.png'),
      title: `${severityEmoji[anomaly.severity]} Suspicious Extension Detected`,
      message: `${anomaly.extensionName}: ${anomaly.changes[0]?.description}`,
      priority: anomaly.severity === 'critical' ? 2 : 1,
    });
  }

  /**
   * Get all extension profiles (for UI display)
   */
  getAllProfiles(): ExtensionProfile[] {
    return Array.from(this.profiles.values());
  }

  /**
   * Persistence
   */
  private async saveProfile(profile: ExtensionProfile): Promise<void> {
    try {
      await chrome.storage.local.set({
        [`ext_profile_${profile.id}`]: profile,
      });
    } catch (error) {
      console.error('[ExtensionScanner] Error saving profile:', error);
    }
  }

  private async loadProfiles(): Promise<void> {
    try {
      chrome.storage.local.get(null, (stored) => {
        if (stored && Object.keys(stored).length > 0) {
          Object.entries(stored).forEach(([key, value]) => {
            if (key.startsWith('ext_profile_')) {
              const profile = value as ExtensionProfile;
              this.profiles.set(profile.id, profile);
            }
          });
          console.log('[ExtensionScanner] Loaded', this.profiles.size, 'extension profiles');
        }
      });
    } catch (error) {
      console.error('[ExtensionScanner] Error loading profiles:', error);
    }
  }
}
