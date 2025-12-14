/**
 * Module 1.3: Extension Scanner & Monitor
 * Type definitions for browser extension anomaly detection
 */

export interface ExtensionProfile {
  id: string;
  name: string;
  version: string;
  firstSeen: number;
  lastChecked: number;
  
  // Permission tracking
  permissions: string[];
  hostPermissions: string[];
  optionalPermissions: string[];
  
  // Behavioral tracking
  contentScriptInjections: Record<string, number>; // domain -> count
  backgroundRequests: string[];                     // Domains contacted
  storageKeys: string[];
  
  // Code analysis
  manifestHash: string;
  contentScriptHashes: string[];
  backgroundScriptHash: string;
  
  // Risk indicators
  riskScore: number;                                 // 0-100
  riskFactors: string[];
  
  baseline: {
    networkActivityPerHour: number;
    storageWritesPerDay: number;
    updatedAt: number;
  };
}

export interface ExtensionAnomaly {
  type: 'extension';
  extensionId: string;
  extensionName: string;
  detectedAt: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  changes: ExtensionChange[];
  confidence: number;
  recommendation: 'monitor' | 'warn' | 'disable' | 'uninstall';
  
  // Required for unified handling
  targetId: string;      // same as extensionId
  targetName: string;    // same as extensionName
  indicators?: any[];    // For compatibility
}

export interface ExtensionChange {
  type: 'permission' | 'code' | 'behavior' | 'network';
  description: string;
  oldValue?: any;
  newValue?: any;
  riskLevel: number; // 1-10
}
