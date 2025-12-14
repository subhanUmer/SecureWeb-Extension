/**
 * Module 2.2: ML Threat Detection
 * Type definitions for machine learning-based threat classification
 */

export interface MLPrediction {
  isThreat: boolean;
  confidence: number; // 0-1
  category: 'safe' | 'phishing' | 'malware';
  scores: {
    safe: number;
    phishing: number;
    malware?: number;
  };
}

export interface MLAnomaly {
  type: 'ml-threat';
  targetId: string; // URL or domain
  targetName: string;
  detectedAt: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  prediction: MLPrediction;
  url: string;
  confidence: number; // 0-1
  recommendation: 'monitor' | 'warn' | 'block';
}

export interface FeatureVector {
  features: number[];
  metadata?: {
    url: string;
    extractionTime: number;
  };
}

export interface MLModelInfo {
  loaded: boolean;
  inputShape?: number[];
  outputShape?: number[];
  version?: string;
}
