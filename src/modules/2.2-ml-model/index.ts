/**
 * Module 2.2: ML Threat Detection
 * Main entry point and convenience functions
 */

import { mlClassifier } from './MLThreatClassifier';
import type { MLAnomaly, MLPrediction } from './types';

/**
 * Analyze a URL with ML and create an anomaly if threat detected
 * This is the main integration point with the AnomalyEngine
 */
export async function analyzeURLWithML(url: string): Promise<MLAnomaly | null> {
    try {
        const prediction = await mlClassifier.classify(url);

        // Only create anomaly if threat detected with sufficient confidence
        if (!prediction.isThreat || prediction.confidence < 0.6) {
            return null;
        }

        // Calculate severity based on confidence
        let severity: 'low' | 'medium' | 'high' | 'critical';
        if (prediction.confidence >= 0.95) {
            severity = 'critical';
        } else if (prediction.confidence >= 0.85) {
            severity = 'high';
        } else if (prediction.confidence >= 0.75) {
            severity = 'medium';
        } else {
            severity = 'low';
        }

        // Determine recommendation
        let recommendation: 'monitor' | 'warn' | 'block';
        if (severity === 'critical' || severity === 'high') {
            recommendation = 'block';
        } else if (severity === 'medium') {
            recommendation = 'warn';
        } else {
            recommendation = 'monitor';
        }

        const domain = new URL(url).hostname;

        const anomaly: MLAnomaly = {
            type: 'ml-threat',
            targetId: domain,
            targetName: domain,
            detectedAt: Date.now(),
            severity,
            prediction,
            url,
            confidence: prediction.confidence,
            recommendation,
        };

        console.log('[ML] 🚨 Threat detected:', {
            url: url.substring(0, 60),
            category: prediction.category,
            confidence: (prediction.confidence * 100).toFixed(1) + '%',
            severity,
        });

        return anomaly;
    } catch (error) {
        console.error('[ML] Error analyzing URL:', error);
        return null;
    }
}

// Export types and classifier
export { mlClassifier } from './MLThreatClassifier';
export type { MLPrediction, MLAnomaly, MLModelInfo } from './types';
export { extractMLFeatures, getFeatureNames } from './feature-extractor';
