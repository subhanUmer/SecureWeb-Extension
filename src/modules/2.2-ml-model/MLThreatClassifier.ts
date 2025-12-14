/**
 * Module 2.2: ML Threat Detection
 * TensorFlow.js-based URL threat classifier
 */

import * as tf from '@tensorflow/tfjs';
import type { MLPrediction, MLModelInfo } from './types';
import { extractMLFeatures } from './feature-extractor';

export class MLThreatClassifier {
    private model: tf.LayersModel | null = null;
    private isLoading: boolean = false;
    private loadPromise: Promise<void> | null = null;

    /**
     * Load the ML model (call once on extension startup)
     */
    async loadModel(): Promise<void> {
        if (this.model) {
            console.log('[ML] Model already loaded');
            return;
        }

        if (this.isLoading && this.loadPromise) {
            console.log('[ML] Model loading in progress, waiting...');
            return this.loadPromise;
        }

        this.isLoading = true;
        this.loadPromise = this._loadModel();
        return this.loadPromise;
    }

    private async _loadModel(): Promise<void> {
        try {
            console.log('[ML] Loading threat classification model...');

            const modelPath = chrome.runtime.getURL(
                'assets/ml-models/threat-classifier/model.json'
            );

            this.model = await tf.loadLayersModel(modelPath);

            console.log('[ML] ✅ Model loaded successfully');
            console.log('[ML] Model input shape:', this.model.inputs[0].shape);

            // Warm up the model with a dummy prediction
            const dummyInput = tf.zeros([1, 20]);
            const warmup = this.model.predict(dummyInput) as tf.Tensor;
            warmup.dispose();
            dummyInput.dispose();

            console.log('[ML] Model warmed up and ready');
        } catch (error) {
            console.error('[ML] ❌ Failed to load model:', error);
            this.model = null;
            throw error;
        } finally {
            this.isLoading = false;
        }
    }

    /**
     * Classify a URL using the ML model
     */
    async classify(url: string): Promise<MLPrediction> {
        // Ensure model is loaded
        if (!this.model) {
            await this.loadModel();
        }

        if (!this.model) {
            throw new Error('Model failed to load');
        }

        try {
            // Extract features
            const features = extractMLFeatures(url);

            // Create tensor
            const inputTensor = tf.tensor2d([features]);

            // Run prediction
            const prediction = this.model.predict(inputTensor) as tf.Tensor;
            const scores = await prediction.data();

            // Cleanup tensors
            inputTensor.dispose();
            prediction.dispose();

            // Parse results (2 classes: safe=0, phishing=1)
            const safeScore = scores[0];
            const phishingScore = scores[1];

            const isThreat = phishingScore > safeScore;
            // CRITICAL FIX: Use the score of the predicted class, not max
            const confidence = isThreat ? phishingScore : safeScore;

            const result: MLPrediction = {
                isThreat,
                confidence,
                category: isThreat ? 'phishing' : 'safe',
                scores: {
                    safe: safeScore,
                    phishing: phishingScore,
                },
            };

            console.log(`[ML] Classified ${url.substring(0, 50)}...`, {
                category: result.category,
                confidence: (result.confidence * 100).toFixed(1) + '%',
            });

            return result;
        } catch (error) {
            console.error('[ML] Classification error:', error);
            throw error;
        }
    }

    /**
     * Batch classify multiple URLs for better performance
     */
    async classifyBatch(urls: string[]): Promise<MLPrediction[]> {
        if (!this.model) {
            await this.loadModel();
        }

        if (!this.model) {
            throw new Error('Model failed to load');
        }

        try {
            // Extract features for all URLs
            const allFeatures = urls.map(url => extractMLFeatures(url));

            // Create batch tensor
            const inputTensor = tf.tensor2d(allFeatures);

            // Run prediction
            const prediction = this.model.predict(inputTensor) as tf.Tensor;
            const scoresArray = await prediction.array() as number[][];

            // Cleanup
            inputTensor.dispose();
            prediction.dispose();

            // Parse results
            return scoresArray.map((scores, idx) => {
                const safeScore = scores[0];
                const phishingScore = scores[1];
                const isThreat = phishingScore > safeScore;

                return {
                    isThreat,
                    confidence: isThreat ? phishingScore : safeScore, // Fixed: use predicted class score
                    category: isThreat ? 'phishing' : 'safe',
                    scores: {
                        safe: safeScore,
                        phishing: phishingScore,
                    },
                };
            });
        } catch (error) {
            console.error('[ML] Batch classification error:', error);
            throw error;
        }
    }

    /**
     * Get model info for debugging
     */
    getModelInfo(): MLModelInfo {
        if (!this.model) {
            return { loaded: false };
        }

        return {
            loaded: true,
            inputShape: this.model.inputs[0].shape as number[],
            outputShape: this.model.outputs[0].shape as number[],
        };
    }

    /**
     * Check if model is ready
     */
    isReady(): boolean {
        return this.model !== null;
    }
}

// Export singleton instance
export const mlClassifier = new MLThreatClassifier();
