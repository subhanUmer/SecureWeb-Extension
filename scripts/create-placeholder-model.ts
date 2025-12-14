/**
 * Create a minimal placeholder model for development/testing
 * This is NOT a trained model - just provides the correct architecture
 * for testing the ML integration without full training setup
 */

import * as tf from '@tensorflow/tfjs';
import * as fs from 'fs';

async function createPlaceholderModel() {
    console.log('🔨 Creating placeholder ML model...\n');

    // Create the same architecture as the real model
    const model = tf.sequential();

    model.add(tf.layers.dense({
        inputShape: [20],
        units: 64,
        activation: 'relu',
        kernelInitializer: 'heNormal',
    }));

    model.add(tf.layers.dropout({ rate: 0.3 }));

    model.add(tf.layers.dense({
        units: 32,
        activation: 'relu',
        kernelInitializer: 'heNormal',
    }));

    model.add(tf.layers.dropout({ rate: 0.2 }));

    model.add(tf.layers.dense({
        units: 16,
        activation: 'relu',
        kernelInitializer: 'heNormal',
    }));

    model.add(tf.layers.dense({
        units: 2,
        activation: 'softmax',
    }));

    model.compile({
        optimizer: tf.train.adam(0.001),
        loss: 'sparseCategoricalCrossentropy',
        metrics: ['accuracy'],
    });

    console.log('Model architecture:');
    model.summary();

    // Save to assets directory
    const outputPath = '../assets/ml-models/threat-classifier';

    if (!fs.existsSync(outputPath)) {
        fs.mkdirSync(outputPath, { recursive: true });
    }

    console.log(`\n💾 Saving placeholder model to ${outputPath}...`);
    await model.save(`file://${outputPath}`);

    console.log('\n✅ Placeholder model created!');
    console.log('⚠️  WARNING: This is NOT a trained model!');
    console.log('   It will give random predictions.');
    console.log('   Use ML-TRAINING-GUIDE.md to train a real model.\n');
}

createPlaceholderModel().catch(console.error);
