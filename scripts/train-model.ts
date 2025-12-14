/**
 * ML Training Script 2: Model Training
 * Trains a neural network for URL threat classification
 */

import * as tf from '@tensorflow/tfjs-node';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Load dataset from JSON
 */
function loadDataset(filename: string): { features: number[][], labels: number[] } {
    const data = JSON.parse(fs.readFileSync(filename, 'utf-8'));

    return {
        features: data.map((item: any) => item.features),
        labels: data.map((item: any) => item.label),
    };
}

/**
 * Create the neural network model
 */
function createModel(inputShape: number): tf.Sequential {
    const model = tf.sequential();

    // Input layer + first hidden layer
    model.add(tf.layers.dense({
        inputShape: [inputShape],
        units: 64,
        activation: 'relu',
        kernelInitializer: 'heNormal',
    }));

    // Dropout for regularization
    model.add(tf.layers.dropout({ rate: 0.3 }));

    // Second hidden layer
    model.add(tf.layers.dense({
        units: 32,
        activation: 'relu',
        kernelInitializer: 'heNormal',
    }));

    // Dropout
    model.add(tf.layers.dropout({ rate: 0.2 }));

    // Third hidden layer
    model.add(tf.layers.dense({
        units: 16,
        activation: 'relu',
        kernelInitializer: 'heNormal',
    }));

    // Output layer (2 classes: safe, phishing)
    model.add(tf.layers.dense({
        units: 2,
        activation: 'softmax',
    }));

    // Compile model
    model.compile({
        optimizer: tf.train.adam(0.001),
        loss: 'sparseCategoricalCrossentropy',
        metrics: ['accuracy'],
    });

    return model;
}

/**
 * Train the model
 */
async function trainModel() {
    console.log('🚀 Starting model training...\n');

    // Load datasets
    console.log('📂 Loading datasets...');
    const trainData = loadDataset('src/modules/2.2-ml-model/datasets/train.json');
    const valData = loadDataset('src/modules/2.2-ml-model/datasets/validation.json');

    console.log(`   Training samples: ${trainData.features.length}`);
    console.log(`   Validation samples: ${valData.features.length}`);

    // Convert to tensors
    const trainX = tf.tensor2d(trainData.features);
    const trainY = tf.tensor1d(trainData.labels, 'int32');
    const valX = tf.tensor2d(valData.features);
    const valY = tf.tensor1d(valData.labels, 'int32');

    // Create model
    console.log('\n🏗️  Creating model architecture...');
    const model = createModel(trainData.features[0].length);
    model.summary();

    // Train model
    console.log('\n🔥 Training model...\n');
    const history = await model.fit(trainX, trainY, {
        epochs: 50,
        batchSize: 32,
        validationData: [valX, valY],
        shuffle: true,
        callbacks: {
            onEpochEnd: (epoch, logs) => {
                console.log(
                    `Epoch ${epoch + 1}/50 - ` +
                    `Loss: ${logs?.loss.toFixed(4)} - ` +
                    `Accuracy: ${((logs?.acc || 0) * 100).toFixed(2)}% - ` +
                    `Val Loss: ${logs?.val_loss.toFixed(4)} - ` +
                    `Val Accuracy: ${((logs?.val_acc || 0) * 100).toFixed(2)}%`
                );
            },
        },
    });

    // Save model
    const modelPath = 'file://src/modules/2.2-ml-model/trained-model';
    console.log(`\n💾 Saving model to ${modelPath}...`);
    await model.save(modelPath);

    // Also copy to assets directory
    console.log('📦 Copying model to assets directory...');
    const assetsPath = 'assets/ml-models/threat-classifier';
    if (!fs.existsSync(assetsPath)) {
        fs.mkdirSync(assetsPath, { recursive: true });
    }

    // Copy model files
    const srcModelDir = 'src/modules/2.2-ml-model/trained-model';
    fs.copyFileSync(
        path.join(srcModelDir, 'model.json'),
        path.join(assetsPath, 'model.json')
    );

    const weightsFiles = fs.readdirSync(srcModelDir).filter(f => f.includes('weights'));
    weightsFiles.forEach(file => {
        fs.copyFileSync(
            path.join(srcModelDir, file),
            path.join(assetsPath, file)
        );
    });

    // Cleanup tensors
    trainX.dispose();
    trainY.dispose();
    valX.dispose();
    valY.dispose();

    const finalTrainAcc = history.history.acc[history.history.acc.length - 1] as number;
    const finalValAcc = history.history.val_acc[history.history.val_acc.length - 1] as number;

    console.log('\n✅ Training complete!');
    console.log(`   Final Training Accuracy: ${(finalTrainAcc * 100).toFixed(2)}%`);
    console.log(`   Final Validation Accuracy: ${(finalValAcc * 100).toFixed(2)}%`);
    console.log(`\n📍 Model saved to:`);
    console.log(`   - ${srcModelDir}/`);
    console.log(`   - ${assetsPath}/`);
}

// Run training
trainModel().catch(console.error);
