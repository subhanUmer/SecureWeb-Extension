/**
 * ML Model Training - JavaScript Version
 * Requires: @tensorflow/tfjs-node (install separately due to native deps)
 */

const tf = require('@tensorflow/tfjs-node');
const fs = require('fs');
const path = require('path');

function loadDataset(filename) {
    const data = JSON.parse(fs.readFileSync(filename, 'utf-8'));
    return {
        features: data.map(item => item.features),
        labels: data.map(item => item.label)
    };
}

function createModel(inputShape) {
    const model = tf.sequential();

    model.add(tf.layers.dense({
        inputShape: [inputShape],
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
        loss: 'categoricalCrossentropy',
        metrics: ['accuracy'],
    });

    return model;
}

async function trainModel() {
    console.log('🚀 Starting model training...\n');

    console.log('[1/4] Loading datasets...');
    const trainData = loadDataset('src/modules/2.2-ml-model/datasets/train.json');
    const valData = loadDataset('src/modules/2.2-ml-model/datasets/validation.json');

    console.log(`   Training samples: ${trainData.features.length}`);
    console.log(`   Validation samples: ${valData.features.length}`);

    console.log('\n[2/4] Converting to tensors...');
    const trainX = tf.tensor2d(trainData.features);
    const trainY = tf.oneHot(tf.tensor1d(trainData.labels, 'int32'), 2);
    const valX = tf.tensor2d(valData.features);
    const valY = tf.oneHot(tf.tensor1d(valData.labels, 'int32'), 2);

    console.log('\n[3/4] Creating model architecture...');
    const model = createModel(trainData.features[0].length);
    model.summary();

    console.log('\n[4/4] Training model (50 epochs)....\n');
    const history = await model.fit(trainX, trainY, {
        epochs: 50,
        batchSize: 32,
        validationData: [valX, valY],
        shuffle: true,
        callbacks: {
            onEpochEnd: (epoch, logs) => {
                const trainAcc = ((logs.acc || 0) * 100).toFixed(2);
                const valAcc = ((logs.val_acc || 0) * 100).toFixed(2);
                console.log(
                    `Epoch ${(epoch + 1).toString().padStart(2)}/${50} - ` +
                    `Loss: ${logs.loss.toFixed(4)} - ` +
                    `Acc: ${trainAcc}% - ` +
                    `Val Loss: ${logs.val_loss.toFixed(4)} - ` +
                    `Val Acc: ${valAcc}%`
                );
            },
        },
    });

    console.log('\n💾 Saving model...');
    const modelPath = 'file://src/modules/2.2-ml-model/trained-model';
    await model.save(modelPath);

    const assetsPath = 'assets/ml-models/threat-classifier';
    if (!fs.existsSync(assetsPath)) {
        fs.mkdirSync(assetsPath, { recursive: true });
    }

    const srcDir = 'src/modules/2.2-ml-model/trained-model';
    fs.copyFileSync(
        path.join(srcDir, 'model.json'),
        path.join(assetsPath, 'model.json')
    );

    const weightsFiles = fs.readdirSync(srcDir).filter(f => f.includes('weights'));
    weightsFiles.forEach(file => {
        fs.copyFileSync(
            path.join(srcDir, file),
            path.join(assetsPath, file)
        );
    });

    trainX.dispose();
    trainY.dispose();
    valX.dispose();
    valY.dispose();

    const finalAcc = history.history.acc[history.history.acc.length - 1];
    const finalValAcc = history.history.val_acc[history.history.val_acc.length - 1];

    console.log('\n✅ Training complete!');
    console.log(`   Final Training Accuracy: ${(finalAcc * 100).toFixed(2)}%`);
    console.log(`   Final Validation Accuracy: ${(finalValAcc * 100).toFixed(2)}%`);
    console.log(`\n📍 Model saved to:`);
    console.log(`   - ${srcDir}/`);
    console.log(`   - ${assetsPath}/`);
}

trainModel().catch(e => console.error('ERROR:', e.message));
