/**
 * Simplified ML Dataset Preparation - Works with actual data format
 */

const fs = require('fs');
const path = require('path');

function extractFeatures(url) {
    try {
        const urlObj = new URL(url.startsWith('http') ? url : `http://${url}`);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();
        const search = urlObj.search.toLowerCase();

        return [
            Math.min(url.length / 200, 1.0),
            Math.min(hostname.length / 100, 1.0),
            Math.min(pathname.length / 100, 1.0),
            Math.min(hostname.split('.').length / 5, 1.0),
            Math.min((hostname.match(/-/g) || []).length / 10, 1.0),
            Math.min((hostname.match(/_/g) || []).length / 5, 1.0),
            Math.min((url.match(/\d/g) || []).length / 20, 1.0),
            /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname) ? 1 : 0,
            urlObj.port && urlObj.port !== '80' && urlObj.port !== '443' ? 1 : 0,
            urlObj.protocol === 'https:' ? 1 : 0,
            /\.(tk|ml|ga|cf|gq|pw|buzz|club|top)$/.test(hostname) ? 1 : 0,
            url.includes('@') ? 1 : 0,
            pathname.includes('//') ? 1 : 0,
            /(login|signin|verify|secure|account|update|confirm|banking|paypal)/i.test(url) ? 1 : 0,
            /(\\.exe|\\.zip|\\.apk|\\.scr|\\.bat)$/i.test(pathname) ? 1 : 0,
            Math.min(search.length / 100, 1.0),
            Math.min((search.match(/&/g) || []).length / 10, 1.0),
            /(password|credit|ssn|account|login)/i.test(search) ? 1 : 0,
            Math.min((url.match(/[^a-zA-Z0-9]/g) || []).length / url.length, 1.0),
            /\d/.test(hostname.split('.')[0] || '') ? 1 : 0,
        ];
    } catch (error) {
        return new Array(20).fill(0);
    }
}

function generateSafeURLs(count) {
    const domains = ['google.com', 'youtube.com', 'github.com', 'wikipedia.org', 'amazon.com'];
    const paths = ['/', '/home', '/about', '/docs'];
    const urls = [];

    for (let i = 0; i < count; i++) {
        const domain = domains[Math.floor(Math.random() * domains.length)];
        const path = paths[Math.floor(Math.random() * paths.length)];
        urls.push({ url: `https://${domain}${path}`, label: 0, type: 'safe' });
    }
    return urls;
}

async function main() {
    console.log('[1/5] Loading phishing datasets...');

    const phishing1 = JSON.parse(fs.readFileSync('assets/datasets/phishing-urls.json', 'utf-8'));
    const phishing2 = JSON.parse(fs.readFileSync('assets/datasets/phishtank_urls.json', 'utf-8'));

    const phishURLs = phishing1.threats.map(t => ({ url: t.url, label: 1, type: 'phishing' }));
    const tankURLs = phishing2.map(url => ({ url, label: 1, type: 'phishing' }));

    console.log(`   Loaded ${phishURLs.length} + ${tankURLs.length} phishing URLs`);

    const allPhish = [...phishURLs, ...tankURLs];
    const unique = Array.from(new Map(allPhish.map(i => [i.url, i])).values());
    console.log(`   ${unique.length} unique phishing URLs`);

    console.log('[2/5] Generating safe URLs...');
    const safeURLs = generateSafeURLs(Math.ceil(unique.length * 1.2));
    console.log(`   Generated ${safeURLs.length} safe URLs`);

    const all = [...unique, ...safeURLs];
    for (let i = all.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [all[i], all[j]] = [all[j], all[i]];
    }

    console.log('[3/5] Extracting features...');
    const dataset = [];
    const batchSize = 10000;
    for (let i = 0; i < all.length; i++) {
        if (i % batchSize === 0) console.log(`   Progress: ${i}/${all.length}`);
        dataset.push({
            features: extractFeatures(all[i].url),
            label: all[i].label,
            url: all[i].url,
            type: all[i].type
        });
    }

    console.log('[4/5] Splitting dataset...');
    const trainSize = Math.floor(dataset.length * 0.7);
    const valSize = Math.floor(dataset.length * 0.15);

    const trainData = dataset.slice(0, trainSize);
    const valData = dataset.slice(trainSize, trainSize + valSize);
    const testData = dataset.slice(trainSize + valSize);

    console.log(`   Train: ${trainData.length}, Val: ${valData.length}, Test: ${testData.length}`);

    console.log('[5/5] Saving datasets...');
    const outDir = 'src/modules/2.2-ml-model/datasets';
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    fs.writeFileSync(path.join(outDir, 'train.json'), JSON.stringify(trainData));
    fs.writeFileSync(path.join(outDir, 'validation.json'), JSON.stringify(valData));
    fs.writeFileSync(path.join(outDir, 'test.json'), JSON.stringify(testData));

    console.log('✅ Dataset preparation complete!');
    console.log(`   Files saved to ${outDir}/`);
}

main().catch(e => console.error('ERROR:', e.message));
