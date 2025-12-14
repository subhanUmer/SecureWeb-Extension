/**
 * ML Training Script 1: Dataset Preparation
 * Converts phishing datasets to ML-ready format with features
 */

import * as fs from 'fs';
import * as path from 'path';

interface ThreatURL {
    url: string;
    domain?: string;
    type: 'phishing' | 'malware' | 'safe';
    label: number; // 0=safe, 1=phishing, 2=malware
}

/**
 * Extract features from a URL for ML training
 * MUST MATCH the runtime feature extraction exactly!
 */
function extractFeatures(url: string): number[] {
    try {
        const urlObj = new URL(url.startsWith('http') ? url : `http://${url}`);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();
        const search = urlObj.search.toLowerCase();

        return [
            // 1. URL Length (normalized to 0-1)
            Math.min(url.length / 200, 1.0),

            // 2. Hostname Length
            Math.min(hostname.length / 100, 1.0),

            // 3. Path Length
            Math.min(pathname.length / 100, 1.0),

            // 4. Number of Subdomains
            Math.min(hostname.split('.').length / 5, 1.0),

            // 5. Number of Dashes in hostname
            Math.min((hostname.match(/-/g) || []).length / 10, 1.0),

            // 6. Number of Underscores
            Math.min((hostname.match(/_/g) || []).length / 5, 1.0),

            // 7. Number of Digits in URL
            Math.min((url.match(/\d/g) || []).length / 20, 1.0),

            // 8. Has IP Address (binary)
            /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname) ? 1 : 0,

            // 9. Non-standard Port (binary)
            urlObj.port && urlObj.port !== '80' && urlObj.port !== '443' ? 1 : 0,

            // 10. Uses HTTPS (binary)
            urlObj.protocol === 'https:' ? 1 : 0,

            // 11. Suspicious TLD (binary)
            /\.(tk|ml|ga|cf|gq|pw|buzz|club|top)$/.test(hostname) ? 1 : 0,

            // 12. Has @ symbol (binary)
            url.includes('@') ? 1 : 0,

            // 13. Has double slash in path (binary)
            pathname.includes('//') ? 1 : 0,

            // 14. Suspicious Keywords in URL (binary)
            /(login|signin|verify|secure|account|update|confirm|banking|paypal)/i.test(url) ? 1 : 0,

            // 15. Has Suspicious Path Patterns (binary)
            /(\\.exe|\\.zip|\\.apk|\\.scr|\\.bat)$/i.test(pathname) ? 1 : 0,

            // 16. Query String Length
            Math.min(search.length / 100, 1.0),

            // 17. Number of Query Parameters
            Math.min((search.match(/&/g) || []).length / 10, 1.0),

            // 18. Has Suspicious Params (binary)
            /(password|credit|ssn|account|login)/i.test(search) ? 1 : 0,

            // 19. Percentage of Special Characters
            Math.min((url.match(/[^a-zA-Z0-9]/g) || []).length / url.length, 1.0),

            // 20. Domain has Numbers (binary)
            /\d/.test(hostname.split('.')[0] || '') ? 1 : 0,
        ];
    } catch (error) {
        console.error(`Error extracting features from ${url}:`, error);
        return new Array(20).fill(0);
    }
}

/**
 * Load phishing URLs from main dataset
 */
function loadPhishingURLs(): ThreatURL[] {
    const phishingData = JSON.parse(
        fs.readFileSync('assets/datasets/phishing-urls.json', 'utf-8')
    );

    const urls: ThreatURL[] = [];

    // Handle structured format with threats array
    if (phishingData.threats && Array.isArray(phishingData.threats)) {
        phishingData.threats.forEach((threat: any) => {
            if (threat.url) {
                urls.push({ url: threat.url, type: 'phishing', label: 1 });
            }
        });
    } else if (Array.isArray(phishingData)) {
        // Handle simple array format
        phishingData.forEach((item: any) => {
            const url = typeof item === 'string' ? item : (item.url || item.domain);
            if (url) {
                urls.push({ url, type: 'phishing', label: 1 });
            }
        });
    }

    return urls;
}

/**
 * Load PhishTank URLs
 */
function loadPhishTankURLs(): ThreatURL[] {
    const phishTankData = JSON.parse(
        fs.readFileSync('assets/datasets/phishtank_urls.json', 'utf-8')
    );

    if (Array.isArray(phishTankData)) {
        return phishTankData.map((url: string) => ({
            url,
            type: 'phishing' as const,
            label: 1,
        }));
    }

    return [];
}

/**
 * Generate safe URLs for training
 */
function generateSafeURLs(count: number): ThreatURL[] {
    const safeDomains = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
        'wikipedia.org', 'twitter.com', 'instagram.com', 'linkedin.com',
        'reddit.com', 'github.com', 'stackoverflow.com', 'medium.com',
        'nytimes.com', 'bbc.com', 'cnn.com', 'netflix.com',
        'microsoft.com', 'apple.com', 'adobe.com', 'zoom.us',
        'dropbox.com', 'spotify.com', 'twitch.tv', 'discord.com',
        'npmjs.com', 'nodejs.org', 'python.org', 'mozilla.org',
    ];

    const safePaths = [
        '/', '/home', '/about', '/contact', '/products', '/services',
        '/blog', '/news', '/help', '/support', '/pricing', '/features',
        '/docs', '/api', '/download', '/team', '/careers',
    ];

    const urls: ThreatURL[] = [];

    for (let i = 0; i < count; i++) {
        const domain = safeDomains[Math.floor(Math.random() * safeDomains.length)];
        const path = safePaths[Math.floor(Math.random() * safePaths.length)];
        const protocol = Math.random() > 0.2 ? 'https' : 'http';

        urls.push({
            url: `${protocol}://${domain}${path}`,
            type: 'safe',
            label: 0,
        });
    }

    return urls;
}

/**
 * Main function to prepare dataset
 */
async function prepareDataset() {
    console.log('🔄 Loading datasets...\n');

    // Load malicious URLs
    const phishingURLs = loadPhishingURLs();
    const phishTankURLs = loadPhishTankURLs();

    console.log(`📊 Loaded ${phishingURLs.length} phishing URLs`);
    console.log(`📊 Loaded ${phishTankURLs.length} PhishTank URLs`);

    // Combine and deduplicate
    const allMaliciousURLs = [...phishingURLs, ...phishTankURLs];
    const uniqueMalicious = Array.from(
        new Map(allMaliciousURLs.map(item => [item.url, item])).values()
    );

    console.log(`📊 Total unique malicious URLs: ${uniqueMalicious.length}`);

    // Generate safe URLs (equal or slightly more than malicious)
    const safeURLs = generateSafeURLs(Math.ceil(uniqueMalicious.length * 1.2));
    console.log(`📊 Generated ${safeURLs.length} safe URLs`);

    // Combine all URLs
    const allURLs = [...uniqueMalicious, ...safeURLs];

    // Shuffle dataset
    for (let i = allURLs.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [allURLs[i], allURLs[j]] = [allURLs[j], allURLs[i]];
    }

    console.log(`\n🔄 Extracting features from ${allURLs.length} URLs...`);

    // Extract features
    const dataset = allURLs.map((item, index) => {
        if (index % 10000 === 0) {
            console.log(`   Processed ${index}/${allURLs.length}`);
        }

        return {
            features: extractFeatures(item.url),
            label: item.label,
            url: item.url, // Keep for reference
            type: item.type,
        };
    });

    // Split into train/validation/test (70/15/15)
    const trainSize = Math.floor(dataset.length * 0.7);
    const valSize = Math.floor(dataset.length * 0.15);

    const trainData = dataset.slice(0, trainSize);
    const valData = dataset.slice(trainSize, trainSize + valSize);
    const testData = dataset.slice(trainSize + valSize);

    console.log(`\n📊 Dataset Statistics:`);
    console.log(`   Total URLs: ${dataset.length}`);
    console.log(`   Training: ${trainData.length}`);
    console.log(`   Validation: ${valData.length}`);
    console.log(`   Testing: ${testData.length}`);

    // Calculate class distribution
    const trainSafe = trainData.filter(d => d.label === 0).length;
    const trainPhish = trainData.filter(d => d.label === 1).length;
    console.log(`\n   Training set: ${trainSafe} safe, ${trainPhish} phishing`);

    // Save datasets
    const outputDir = 'src/modules/2.2-ml-model/datasets';
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    fs.writeFileSync(
        path.join(outputDir, 'train.json'),
        JSON.stringify(trainData, null, 2)
    );
    fs.writeFileSync(
        path.join(outputDir, 'validation.json'),
        JSON.stringify(valData, null, 2)
    );
    fs.writeFileSync(
        path.join(outputDir, 'test.json'),
        JSON.stringify(testData, null, 2)
    );

    console.log(`\n✅ Datasets saved to ${outputDir}/`);
    console.log(`   - train.json (${trainData.length} samples)`);
    console.log(`   - validation.json (${valData.length} samples)`);
    console.log(`   - test.json (${testData.length} samples)`);
}

// Run the script
prepareDataset().catch(console.error);
