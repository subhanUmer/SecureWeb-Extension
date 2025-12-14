/**
 * Module 2.2: ML Threat Detection
 * Feature extraction from URLs for ML classification
 * 
 * CRITICAL: These features MUST match exactly what's used in training!
 */

/**
 * Extract 20 numerical features from a URL for ML classification
 * Each feature is normalized to 0-1 range for consistent model input
 */
export function extractMLFeatures(url: string): number[] {
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
        console.error('[ML] Feature extraction error:', error);
        // Return zero vector on error
        return new Array(20).fill(0);
    }
}

/**
 * Get feature names for debugging/logging
 */
export function getFeatureNames(): string[] {
    return [
        'url_length',
        'hostname_length',
        'path_length',
        'subdomain_count',
        'dash_count',
        'underscore_count',
        'digit_count',
        'has_ip_address',
        'non_standard_port',
        'uses_https',
        'suspicious_tld',
        'has_at_symbol',
        'double_slash_in_path',
        'suspicious_keywords',
        'suspicious_file_extension',
        'query_string_length',
        'query_param_count',
        'suspicious_params',
        'special_char_ratio',
        'domain_has_numbers',
    ];
}
