/**
 * PhishTank Auto-Updater
 * 
 * Automatically downloads and updates the PhishTank phishing database
 * every 6 hours using Chrome extension APIs.
 */

import type { PhishTankDatabase, PhishTankThreat, UpdateStatus } from './types/phishtank';

// Configuration
const PHISHTANK_FEED_URL = 'https://data.phishtank.com/data/online-valid.csv';
const UPDATE_INTERVAL_MINUTES = 360; // 6 hours
const ALARM_NAME = 'phishtank-update';
const STORAGE_KEY = 'phishtank_database';
const STATUS_KEY = 'phishtank_update_status';

/**
 * PhishTank Database Updater
 */
export class PhishTankUpdater {
    private isUpdating = false;

    /**
   * Initialize the updater
   * - Schedules automatic updates
   * - Downloads database only if missing or stale (>24 hours old)
   */
    async initialize(): Promise<void> {
        console.log('[PhishTank] Initializing auto-updater...');

        const db = await this.getDatabase();

        if (db) {
            const age = Date.now() - new Date(db.lastUpdated).getTime();
            const hoursSinceUpdate = age / (1000 * 60 * 60);

            console.log(`[PhishTank] Database loaded: ${db.total} URLs (last updated: ${db.lastUpdated})`);
            console.log(`[PhishTank] Database age: ${hoursSinceUpdate.toFixed(1)} hours`);

            // Only download if database is stale (>24 hours old)
            if (hoursSinceUpdate > 24) {
                console.log('[PhishTank] Database is stale, will update in background...');
                // Don't await - update in background to avoid blocking initialization
                this.updateDatabase().catch(err => {
                    console.warn('[PhishTank] Background update failed (will retry later):', err.message);
                });
            }
        } else {
            console.log('[PhishTank] No database found, will download in background...');
            // Don't await - download in background to avoid blocking initialization
            this.updateDatabase().catch(err => {
                console.warn('[PhishTank] Initial download failed (will retry at next scheduled update):', err.message);
                console.warn('[PhishTank] Extension will work without PhishTank database for now');
            });
        }

        // Schedule automatic updates regardless of download success
        await this.scheduleUpdates();

        console.log('[PhishTank] ✅ Auto-updater initialized');
    }

    /**
     * Schedule automatic database updates
     */
    private async scheduleUpdates(): Promise<void> {
        // Create alarm for periodic updates
        chrome.alarms.create(ALARM_NAME, {
            delayInMinutes: UPDATE_INTERVAL_MINUTES,
            periodInMinutes: UPDATE_INTERVAL_MINUTES,
        });

        console.log(`[PhishTank] Scheduled updates every ${UPDATE_INTERVAL_MINUTES} minutes (${UPDATE_INTERVAL_MINUTES / 60} hours)`);
    }

    /**
     * Download and update the database
     */
    async updateDatabase(): Promise<void> {
        if (this.isUpdating) {
            console.log('[PhishTank] Update already in progress, skipping...');
            return;
        }

        this.isUpdating = true;
        await this.setUpdateStatus({ isUpdating: true });

        try {
            console.log('[PhishTank] 🔄 Starting database update...');

            // Download CSV
            const csvText = await this.downloadCSV();

            // Parse to database
            const database = await this.parseCSV(csvText);

            // Save to storage
            await this.saveDatabase(database);

            // Update status
            await this.setUpdateStatus({
                isUpdating: false,
                lastUpdateTime: new Date().toISOString(),
                lastUpdateSuccess: true,
                totalUrls: database.total,
            });

            console.log(`[PhishTank] ✅ Update complete: ${database.total} URLs`);

        } catch (error) {
            console.error('[PhishTank] ❌ Update failed:', error);

            await this.setUpdateStatus({
                isUpdating: false,
                lastUpdateTime: new Date().toISOString(),
                lastUpdateSuccess: false,
                errorMessage: error instanceof Error ? error.message : 'Unknown error',
            });
        } finally {
            this.isUpdating = false;
        }
    }

    /**
   * Download PhishTank CSV feed
   */
    private async downloadCSV(): Promise<string> {
        console.log('[PhishTank] Downloading CSV feed...');

        const response = await fetch(PHISHTANK_FEED_URL, {
            headers: {
                'User-Agent': 'SecureWeb-Extension/1.0',
                'Accept': 'text/csv,text/plain,*/*',
            },
        });

        if (!response.ok) {
            if (response.status === 429) {
                throw new Error(`HTTP 429: Rate limited by PhishTank. Please wait before retrying. The database will auto-update in 6 hours.`);
            }
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const csvText = await response.text();
        console.log(`[PhishTank] Downloaded ${csvText.length} bytes`);

        return csvText;
    }

    /**
     * Parse CSV to database structure
     */
    private async parseCSV(csvText: string): Promise<PhishTankDatabase> {
        console.log('[PhishTank] Parsing CSV...');

        // Simple CSV parser (assumes PhishTank format)
        const lines = csvText.split('\n');
        const headers = lines[0].split(',').map(h => h.trim());

        const urlIndex = headers.indexOf('url');
        const phishIdIndex = headers.indexOf('phish_id');
        const targetIndex = headers.indexOf('target');

        const seen = new Set<string>();
        const urls: string[] = [];
        const threats: PhishTankThreat[] = [];

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            const fields = line.split(',');
            const url = fields[urlIndex]?.replace(/^"|"$/g, '').trim();

            if (!url || seen.has(url)) continue;

            seen.add(url);
            urls.push(url);

            let domain = '';
            try {
                domain = new URL(url).hostname;
            } catch {
                continue;
            }

            const phishId = fields[phishIdIndex]?.trim();
            const id = phishId ? `phishtank-${phishId}` : `phishtank-${threats.length + 1}`;

            threats.push({
                id,
                url,
                domain,
                patternType: 'exact',
                type: 'phishing',
                severity: 'high',
                source: 'phishtank',
                meta: {
                    phish_id: phishId,
                    target: fields[targetIndex]?.replace(/^"|"$/g, '').trim(),
                },
            });
        }

        const database: PhishTankDatabase = {
            version: 1,
            source: 'phishtank',
            total: urls.length,
            lastUpdated: new Date().toISOString(),
            generatedAt: new Date().toISOString(),
            urls,
            threats,
        };

        console.log(`[PhishTank] Parsed ${database.total} unique URLs`);

        return database;
    }

    /**
   * Save database to Chrome storage (optimized for size)
   */
    private async saveDatabase(database: PhishTankDatabase): Promise<void> {
        console.log('[PhishTank] Saving to storage...');

        // Store only essential data to save space
        // Full database with threat objects is ~9MB - too large!
        // Optimized version stores only URLs + basic metadata
        const optimizedDatabase = {
            version: database.version,
            source: database.source,
            total: database.total,
            lastUpdated: database.lastUpdated,
            generatedAt: database.generatedAt,
            urls: database.urls, // Array of URL strings (~1-2MB)
            // Skip storing full threat objects to save ~7-8MB
        };

        console.log(`[PhishTank] Optimized size: ${JSON.stringify(optimizedDatabase).length} bytes (from ${JSON.stringify(database).length} bytes)`);

        await chrome.storage.local.set({
            [STORAGE_KEY]: optimizedDatabase,
        });

        console.log('[PhishTank] ✅ Saved to storage');
    }

    /**
     * Get database from storage
     */
    async getDatabase(): Promise<PhishTankDatabase | null> {
        const result = await chrome.storage.local.get(STORAGE_KEY);
        return result[STORAGE_KEY] || null;
    }

    /**
     * Check if database exists
     */
    private async hasDatabase(): Promise<boolean> {
        const db = await this.getDatabase();
        return db !== null && db.urls.length > 0;
    }

    /**
     * Get update status
     */
    async getUpdateStatus(): Promise<UpdateStatus> {
        const result = await chrome.storage.local.get(STATUS_KEY);
        return result[STATUS_KEY] || { isUpdating: false };
    }

    /**
     * Set update status
     */
    private async setUpdateStatus(status: UpdateStatus): Promise<void> {
        await chrome.storage.local.set({
            [STATUS_KEY]: status,
        });
    }

    /**
     * Check if URL is in PhishTank database
     */
    async isPhishingURL(url: string): Promise<boolean> {
        const db = await this.getDatabase();
        if (!db) return false;

        // Exact match check
        return db.urls.includes(url);
    }

    /**
   * Get threat info for URL
   * Note: Returns minimal info since we optimize storage by not keeping full threat objects
   */
    async getThreatInfo(url: string): Promise<PhishTankThreat | null> {
        const db = await this.getDatabase();
        if (!db) return null;

        const index = db.urls.indexOf(url);
        if (index === -1) return null;

        // Create minimal threat info since we don't store full objects
        const domain = new URL(url).hostname;
        return {
            id: `phishtank-${index}`,
            url: url,
            domain: domain,
            patternType: 'exact',
            type: 'phishing',
            severity: 'high',
            source: 'phishtank',
        };
    }
}

// Singleton instance
export const phishTankUpdater = new PhishTankUpdater();

/**
 * Initialize PhishTank auto-updater
 * Call this from background script on extension install
 */
export async function initPhishTankUpdater(): Promise<void> {
    await phishTankUpdater.initialize();

    // Setup alarm listener
    chrome.alarms.onAlarm.addListener((alarm) => {
        if (alarm.name === ALARM_NAME) {
            console.log('[PhishTank] ⏰ Alarm triggered, starting update...');
            phishTankUpdater.updateDatabase();
        }
    });
}
