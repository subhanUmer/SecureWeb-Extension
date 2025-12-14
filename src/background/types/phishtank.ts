/**
 * PhishTank Database Types
 */

export interface PhishTankThreat {
    id: string;
    url: string;
    domain: string;
    patternType: 'exact';
    type: 'phishing';
    severity: 'high';
    source: 'phishtank';
    meta?: {
        phish_id?: string;
        phish_detail_url?: string;
        submission_time?: string;
        verified?: string;
        verification_time?: string;
        online?: string;
        target?: string;
    };
}

export interface PhishTankDatabase {
    version: number;
    source: 'phishtank';
    total: number;
    lastUpdated: string;
    generatedAt: string;
    urls: string[];
    threats: PhishTankThreat[];
}

export interface UpdateStatus {
    isUpdating: boolean;
    lastUpdateTime?: string;
    lastUpdateSuccess?: boolean;
    errorMessage?: string;
    totalUrls?: number;
}
