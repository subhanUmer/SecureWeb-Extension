/**
 * Shared Anomaly Detection Engine
 * Unified handler for both website and extension anomalies
 */

import type { BehaviorAnomaly } from '../2.3-behavior-monitor/types';
import type { ExtensionAnomaly } from '../1.3-extension-scanner/types';

type AnyAnomaly = BehaviorAnomaly | ExtensionAnomaly;

export class AnomalyEngine {
  /**
   * Unified alert handler for all anomalies
   */
  async handleAnomaly(anomaly: AnyAnomaly): Promise<void> {
    console.log(`[AnomalyEngine] 🚨 Detected ${anomaly.type} anomaly:`, {
      target: anomaly.targetName,
      severity: anomaly.severity,
      confidence: anomaly.confidence,
      recommendation: anomaly.recommendation,
    });

    // Store anomaly in history
    await this.recordAnomaly(anomaly);

    // Take action based on recommendation
    switch (anomaly.recommendation) {
      case 'block':
        await this.blockTarget(anomaly);
        break;
      case 'warn':
        await this.warnUser(anomaly);
        break;
      case 'disable':
        if (anomaly.type === 'extension') {
          await this.disableExtension((anomaly as ExtensionAnomaly).extensionId);
        }
        break;
      case 'uninstall':
        if (anomaly.type === 'extension') {
          await this.promptUninstall((anomaly as ExtensionAnomaly).extensionId);
        }
        break;
      case 'monitor':
        // Just log it
        console.log(`[AnomalyEngine] 👁️ Monitoring ${anomaly.targetName}`);
        break;
    }

    // Update stats
    await this.incrementAnomalyCount();
  }

  /**
   * Block a website
   */
  private async blockTarget(anomaly: AnyAnomaly): Promise<void> {
    if (anomaly.type === 'website') {
      // Add to blocklist
      try {
        await chrome.storage.local.set({
          [`blocked_${anomaly.targetId}`]: {
            domain: anomaly.targetId,
            reason: 'Anomalous behavior detected',
            blockedAt: Date.now(),
            anomaly,
          },
        });

        console.log(`[AnomalyEngine] 🚫 Blocked website: ${anomaly.targetId}`);
        
        // Notify user
        await this.warnUser(anomaly);
      } catch (error) {
        console.error('[AnomalyEngine] Error blocking target:', error);
      }
    }
  }

  /**
   * Warn user with notification
   */
  private async warnUser(anomaly: AnyAnomaly): Promise<void> {
    const severityEmoji = {
      low: 'ℹ️',
      medium: '⚠️',
      high: '⚠️',
      critical: '🚨'
    };

    const title = anomaly.type === 'website' 
      ? `${severityEmoji[anomaly.severity]} Suspicious Website Detected`
      : `${severityEmoji[anomaly.severity]} Suspicious Extension Detected`;

    const behaviorAnomaly = anomaly as BehaviorAnomaly;
    const extensionAnomaly = anomaly as ExtensionAnomaly;

    // Create detailed message for website anomalies
    let message = '';
    if (anomaly.type === 'website') {
      const indicatorCount = behaviorAnomaly.indicators?.length || 0;
      const topIndicator = behaviorAnomaly.indicators?.[0]?.description || 'Unknown behavior';
      message = `${anomaly.targetName}: ${topIndicator}`;
      if (indicatorCount > 1) {
        message += ` (+${indicatorCount - 1} more indicators)`;
      }
      message += ` | Confidence: ${Math.round((anomaly.confidence || 0) * 100)}%`;
    } else {
      const changeCount = extensionAnomaly.changes?.length || 0;
      const topChange = extensionAnomaly.changes?.[0]?.description || 'Unknown change';
      message = `${anomaly.targetName}: ${topChange}`;
      if (changeCount > 1) {
        message += ` (+${changeCount - 1} more)`;
      }
    }

    // Base64 128x128 shield fallback (minified PNG) if icon cannot be loaded
  // 64x64 simple shield PNG (no spaces) for fallback
  const fallbackIcon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAAAQCAYAAABaf7ccAAAACXBIWXMAAAsTAAALEwEAmpwYAAABFElEQVR4nO3SsUpDQRTH8Y+NCLY2VnYWFqJYWNiKWCipVhY2foH9B2FpY+AGFkYWNpYWJhYWFgY2dgItgENJuZuzv7nJmZc9J5vs/7fM/n4T6I4R9c4ax3vAM3gHPYxX8dke7wn4C1c4QQv4ESe4g8c4gNu4TMe4juc4jtc4lJe4gve4gWecwLZxQJ1xgG1xgEtxgFtxgLtxgG9xgB9xgI9xgK9xgDdxgDd5gL9zga53gYV7gYh7gYx7gbx7gT17gS17gS57gQ57geN3gKN7gKN3gCN3gKt5gKt5gIt5gIt5gIt7gId7gId7gId5gIt5gK15gK95gJd5gJt5gKt5gId5gId7gMd7gMd5gIf5gIf7gIf3gIc3gIe3gIerRrYFhWKTKQhwTaQLlFsj1oRRpygRtNZYXkLSX8Qik6gMk6gI06gM04gO06gA0rsAVT0hGgH0VoAAAAASUVORK5CYII=';

    // Helper to create notification with graceful fallback
    const createNotification = async (useFallback = false) => {
      return chrome.notifications.create({
        type: 'basic',
        iconUrl: useFallback ? fallbackIcon : chrome.runtime.getURL('assets/icon.png'),
        title,
        message: message.substring(0, 200),
        priority: anomaly.severity === 'critical' ? 2 : 1,
        requireInteraction: anomaly.severity === 'critical' || anomaly.severity === 'high'
      });
    };

    try {
      console.log('[AnomalyEngine] 📢 Showing notification:', { title, message });
      const id = await createNotification(false);
      console.log('[AnomalyEngine] ✅ Notification created:', id);
    } catch (err: any) {
      const msg = String(err?.message || err);
      if (msg.includes('Unable to download all specified images')) {
        console.warn('[AnomalyEngine] Icon load failed, retrying with base64 fallback');
        try {
          const id2 = await createNotification(true);
          console.log('[AnomalyEngine] ✅ Fallback notification created:', id2);
        } catch (err2) {
          console.error('[AnomalyEngine] Fallback notification also failed:', err2);
        }
      } else {
        console.error('[AnomalyEngine] Error showing notification:', err);
      }
    }
  }

  /**
   * Disable an extension
   */
  private async disableExtension(extensionId: string): Promise<void> {
    try {
      await chrome.management.setEnabled(extensionId, false);
      console.log(`[AnomalyEngine] 🛡️ Disabled extension: ${extensionId}`);
      
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('assets/icon.png'),
        title: '🛡️ Extension Disabled',
        message: 'SecureWeb disabled a suspicious extension for your safety',
        priority: 2,
      });
    } catch (error) {
      console.error(`[AnomalyEngine] Failed to disable extension:`, error);
      // Might not have permission - just warn instead
      await this.warnUser({
        type: 'extension',
        targetId: extensionId,
        targetName: extensionId,
        extensionId,
        extensionName: extensionId,
        detectedAt: Date.now(),
        severity: 'high',
        changes: [],
        confidence: 1.0,
        recommendation: 'disable',
      } as ExtensionAnomaly);
    }
  }

  /**
   * Prompt user to uninstall extension
   */
  private async promptUninstall(extensionId: string): Promise<void> {
    try {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('assets/icon.png'),
        title: '🚨 CRITICAL: Malicious Extension Detected',
        message: 'We strongly recommend uninstalling this extension immediately. Click to review.',
        priority: 2,
        requireInteraction: true,
        buttons: [
          { title: 'Uninstall Now' },
          { title: 'Review Details' },
        ],
      }, (notificationId) => {
        // Handle button clicks
        chrome.notifications.onButtonClicked.addListener((nId, buttonIndex) => {
          if (nId === notificationId) {
            if (buttonIndex === 0) {
              // Uninstall
              chrome.management.uninstall(extensionId, { showConfirmDialog: true });
            } else {
              // Show extension details
              chrome.tabs.create({
                url: `chrome://extensions/?id=${extensionId}`,
              });
            }
          }
        });
      });
    } catch (error) {
      console.error('[AnomalyEngine] Error prompting uninstall:', error);
    }
  }

  /**
   * Record anomaly in history
   */
  private async recordAnomaly(anomaly: AnyAnomaly): Promise<void> {
    try {
      chrome.storage.local.get('anomaly_history', (data) => {
        const history = data.anomaly_history || [];
        
        history.unshift({
          ...anomaly,
          timestamp: Date.now(),
        });

        // Keep only last 100 anomalies
        if (history.length > 100) {
          history.splice(100);
        }

        chrome.storage.local.set({ anomaly_history: history });
      });
    } catch (error) {
      console.error('[AnomalyEngine] Error recording anomaly:', error);
    }
  }

  /**
   * Update stats
   */
  private async incrementAnomalyCount(): Promise<void> {
    try {
      chrome.storage.local.get('stats', (data) => {
        const stats = data.stats || { 
          threatsBlocked: 0,
          scriptsBlocked: 0,
          anomaliesDetected: 0,
        };
        
        stats.anomaliesDetected = (stats.anomaliesDetected || 0) + 1;
        
        chrome.storage.local.set({ stats });
      });
    } catch (error) {
      console.error('[AnomalyEngine] Error updating stats:', error);
    }
  }

  /**
   * Get anomaly history for UI
   */
  async getAnomalyHistory(): Promise<AnyAnomaly[]> {
    return new Promise((resolve) => {
      chrome.storage.local.get('anomaly_history', (data) => {
        resolve(data.anomaly_history || []);
      });
    });
  }

  /**
   * Clear anomaly history
   */
  async clearHistory(): Promise<void> {
    await chrome.storage.local.set({ anomaly_history: [] });
    console.log('[AnomalyEngine] Cleared anomaly history');
  }
}
