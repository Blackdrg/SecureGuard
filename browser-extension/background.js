// SecureGuard Browser Protection - Background Service Worker
// Handles web request blocking, threat detection, and communication with the main app

// Local threat database (would be updated from main app)
const threatDatabase = {
    phishingDomains: new Set([
        'fake-login.com',
        'secure-bank-alert.com',
        'account-verify.net',
        'password-reset.org',
        'free-gift.xyz'
    ]),
    maliciousPatterns: [
        /login.*verify/i,
        /account.*suspended/i,
        /urgent.*payment/i,
        /bank.*confirm/i,
        /password.*reset/i
    ],
    safeDomains: new Set([
        'google.com',
        'microsoft.com',
        'github.com',
        'apple.com',
        'amazon.com',
        'facebook.com',
        'twitter.com'
    ])
};

// Statistics
let stats = {
    blockedRequests: 0,
    phishingBlocked: 0,
    malwareBlocked: 0,
    safeBrowsing: 0
};

// API endpoint for communication with SecureGuard desktop app
const API_BASE_URL = 'http://localhost:8765/api';

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
    console.log('SecureGuard Browser Protection installed');
    initializeStorage();
});

// Initialize storage with defaults
function initializeStorage() {
    chrome.storage.local.get(['settings', 'stats'], (result) => {
        if (!result.settings) {
            chrome.storage.local.set({
                settings: {
                    phishingProtection: true,
                    malwareBlocking: true,
                    safeBrowsing: true,
                    notifications: true
                },
                stats: stats
            });
        }
    });
}

// Handle web requests
chrome.webRequest.onBeforeRequest.addListener(
    async (details) => {
        const url = new URL(details.url);
        
        // Check settings
        const settings = await getSettings();
        if (!settings.phishingProtection && !settings.malwareBlocking) {
            return;
        }

        // Check if URL is in threat database
        const hostname = url.hostname.toLowerCase();
        
        // Check phishing domains
        if (settings.phishingProtection) {
            for (const threat of threatDatabase.phishingDomains) {
                if (hostname.includes(threat)) {
                    logThreat('phishing', details.url, hostname);
                    return { cancel: true };
                }
            }
            
            // Check malicious patterns in URL
            for (const pattern of threatDatabase.maliciousPatterns) {
                if (pattern.test(details.url)) {
                    logThreat('malware', details.url, hostname);
                    return { cancel: true };
                }
            }
        }

        // Check with Safe Browsing API (if enabled)
        if (settings.safeBrowsing) {
            try {
                const response = await fetch(`${API_BASE_URL}/webprotection/check`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: details.url })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.isThreat) {
                        logThreat(data.threatType, details.url, hostname);
                        return { cancel: true };
                    }
                }
            } catch (e) {
                // Safe Browsing API not available, continue
            }
        }

        // Log safe browsing
        if (settings.safeBrowsing) {
            updateStats('safeBrowsing');
        }

        return { cancel: false };
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

// Handle navigation to detect phishing attempts
chrome.webNavigation.onBeforeNavigate.addListener(
    async (details) => {
        if (details.frameId !== 0) return; // Only main frame
        
        const settings = await getSettings();
        if (!settings.phishingProtection) return;

        const url = new URL(details.url);
        
        // Check for login forms on non-standard domains
        if (url.protocol !== 'chrome-extension:' && url.protocol !== 'chrome:') {
            // Notify content script to check for login forms
            chrome.tabs.sendMessage(details.tabId, {
                action: 'checkPage',
                url: details.url
            }).catch(() => {
                // Tab might not be ready yet
            });
        }
    },
    { url: [{ schemes: ["http", "https"] }] }
);

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case 'getStats':
            getStats().then(sendResponse);
            return true;
            
        case 'getSettings':
            getSettings().then(sendResponse);
            return true;
            
        case 'updateSettings':
            updateSettings(message.settings).then(sendResponse);
            return true;
            
        case 'reportPhishing':
            reportPhishing(message.url).then(sendResponse);
            return true;
            
        case 'checkURL':
            checkURL(message.url).then(sendResponse);
            return true;
            
        case 'getProtectionStatus':
            sendResponse({
                enabled: true,
                version: '1.0.0',
                lastUpdate: new Date().toISOString()
            });
            return true;
    }
});

// Check URL for threats
async function checkURL(url) {
    const settings = await getSettings();
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();
    
    // Check local database
    if (settings.phishingProtection) {
        for (const threat of threatDatabase.phishingDomains) {
            if (hostname.includes(threat)) {
                return { isThreat: true, threatType: 'phishing', source: 'local' };
            }
        }
    }
    
    // Check with API
    try {
        const response = await fetch(`${API_BASE_URL}/webprotection/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        
        if (response.ok) {
            return await response.json();
        }
    } catch (e) {
        console.log('API not available');
    }
    
    return { isThreat: false, threatType: 'none', source: 'none' };
}

// Report phishing URL
async function reportPhishing(url) {
    try {
        // Send to API
        await fetch(`${API_BASE_URL}/webprotection/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url, type: 'phishing' })
        });
        
        // Add to local database
        const parsedUrl = new URL(url);
        threatDatabase.phishingDomains.add(parsedUrl.hostname);
        
        updateStats('phishingBlocked');
        
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// Log threat detection
function logThreat(type, url, domain) {
    updateStats(type === 'phishing' ? 'phishingBlocked' : 'malwareBlocked');
    
    // Show notification
    getSettings().then(settings => {
        if (settings.notifications) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: 'SecureGuard - Threat Blocked',
                message: `Blocked ${type} attempt from ${domain}`
            });
        }
    });
    
    // Log to local storage
    chrome.storage.local.get(['threatLog'], (result) => {
        const log = result.threatLog || [];
        log.unshift({
            type,
            url,
            domain,
            timestamp: new Date().toISOString()
        });
        
        // Keep last 100 entries
        if (log.length > 100) {
            log.length = 100;
        }
        
        chrome.storage.local.set({ threatLog: log });
    });
}

// Get settings from storage
function getSettings() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['settings'], (result) => {
            resolve(result.settings || {
                phishingProtection: true,
                malwareBlocking: true,
                safeBrowsing: true,
                notifications: true
            });
        });
    });
}

// Update settings
function updateSettings(settings) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ settings }, () => {
            resolve({ success: true });
        });
    });
}

// Get stats
function getStats() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['stats'], (result) => {
            resolve(result.stats || stats);
        });
    });
}

// Update stats
function updateStats(stat) {
    chrome.storage.local.get(['stats'], (result) => {
        const currentStats = result.stats || stats;
        currentStats[stat]++;
        chrome.storage.local.set({ stats: currentStats });
    });
}

// Handle tab updates to show protection status
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Update badge to show protection is active
        chrome.action.setBadgeText({ tabId, text: '✓' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' });
    }
});

console.log('SecureGuard background service worker loaded');

