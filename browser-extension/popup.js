// SecureGuard Browser Protection - Popup Script

document.addEventListener('DOMContentLoaded', function() {
    loadStats();
    loadSettings();
});

// Load statistics from background script
function loadStats() {
    chrome.runtime.sendMessage({ action: 'getStats' }, (stats) => {
        if (stats) {
            document.getElementById('blocked-phishing').textContent = stats.phishingBlocked || 0;
            document.getElementById('blocked-malware').textContent = stats.malwareBlocked || 0;
            document.getElementById('safe-browsing').textContent = stats.safeBrowsing || 0;
        }
    });
}

// Load settings
function loadSettings() {
    chrome.runtime.sendMessage({ action: 'getSettings' }, (settings) => {
        if (settings) {
            // Update toggle states
            document.getElementById('toggle-phishing').classList.toggle('active', settings.phishingProtection);
            document.getElementById('toggle-malware').classList.toggle('active', settings.malwareBlocking);
            document.getElementById('toggle-safe').classList.toggle('active', settings.safeBrowsing);
        }
    });
}

// Toggle setting
function toggleSetting(setting) {
    chrome.runtime.sendMessage({ action: 'getSettings' }, (settings) => {
        if (settings) {
            // Toggle the value
            switch (setting) {
                case 'phishingProtection':
                    settings.phishingProtection = !settings.phishingProtection;
                    break;
                case 'malwareBlocking':
                    settings.malwareBlocking = !settings.malwareBlocking;
                    break;
                case 'safeBrowsing':
                    settings.safeBrowsing = !settings.safeBrowsing;
                    break;
            }
            
            // Update background
            chrome.runtime.sendMessage({
                action: 'updateSettings',
                settings: settings
            }, (result) => {
                if (result && result.success) {
                    // Update UI
                    const toggleId = 'toggle-' + setting.replace('Protection', '').replace('Blocking', '').replace('Browsing', '');
                    const toggle = document.getElementById(toggleId);
                    if (toggle) {
                        toggle.classList.toggle('active');
                    }
                }
            });
        }
    });
}

// Open dashboard
function openDashboard() {
    chrome.tabs.create({ url: 'http://localhost:8765' });
}

// Report phishing
function reportPhishing() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
            chrome.runtime.sendMessage({
                action: 'reportPhishing',
                url: tabs[0].url
            }, (result) => {
                if (result && result.success) {
                    alert('Thank you for reporting this phishing site!');
                }
            });
        }
    });
}

