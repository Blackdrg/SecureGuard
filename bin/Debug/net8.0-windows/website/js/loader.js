/**
 * SecureGuard Data Loader
 * Shared real-time data loading for all web dashboard pages
 * Include this script after api.js to enable real-time data
 */

(function() {
    'use strict';
    
    // Configuration
    const POLL_INTERVAL = 5000; // 5 seconds
    let pollIntervalId = null;
    let isConnected = false;
    let currentData = {};
    
    // Initialize data loading
    window.SecureGuardLoader = {
        init: async function() {
            console.log('SecureGuard Data Loader initializing...');
            await this.checkConnection();
            return isConnected;
        },
        
        // Check backend connection
        checkConnection: async function() {
            if (typeof secureGuardAPI === 'undefined') {
                console.warn('SecureGuard API not found');
                return false;
            }
            
            try {
                isConnected = await secureGuardAPI.checkConnection();
                this.updateConnectionUI(isConnected);
                console.log('SecureGuard:', isConnected ? 'Connected' : 'Offline Mode');
                return isConnected;
            } catch (e) {
                console.warn('Connection check failed:', e);
                isConnected = false;
                return false;
            }
        },
        
        // Update connection status in UI
        updateConnectionUI: function(connected) {
            // Try to find live indicator elements
            const liveDot = document.querySelector('.live-dot');
            const liveText = document.querySelector('.live-indicator span');
            const statusEl = document.querySelector('.user-status');
            
            if (liveDot && liveText) {
                if (connected) {
                    liveDot.style.background = 'var(--secondary)';
                    liveText.textContent = 'LIVE';
                } else {
                    liveDot.style.background = 'var(--warning)';
                    liveText.textContent = 'OFFLINE';
                }
            }
            
            if (statusEl) {
                if (connected) {
                    statusEl.innerHTML = '<span style="color: #10b981;">●</span> Connected';
                } else {
                    statusEl.innerHTML = '<span style="color: #f59e0b;">●</span> Offline Mode';
                }
            }
        },
        
        // Load dashboard stats
        loadDashboardStats: async function() {
            if (!isConnected) return null;
            
            try {
                const data = await secureGuardAPI.getDashboardStats();
                currentData = { ...currentData, ...data };
                return data;
            } catch (e) {
                console.warn('Failed to load dashboard stats:', e);
                return null;
            }
        },
        
        // Load system performance
        loadSystemPerformance: async function() {
            if (!isConnected) return null;
            
            try {
                const data = await secureGuardAPI.getSystemPerformance();
                return data;
            } catch (e) {
                console.warn('Failed to load system performance:', e);
                return null;
            }
        },
        
        // Load processes
        loadProcesses: async function() {
            if (!isConnected) return null;
            
            try {
                const data = await secureGuardAPI.getProcesses();
                return data;
            } catch (e) {
                console.warn('Failed to load processes:', e);
                return null;
            }
        },
        
        // Load threats
        loadThreats: async function() {
            if (!isConnected) return null;
            
            try {
                const data = await secureGuardAPI.getThreats();
                return data;
            } catch (e) {
                console.warn('Failed to load threats:', e);
                return null;
            }
        },
        
        // Load settings
        loadSettings: async function() {
            if (!isConnected) return null;
            
            try {
                const data = await secureGuardAPI.getSettings();
                return data;
            } catch (e) {
                console.warn('Failed to load settings:', e);
                return null;
            }
        },
        
        // Save settings
        saveSettings: async function(settings) {
            if (!isConnected) return false;
            
            try {
                await secureGuardAPI.updateSettings(settings);
                return true;
            } catch (e) {
                console.warn('Failed to save settings:', e);
                return false;
            }
        },
        
        // Start polling
        startPolling: function(callback, intervalMs) {
            this.stopPolling();
            const interval = intervalMs || POLL_INTERVAL;
            
            const poll = async () => {
                await this.checkConnection();
                if (callback) {
                    await callback(isConnected);
                }
            };
            
            poll(); // Initial call
            pollIntervalId = setInterval(poll, interval);
            console.log('SecureGuard polling started, interval:', interval);
        },
        
        // Stop polling
        stopPolling: function() {
            if (pollIntervalId) {
                clearInterval(pollIntervalId);
                pollIntervalId = null;
                console.log('SecureGuard polling stopped');
            }
        },
        
        // Get current data
        getData: function() {
            return currentData;
        },
        
        // Check if connected
        isConnected: function() {
            return isConnected;
        }
    };
    
    // Auto-initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            window.SecureGuardLoader.init();
        });
    } else {
        // DOM already loaded
        window.SecureGuardLoader.init();
    }
    
})();

