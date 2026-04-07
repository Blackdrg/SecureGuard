/**
 * SecureGuard Authentication Module
 * Provides authentication functions for the dashboard
 */

(function() {
    'use strict';
    
    // Auth configuration
    const AUTH_CONFIG = {
        sessionKey: 'secureguard_session',
        userKey: 'secureguard_user',
        tokenKey: 'secureguard_token'
    };
    
    // Check if user is authenticated
    function isAuthenticated() {
        const session = localStorage.getItem(AUTH_CONFIG.sessionKey);
        const user = localStorage.getItem(AUTH_CONFIG.userKey);
        const token = localStorage.getItem(AUTH_CONFIG.tokenKey);
        return !!(session || user || token);
    }
    
    // Get current user
    function getCurrentUser() {
        try {
            const user = localStorage.getItem(AUTH_CONFIG.userKey);
            return user ? JSON.parse(user) : null;
        } catch (e) {
            return null;
        }
    }
    
    // Login function
    function login(credentials) {
        // This would typically call an API
        // For now, we'll store in localStorage
        localStorage.setItem(AUTH_CONFIG.sessionKey, 'true');
        localStorage.setItem(AUTH_CONFIG.userKey, JSON.stringify(credentials));
        return true;
    }
    
    // Logout function
    function logout() {
        localStorage.removeItem(AUTH_CONFIG.sessionKey);
        localStorage.removeItem(AUTH_CONFIG.userKey);
        localStorage.removeItem(AUTH_CONFIG.tokenKey);
        window.location.href = 'login.html';
    }
    
    // Validate session (would typically call API)
    async function validateSession() {
        return isAuthenticated();
    }
    
    // Export functions to window
    window.SecureGuardAuth = {
        isAuthenticated: isAuthenticated,
        getCurrentUser: getCurrentUser,
        login: login,
        logout: logout,
        validateSession: validateSession
    };
    
})();

