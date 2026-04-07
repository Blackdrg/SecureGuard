/**
 * SecureGuard Frontend Security Module
 * Provides CSRF protection, XSS sanitization, and input validation
 */

(function() {
    'use strict';

    // Security configuration
    const SECURITY_CONFIG = {
        csrfHeaderName: 'X-CSRF-Token',
        csrfCookieName: 'csrf_token',
        maxInputLength: 10000,
        allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
        allowedAttributes: {
            'a': ['href', 'title', 'target']
        }
    };

    /**
     * CSRF Token Manager
     */
    const CSRFManager = {
        token: null,

        /**
         * Initialize CSRF token from headers or generate new
         */
        async init() {
            // Try to get from cookie first
            this.token = this.getCookie(SECURITY_CONFIG.csrfCookieName);
            
            if (!this.token) {
                // Fetch new token from server
                try {
                    const response = await fetch('/api/auth/csrf', {
                        method: 'GET',
                        credentials: 'include'
                    });
                    if (response.ok) {
                        const data = await response.json();
                        this.token = data.csrf_token;
                        this.setCookie(SECURITY_CONFIG.csrfCookieName, this.token, 7);
                    }
                } catch (e) {
                    console.warn('Failed to fetch CSRF token:', e);
                }
            }
            
            return this.token;
        },

        /**
         * Get CSRF token for requests
         */
        getToken() {
            return this.token || localStorage.getItem('csrf_token');
        },

        /**
         * Set token from response header
         */
        setTokenFromHeader(token) {
            if (token) {
                this.token = token;
                localStorage.setItem('csrf_token', token);
            }
        },

        /**
         * Get cookie value
         */
        getCookie(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) {
                return parts.pop().split(';').shift();
            }
            return null;
        },

        /**
         * Set cookie
         */
        setCookie(name, value, days) {
            const expires = new Date();
            expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
            document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Strict`;
        }
    };

    /**
     * XSS Sanitizer
     */
    const XSSSanitizer = {
        /**
         * Sanitize HTML content
         */
        sanitizeHtml(unsafe) {
            if (typeof unsafe !== 'string') return unsafe;
            
            // Create a temporary element
            const temp = document.createElement('div');
            temp.textContent = unsafe;
            return temp.innerHTML;
        },

        /**
         * Sanitize user input for display
         */
        sanitizeInput(input) {
            if (typeof input !== 'string') return input;
            
            // Remove potentially dangerous patterns
            let sanitized = input
                .replace(/</g, '<')
                .replace(/>/g, '>')
                .replace(/"/g, '"')
                .replace(/'/g, '&#x27;')
                .replace(/\//g, '&#x2F;');
            
            // Remove script tags
            sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
            
            // Remove event handlers
            sanitized = sanitized.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
            
            // Remove javascript: URLs
            sanitized = sanitized.replace(/javascript:/gi, '');
            
            return sanitized;
        },

        /**
         * Validate and sanitize URL
         */
        sanitizeUrl(url) {
            if (!url) return '';
            
            try {
                const urlObj = new URL(url);
                // Only allow http, https, and relative URLs
                if (!['http:', 'https:', ''].includes(urlObj.protocol)) {
                    return '';
                }
                return url;
            } catch {
                // If URL parsing fails, treat as relative path
                if (!url.startsWith('/') && !url.startsWith('./') && !url.startsWith('../')) {
                    return '';
                }
                return url;
            }
        },

        /**
         * Escape HTML for JSON display
         */
        escapeJson(json) {
            if (typeof json === 'string') {
                return this.sanitizeInput(json);
            }
            return json;
        }
    };

    /**
     * Input Validator
     */
    const InputValidator = {
        /**
         * Validate email format
         */
        isValidEmail(email) {
            const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            return pattern.test(email);
        },

        /**
         * Validate password strength
         */
        isStrongPassword(password) {
            if (!password || password.length < 8) return false;
            
            const hasUpperCase = /[A-Z]/.test(password);
            const hasLowerCase = /[a-z]/.test(password);
            const hasDigit = /[0-9]/.test(password);
            const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
            
            return hasUpperCase && hasLowerCase && hasDigit;
        },

        /**
         * Validate username format
         */
        isValidUsername(username) {
            const pattern = /^[a-zA-Z0-9_-]{3,50}$/;
            return pattern.test(username);
        },

        /**
         * Validate input length
         */
        isValidLength(input, maxLength = SECURITY_CONFIG.maxInputLength) {
            return input && input.length <= maxLength;
        },

        /**
         * Validate numeric range
         */
        isInRange(value, min, max) {
            const num = parseFloat(value);
            return !isNaN(num) && num >= min && num <= max;
        },

        /**
         * Sanitize and validate file path
         */
        isSafePath(path) {
            if (!path) return false;
            // Block path traversal
            if (path.includes('..') || path.includes('~')) return false;
            return true;
        }
    };

    /**
     * Output Encoder
     */
    const OutputEncoder = {
        /**
         * Encode for HTML context
         */
        encodeForHtml(value) {
            if (value === null || value === undefined) return '';
            return XSSSanitizer.sanitizeInput(String(value));
        },

        /**
         * Encode for JavaScript context
         */
        encodeForJs(value) {
            if (value === null || value === undefined) return '';
            const json = JSON.stringify(value);
            return json.replace(/<\/script/gi, '<\\/script');
        },

        /**
         * Encode for URL context
         */
        encodeForUrl(value) {
            if (value === null || value === undefined) return '';
            return encodeURIComponent(String(value));
        },

        /**
         * Encode for CSS context
         */
        encodeForCss(value) {
            if (value === null || value === undefined) return '';
            return String(value).replace(/[<>]/g, '');
        }
    };

    /**
     * Secure Storage Manager
     */
    const SecureStorage = {
        /**
         * Store sensitive data securely
         */
        setSecure(key, value) {
            try {
                // Use sessionStorage for sensitive data (cleared on tab close)
                // For longer storage, use localStorage with encryption
                const encoded = btoa(encodeURIComponent(JSON.stringify(value)));
                sessionStorage.setItem(`sg_secure_${key}`, encoded);
                return true;
            } catch (e) {
                console.error('Secure storage error:', e);
                return false;
            }
        },

        /**
         * Retrieve secure data
         */
        getSecure(key) {
            try {
                const encoded = sessionStorage.getItem(`sg_secure_${key}`);
                if (!encoded) return null;
                return JSON.parse(decodeURIComponent(atob(encoded)));
            } catch (e) {
                console.error('Secure retrieval error:', e);
                return null;
            }
        },

        /**
         * Clear sensitive data
         */
        clearSecure(key) {
            sessionStorage.removeItem(`sg_secure_${key}`);
        },

        /**
         * Clear all secure data
         */
        clearAllSecure() {
            const keys = Object.keys(sessionStorage);
            keys.forEach(key => {
                if (key.startsWith('sg_secure_')) {
                    sessionStorage.removeItem(key);
                }
            });
        }
    };

    /**
     * Security Event Handlers
     */
    const SecurityHandlers = {
        /**
         * Initialize security handlers
         */
        init() {
            // Protect forms
            document.addEventListener('submit', this.protectForm.bind(this), true);
            
            // Protect links with external URLs
            document.addEventListener('click', this.protectLinks.bind(this));
            
            // Content Security Policy violation handler
            document.addEventListener('securitypolicyviolation', this.handleCSPViolation.bind(this));
        },

        /**
         * Protect forms from CSRF
         */
        protectForm(event) {
            const form = event.target;
            if (form.method.toLowerCase() === 'post' || form.method.toLowerCase() === 'put' || form.method.toLowerCase() === 'delete') {
                const csrfToken = CSRFManager.getToken();
                if (csrfToken) {
                    // Add CSRF token to form if not present
                    let csrfInput = form.querySelector('input[name="csrf_token"]');
                    if (!csrfInput) {
                        csrfInput = document.createElement('input');
                        csrfInput.type = 'hidden';
                        csrfInput.name = 'csrf_token';
                        form.appendChild(csrfInput);
                    }
                    csrfInput.value = csrfToken;
                }
            }
        },

        /**
         * Protect links
         */
        protectLinks(event) {
            const link = event.target.closest('a');
            if (!link) return;

            const href = link.getAttribute('href');
            if (!href) return;

            // Check for malicious URLs
            if (href.startsWith('javascript:') || href.startsWith('data:')) {
                event.preventDefault();
                console.warn('Blocked potentially malicious link');
                return;
            }

            // Open external links in new tab with security
            try {
                const url = new URL(href, window.location.origin);
                if (url.origin !== window.location.origin) {
                    link.setAttribute('target', '_blank');
                    link.setAttribute('rel', 'noopener noreferrer');
                }
            } catch {
                // Invalid URL, let it be
            }
        },

        /**
         * Handle CSP violations
         */
        handleCSPViolation(event) {
            console.warn('CSP Violation:', {
                blockedURI: event.blockedURI,
                violatedDirective: event.violatedDirective,
                originalPolicy: event.originalPolicy
            });
            
            // Optionally report to server
            if (window.secureGuardAPI) {
                window.secureGuardAPI.reportCSPViolation({
                    blockedURI: event.blockedURI,
                    violatedDirective: event.violatedDirective
                }).catch(() => {});
            }
        }
    };

    /**
     * Security headers parser
     */
    const SecurityHeaders = {
        /**
         * Parse and store security headers from responses
         */
        process(response) {
            // Get CSRF token from response headers
            const csrfToken = response.headers.get('x-csrf-token');
            if (csrfToken) {
                CSRFManager.setTokenFromHeader(csrfToken);
            }
        }
    };

    // Initialize security module
    const SecurityModule = {
        CSRF: CSRFManager,
        XSS: XSSSanitizer,
        Validator: InputValidator,
        Encoder: OutputEncoder,
        Storage: SecureStorage,
        Handlers: SecurityHandlers,
        Headers: SecurityHeaders,

        /**
         * Initialize all security components
         */
        async init() {
            await CSRFManager.init();
            SecurityHandlers.init();
            console.log('SecureGuard Security Module initialized');
        },

        /**
         * Wrap fetch for security
         */
        secureFetch(url, options = {}) {
            const csrfToken = CSRFManager.getToken();
            
            const headers = {
                'Content-Type': 'application/json',
                ...(options.headers || {})
            };

            // Add CSRF token for state-changing methods
            if (options.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method.toUpperCase())) {
                if (csrfToken) {
                    headers[SECURITY_CONFIG.csrfHeaderName] = csrfToken;
                }
            }

            // Handle credentials
            if (options.credentials !== 'omit') {
                options.credentials = 'include';
            }

            return fetch(url, { ...options, headers })
                .then(response => {
                    SecurityHeaders.process(response);
                    return response;
                });
        }
    };

    // Export to global scope
    window.SecureGuardSecurity = SecurityModule;

    // Auto-initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => SecurityModule.init());
    } else {
        SecurityModule.init();
    }

})();

