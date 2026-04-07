// SecureGuard Browser Protection - Content Script
// Handles page analysis, form detection, and user warnings

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case 'checkPage':
            analyzePage(message.url);
            break;
        case 'warnUser':
            showWarning(message.message);
            break;
    }
});

// Analyze page for potential threats
function analyzePage(url) {
    try {
        // Check for login forms on suspicious pages
        const forms = document.querySelectorAll('form');
        const loginKeywords = ['login', 'signin', 'password', 'email', 'username', 'credential'];
        
        for (const form of forms) {
            const formText = form.innerText.toLowerCase();
            const hasLoginField = form.querySelector('input[type="password"]') ||
                                 form.querySelector('input[type="email"]');
            
            if (hasLoginField) {
                // Check if we're on a known safe domain
                const hostname = new URL(url).hostname;
                const isSafeDomain = isKnownSafeDomain(hostname);
                
                if (!isSafeDomain) {
                    // Show warning about potential phishing
                    showLoginFormWarning(hostname);
                }
            }
        }
        
        // Check for suspicious URL patterns
        if (isSuspiciousURL(url)) {
            showSuspiciousURLWarning(url);
        }
        
    } catch (e) {
        console.log('SecureGuard: Page analysis error', e);
    }
}

// Check if domain is known safe
function isKnownSafeDomain(hostname) {
    const safeDomains = [
        'google.com', 'accounts.google.com',
        'microsoft.com', 'login.microsoftonline.com',
        'apple.com', 'appleid.apple.com',
        'amazon.com', 'pay.amazon.com',
        'facebook.com', 'login.facebook.com',
        'twitter.com', 'login.twitter.com',
        'github.com', 'github.com/login',
        'linkedin.com', 'login.linkedin.com',
        'dropbox.com', 'login.dropbox.com'
    ];
    
    return safeDomains.some(domain => hostname.includes(domain));
}

// Check for suspicious URL patterns
function isSuspiciousURL(url) {
    const suspiciousPatterns = [
        /login.*verify/i,
        /account.*suspended/i,
        /secure.*bank/i,
        /password.*reset/i,
        /urgent.*action/i,
        /confirm.*identity/i,
        /verify.*account/i,
        /unlock.*account/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(url));
}

// Show warning about login form
function showLoginFormWarning(hostname) {
    const warning = document.createElement('div');
    warning.id = 'secureguard-warning';
    warning.innerHTML = `
        <div style="
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
            padding: 16px 24px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            z-index: 999999;
            font-family: 'Segoe UI', sans-serif;
            max-width: 400px;
        ">
            <div style="
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 8px;
            ">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                    <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" 
                        stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <strong>SecureGuard Alert</strong>
            </div>
            <p style="margin: 0; opacity: 0.9; font-size: 14px;">
                A login form was detected on <strong>${hostname}</strong>. 
                Make sure this is a legitimate website before entering your credentials.
            </p>
            <button onclick="this.parentElement.remove()" style="
                margin-top: 12px;
                padding: 8px 16px;
                background: rgba(255,255,255,0.2);
                border: none;
                border-radius: 6px;
                color: white;
                cursor: pointer;
                font-weight: 600;
            ">Dismiss</button>
        </div>
    `;
    document.body.appendChild(warning);
}

// Show warning about suspicious URL
function showSuspiciousURLWarning(url) {
    const warning = document.createElement('div');
    warning.id = 'secureguard-url-warning';
    warning.innerHTML = `
        <div style="
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: white;
            padding: 16px 24px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            z-index: 999999;
            font-family: 'Segoe UI', sans-serif;
            max-width: 400px;
        ">
            <div style="
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 8px;
            ">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                    <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" 
                        stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <strong>Suspicious URL Detected</strong>
            </div>
            <p style="margin: 0; opacity: 0.9; font-size: 14px;">
                This URL contains patterns commonly used in phishing attacks.
            </p>
            <button onclick="this.parentElement.remove()" style="
                margin-top: 12px;
                padding: 8px 16px;
                background: rgba(255,255,255,0.2);
                border: none;
                border-radius: 6px;
                color: white;
                cursor: pointer;
                font-weight: 600;
            ">Dismiss</button>
        </div>
    `;
    document.body.appendChild(warning);
}

// Show generic warning
function showWarning(message) {
    const warning = document.createElement('div');
    warning.innerHTML = `
        <div style="
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
            padding: 16px 24px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            z-index: 999999;
            font-family: 'Segoe UI', sans-serif;
        ">
            <strong>SecureGuard Warning:</strong> ${message}
        </div>
    `;
    document.body.appendChild(warning);
    
    setTimeout(() => warning.remove(), 10000);
}

// Check for malicious scripts
function checkForMaliciousScripts() {
    const scripts = document.querySelectorAll('script');
    for (const script of scripts) {
        // Check for inline scripts with suspicious patterns
        if (script.src === '' && script.textContent) {
            const content = script.textContent.toLowerCase();
            if (content.includes('eval') && content.includes('document.cookie')) {
                console.log('SecureGuard: Suspicious script detected');
            }
        }
    }
}

// Initialize
console.log('SecureGuard content script loaded');

