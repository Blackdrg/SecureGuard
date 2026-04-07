/**
 * SecureGuard SPA Router
 * Handles client-side routing for Single Page Application
 * Version: 1.0.0
 */

(function() {
    'use strict';

    // Router Configuration
    const ROUTES = {
        'dashboard': { 
            path: 'dashboard.html', 
            title: 'Dashboard',
            icon: 'fa-gauge-high',
            requiresAuth: true 
        },
        'scan': { 
            path: 'scan-center.html', 
            title: 'Scan Center',
            icon: 'fa-magnifying-glass',
            requiresAuth: true 
        },
        'threats': { 
            path: 'threat-radar.html', 
            title: 'Threat Radar',
            icon: 'fa-bug',
            requiresAuth: true 
        },
        'network': { 
            path: 'network-monitor.html', 
            title: 'Network Monitor',
            icon: 'fa-network-wired',
            requiresAuth: true 
        },
        'system': { 
            path: 'system-health.html', 
            title: 'System Health',
            icon: 'fa-heart-pulse',
            requiresAuth: true 
        },
        'identity': { 
            path: 'digital-identity.html', 
            title: 'Digital Identity',
            icon: 'fa-user-shield',
            requiresAuth: true 
        },
        'settings': { 
            path: 'settings.html', 
            title: 'Settings',
            icon: 'fa-gear',
            requiresAuth: true 
        },
        'admin': { 
            path: 'admin.html', 
            title: 'Admin Panel',
            icon: 'fa-shield-halved',
            requiresAuth: true,
            requiresAdmin: true 
        },
        'login': { 
            path: 'login.html', 
            title: 'Login',
            icon: 'fa-sign-in-alt',
            requiresAuth: false 
        },
        'logout': { 
            path: null,
            title: 'Logout',
            icon: 'fa-sign-out-alt',
            requiresAuth: true 
        }
    };

    // Current route state
    let currentRoute = 'dashboard';
    let isLoading = false;
    let routeChangeCallbacks = [];

    // Router class
    class Router {
        constructor() {
            this.routes = ROUTES;
            this.init();
        }

        // Initialize router
        init() {
            // Handle browser back/forward
            window.addEventListener('popstate', (e) => {
                if (e.state && e.state.route) {
                    this.navigate(e.state.route, false);
                }
            });

            // Handle initial load
            this.handleInitialLoad();

            // Set up navigation click handlers
            this.setupNavigation();

            console.log('SecureGuard Router initialized');
        }

        // Handle initial page load
        handleInitialLoad() {
            const hash = window.location.hash.slice(1);
            const route = hash || this.getStoredRoute() || 'dashboard';
            this.navigate(route, false);
        }

        // Get stored route from session
        getStoredRoute() {
            try {
                return sessionStorage.getItem('secureguard_current_route');
            } catch {
                return 'dashboard';
            }
        }

        // Store current route
        storeRoute(route) {
            try {
                sessionStorage.setItem('secureguard_current_route', route);
            } catch {
                // Ignore storage errors
            }
        }

        // Set up navigation event listeners
        setupNavigation() {
            // Use event delegation for navigation clicks
            document.addEventListener('click', (e) => {
                const navItem = e.target.closest('[data-route]');
                if (navItem) {
                    e.preventDefault();
                    const route = navItem.getAttribute('data-route');
                    this.navigate(route);
                }
            });
        }

        // Navigate to a route
        async navigate(route, pushState = true) {
            if (isLoading) return;
            
            const routeConfig = this.routes[route];
            if (!routeConfig) {
                console.error('Route not found:', route);
                return;
            }

            // Check authentication
            if (routeConfig.requiresAuth && !this.isAuthenticated()) {
                console.log('Route requires auth, redirecting to login');
                this.navigate('login');
                return;
            }

            // Check admin permission
            if (routeConfig.requiresAdmin && !this.isAdmin()) {
                console.log('Route requires admin, redirecting to dashboard');
                this.navigate('dashboard');
                return;
            }

            // Handle logout
            if (route === 'logout') {
                this.logout();
                return;
            }

            isLoading = true;
            currentRoute = route;

            // Update URL
            if (pushState) {
                history.pushState({ route }, routeConfig.title, `#${route}`);
            }

            // Store route
            this.storeRoute(route);

            // Update active navigation
            this.updateNavigation(route);

            // Update page title
            document.title = `${routeConfig.title} - SecureGuard`;

            // Emit route change event
            this.emitRouteChange(route);

            // Load the page content
            await this.loadPage(routeConfig.path, route);

            isLoading = false;
        }

        // Check if user is authenticated
        isAuthenticated() {
            const token = localStorage.getItem('secureguard_token');
            const user = localStorage.getItem('secureguard_user');
            return !!(token || user); // Allow access if either exists
        }

        // Check if user is admin
        isAdmin() {
            try {
                const user = JSON.parse(localStorage.getItem('secureguard_user'));
                return user && user.role === 'admin';
            } catch {
                return false;
            }
        }

        // Handle logout
        logout() {
            localStorage.removeItem('secureguard_token');
            localStorage.removeItem('secureguard_user');
            sessionStorage.removeItem('secureguard_current_route');
            
            // Show logout message
            if (window.SecureGuardUI) {
                window.SecureGuardUI.showNotification('success', 'Logged Out', 'You have been logged out successfully.');
            }
            
            this.navigate('login');
        }

        // Update navigation UI
        updateNavigation(route) {
            // Update nav items
            document.querySelectorAll('[data-route]').forEach(item => {
                const itemRoute = item.getAttribute('data-route');
                if (itemRoute === route) {
                    item.classList.add('active');
                } else {
                    item.classList.remove('active');
                }
            });

            // Update page title in header
            const titleElement = document.querySelector('.page-title span');
            if (titleElement && this.routes[route]) {
                titleElement.textContent = this.routes[route].title;
            }
        }

        // Load page content
        async loadPage(pagePath, route) {
            const mainContent = document.getElementById('main-content');
            if (!mainContent) {
                console.error('Main content container not found');
                return;
            }

            try {
                // Show loading state
                mainContent.innerHTML = this.getLoadingTemplate();

                // Fetch the page content
                const response = await fetch(pagePath);
                if (!response.ok) {
                    throw new Error(`Failed to load page: ${response.status}`);
                }
                
                const html = await response.text();
                
                // Insert content
                mainContent.innerHTML = html;
                
                // Execute any inline scripts
                this.executeInlineScripts(mainContent);
                
                // Trigger page init event
                this.triggerPageInit(route);
                
                // Scroll to top
                window.scrollTo(0, 0);
                
            } catch (error) {
                console.error('Error loading page:', error);
                mainContent.innerHTML = this.getErrorTemplate(error.message);
            }
        }

        // Execute inline scripts in loaded content
        executeInlineScripts(container) {
            const scripts = container.querySelectorAll('script');
            scripts.forEach(script => {
                const newScript = document.createElement('script');
                newScript.textContent = script.textContent;
                script.parentNode.replaceChild(newScript, script);
            });
        }

        // Trigger page initialization
        triggerPageInit(route) {
            // Dispatch custom event for page-specific initialization
            const event = new CustomEvent('pageInit', { 
                detail: { route } 
            });
            document.dispatchEvent(event);
        }

        // Get loading template
        getLoadingTemplate() {
            return `
                <div class="page-loading">
                    <div class="loading-spinner"></div>
                    <p>Loading...</p>
                </div>
            `;
        }

        // Get error template
        getErrorTemplate(message) {
            return `
                <div class="page-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h2>Error Loading Page</h2>
                    <p>${message}</p>
                    <button class="btn btn-primary" onclick="SecureGuardRouter.navigate('dashboard')">
                        <i class="fas fa-home"></i> Go to Dashboard
                    </button>
                </div>
            `;
        }

        // Get current route
        getCurrentRoute() {
            return currentRoute;
        }

        // Get all routes
        getRoutes() {
            return this.routes;
        }

        // Register route change callback
        onRouteChange(callback) {
            routeChangeCallbacks.push(callback);
        }

        // Emit route change event
        emitRouteChange(route) {
            routeChangeCallbacks.forEach(cb => cb(route));
        }

        // Refresh current page
        async refresh() {
            const routeConfig = this.routes[currentRoute];
            if (routeConfig && routeConfig.path) {
                await this.loadPage(routeConfig.path, currentRoute);
            }
        }
    }

    // Create and expose global router instance
    window.SecureGuardRouter = new Router();

    // Also expose for easy access
    window.navigateTo = function(route) {
        window.SecureGuardRouter.navigate(route);
    };

})();

