# SecureGuard Web SPA Refactoring - Implementation TODO

## Phase 1: Core Infrastructure
- [ ] 1.1 Create directory structure (/components, /pages, /assets/css, /assets/icons)
- [ ] 1.2 Create router.js - SPA navigation system
- [ ] 1.3 Create websocket.js - Real-time communication
- [ ] 1.4 Create charts.js - Chart rendering utilities
- [ ] 1.5 Update api.js - Fix API endpoints and add WebSocket support
- [ ] 1.6 Update loader.js - Enhanced real-time data loading

## Phase 2: UI Components
- [ ] 2.1 Create sidebar.html - Main navigation sidebar component
- [ ] 2.2 Create navbar.html - Top notification bar
- [ ] 2.3 Create notification-panel.html - Global alerts
- [ ] 2.4 Create loader.html - Loading spinner component
- [ ] 2.5 Create modal.html - Reusable modal component

## Phase 3: Page Views (SPA Pages)
- [ ] 3.1 Update index.html - Main SPA entry point
- [ ] 3.2 Create pages/dashboard.html - Main dashboard view
- [ ] 3.3 Create pages/scan.html - Scan center view
- [ ] 3.4 Create pages/threats.html - Threat radar view
- [ ] 3.5 Create pages/network.html - Network monitor view
- [ ] 3.6 Create pages/system.html - System health view
- [ ] 3.7 Create pages/identity.html - Digital identity view
- [ ] 3.8 Create pages/settings.html - Settings view
- [ ] 3.9 Create pages/admin.html - Admin panel view

## Phase 4: Feature Integration
- [ ] 4.1 Connect all pages to real-time API
- [ ] 4.2 Add WebSocket for live updates
- [ ] 4.3 Implement authentication flow (login/logout)
- [ ] 4.4 Add global notification system
- [ ] 4.5 Connect scan engine to UI

## Phase 5: Polish & Testing
- [ ] 5.1 Add lazy loading for pages
- [ ] 5.2 Optimize API caching
- [ ] 5.3 Add error handling
- [ ] 5.4 Test all navigation flows
- [ ] 5.5 Verify real data integration

## New Directory Structure:
```
/website
   index.html          (SPA Entry Point)
   
   /assets
       /css
           main.css    (Global styles)
           theme.css   (Dark theme)
       /icons          (SVG icons)
       /images         (Logos, backgrounds)
   
   /components
       sidebar.html
       navbar.html
       notification-panel.html
       loader.html
       modal.html
   
   /pages
       dashboard.html
       scan.html
       threats.html
       network.html
       system.html
       identity.html
       settings.html
       admin.html
       login.html
   
   /js
       router.js      (NEW - SPA Router)
       websocket.js   (NEW - WebSocket)
       charts.js      (NEW - Chart utilities)
       api.js         (UPDATE)
       auth.js        (UPDATE)
       loader.js      (UPDATE)
```

## API Endpoints to Connect:
- GET /api/status - System status
- GET /api/processes - Process list
- GET /api/threats - Detected threats
- GET /api/quarantine - Quarantine items
- GET /api/settings - User settings
- POST /api/settings - Update settings
- POST /api/scan/start - Start scan
- GET /api/scan/status - Scan progress
- GET /api/system/info - System info
- GET /api/storage - Storage info
- GET /api/services - Services status

