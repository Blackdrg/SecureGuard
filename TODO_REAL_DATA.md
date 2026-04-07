# SecureGuard Web - Completed Implementation

## Summary of Completed Work

### 1. Authentication System (NEW)
- **website/js/auth.js** - Complete auth system with:
  - Login/logout functionality
  - Session management via localStorage
  - Page protection (redirects to login if not authenticated)
  - User info display in UI

### 2. API Client (Enhanced)
- **website/js/api.js** - Full API client with:
  - Real-time data polling
  - Connection status tracking
  - Fallback to localStorage when offline
  - All backend endpoints integrated

### 3. Shared Data Loader (NEW)
- **website/js/loader.js** - Reusable data loading for all pages
  - Auto-initializes on page load
  - Polling support for real-time updates

### 4. Pages Updated with Real-Time Data & Auth
- **login.html** - Added auth.js, demo mode login
- **signup.html** - Added auth.js, demo mode signup
- **dashboard.html** - Added api.js, loader.js, auth.js + real data
- **system-health.html** - Added api.js, loader.js, auth.js + real data
- **network-monitor.html** - Added api.js

### 5. Navigation Flow
All pages properly linked:
- index.html (public) → login.html → dashboard.html (protected)
- All protected pages redirect to login if not authenticated

---

## HOW TO RUN - Step by Step

### Step 1: Build the Desktop App
Open Command Prompt in the project folder and run:
```bash
cd c:\Users\mehta\Desktop\SecureGuard
dotnet build --configuration Debug
```

Or simply double-click **build_run.bat** in the project folder.

### Step 2: Run SecureGuard
After build completes, the app will start automatically:
- The desktop app will launch
- It starts a local web server on port **8765**

### Step 3: Open the Website
Open your web browser and go to:
```
file://c:/Users/mehta/Desktop/SecureGuard/website/index.html
```

Or if you have a web server, navigate to the website folder.

### Step 4: Test the Flow
1. **Landing Page**: You'll see the SecureGuard homepage
2. **Login/Signup**: Click "Get Started" or "Login"
   - Enter any email/password (demo mode works without backend)
   - Click Sign In
3. **Dashboard**: You'll be redirected to dashboard.html
4. **Real-Time Data**: The dashboard will show:
   - Live CPU usage
   - Live RAM usage
   - Running processes
   - Threat statistics
   - Security score

### Step 5: View System Health
From dashboard, click "System Health" in sidebar to see:
- Real-time CPU/RAM/Disk usage
- Process list
- Service status

---

## Quick Commands

To build and run:
```bash
cd c:\Users\mehta\Desktop\SecureGuard
build_run.bat
```

To just build:
```bash
dotnet build
```

---

## What Happens:
1. Desktop app starts → Local server runs on port 8765
2. Website connects to API → Shows REAL system data
3. If desktop app not running → Shows fallback demo data

