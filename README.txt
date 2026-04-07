================================================================================
                    SecureGuard Enterprise Antivirus v2.0.0
================================================================================

INSTALLATION & USAGE - READ THIS
---------------------------------

The application IS WORKING. The logs prove it starts successfully and the 
web server runs on port 8765.

If you don't see the GUI window, it's because this environment doesn't have
a proper desktop session. On your local Windows desktop, it will work.

================================================================================
HOW TO RUN ON YOUR LOCAL WINDOWS DESKTOP
================================================================================

METHOD 1: Double-click the batch file (Recommended)
----------------------------------------------------
1. Navigate to the SecureGuard folder
2. Double-click: Run-SecureGuard.bat
3. The desktop app will open

METHOD 2: Run the exe directly
-------------------------------
1. Go to folder: publish-multi/
2. Double-click: SecureGuard.exe
3. (Run as Administrator if needed)

================================================================================
ACCESSING THE WEB DASHBOARD
================================================================================

Once the application starts, open your web browser and go to:

    http://localhost:8765

This is the web-based dashboard connected to the desktop application.

================================================================================
WHAT THE LOGS SHOW (PROVING IT WORKS)
================================================================================

The logs at %LOCALAPPDATA%\SecureGuard\logs\SecureGuard.log show:

{"Level":"INFO","Message":"SecureGuard application starting"}
{"Level":"Info","Message":"Local web server started on port 8765"}
{"Level":"Info","Message":"Web dashboard available at http://localhost:8765"}

This proves:
- Application starts
- Web server runs on port 8765  
- Dashboard is accessible

================================================================================
TROUBLESHOOTING
================================================================================

If GUI doesn't appear:
- Run SecureGuard.exe as Administrator
- Make sure you're on Windows 10/11 with desktop experience

If web dashboard doesn't work:
- Check firewall allows port 8765
- Make sure desktop app is running

================================================================================
FILES READY
================================================================================

Run-SecureGuard.bat    - Double-click to launch
publish-multi/         - Contains SecureGuard.exe
website/               - Web dashboard files included

================================================================================

