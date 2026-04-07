using System;
using System.Runtime.InteropServices;

namespace SecureGuard.Core
{
    /// <summary>
    /// Windows Toast Notification Manager
    /// </summary>
    public class NotificationManager
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int FlashWindow(IntPtr hwnd, bool bInvert);

        [DllImport("user32.dll")]
        private static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

        [StructLayout(LayoutKind.Sequential)]
        private struct FLASHWINFO
        {
            public uint cbSize;
            public IntPtr hwnd;
            public uint dwFlags;
            public uint uCount;
            public uint dwTimeout;
        }

        private const uint FLASHW_STOP = 0;
        private const uint FLASHW_CAPTION = 1;
        private const uint FLASHW_TRAY = 2;
        private const uint FLASHW_ALL = 3;
        private const uint FLASHW_TIMER = 4;
        private const uint FLASHW_TIMERNOFG = 12;

        private static IntPtr _mainWindowHandle;

        public static void SetMainWindowHandle(IntPtr handle)
        {
            _mainWindowHandle = handle;
        }

        /// <summary>
        /// Shows a threat detected notification
        /// </summary>
        public static void ShowThreatDetected(string threatName, string filePath)
        {
            try
            {
                // Log the threat
                Logger.Log("Warning", $"Threat Detected: {threatName} - {filePath}");
                
                // Flash the taskbar to alert user
                FlashTaskbar();
                
                // In production, use Windows Toast Notifications via Windows.UI.Notifications
                // For now, we log and flash
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to show notification", ex);
            }
        }

        /// <summary>
        /// Shows a protection enabled notification
        /// </summary>
        public static void ShowProtectionEnabled()
        {
            try
            {
                Logger.Log("Info", "Protection Enabled - Notification shown");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to show notification", ex);
            }
        }

        /// <summary>
        /// Shows a protection disabled notification
        /// </summary>
        public static void ShowProtectionDisabled()
        {
            try
            {
                Logger.Log("Info", "Protection Disabled - Notification shown");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to show notification", ex);
            }
        }

        /// <summary>
        /// Shows an update available notification
        /// </summary>
        public static void ShowUpdateAvailable(string version)
        {
            try
            {
                Logger.Log("Info", $"Update available: v{version}");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to show notification", ex);
            }
        }

        /// <summary>
        /// Shows a scan completed notification
        /// </summary>
        public static void ShowScanCompleted(int threatsFound, int filesScanned)
        {
            try
            {
                if (threatsFound > 0)
                {
                    Logger.Log("Warning", $"Scan complete: {threatsFound} threats found in {filesScanned} files");
                }
                else
                {
                    Logger.Log("Info", $"Scan complete: No threats found in {filesScanned} files");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to show notification", ex);
            }
        }

        /// <summary>
        /// Flashes the taskbar to get user's attention
        /// </summary>
        public static void FlashTaskbar()
        {
            try
            {
                if (_mainWindowHandle == IntPtr.Zero) return;

                var fInfo = new FLASHWINFO
                {
                    cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO)),
                    hwnd = _mainWindowHandle,
                    dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG,
                    uCount = 3,
                    dwTimeout = 0
                };

                FlashWindowEx(ref fInfo);
            }
            catch { }
        }

        /// <summary>
        /// Stops the taskbar flashing
        /// </summary>
        public static void StopFlashTaskbar()
        {
            try
            {
                if (_mainWindowHandle == IntPtr.Zero) return;

                var fInfo = new FLASHWINFO
                {
                    cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO)),
                    hwnd = _mainWindowHandle,
                    dwFlags = FLASHW_STOP,
                    uCount = 0,
                    dwTimeout = 0
                };

                FlashWindowEx(ref fInfo);
            }
            catch { }
        }
    }
}

