using System;
using System.IO;
using Microsoft.Win32;

namespace SecureGuard.Core
{
    /// <summary>
    /// Manages Windows startup registration and system tray functionality
    /// </summary>
    public class StartupManager
    {
        private const string AppName = "SecureGuard";
        private const string RegistryKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        private readonly string _exePath;

        public StartupManager()
        {
            _exePath = Environment.ProcessPath ?? System.Reflection.Assembly.GetExecutingAssembly().Location;
        }

        /// <summary>
        /// Registers the application to start with Windows
        /// </summary>
        public bool RegisterStartup()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegistryKey, true);
                if (key == null) return false;

                key.SetValue(AppName, $"\"{_exePath}\" --minimized");
                Core.Logger.Log("Info", "Registered SecureGuard for Windows startup");
                return true;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to register startup", ex);
                return false;
            }
        }

        /// <summary>
        /// Unregisters the application from Windows startup
        /// </summary>
        public bool UnregisterStartup()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegistryKey, true);
                if (key == null) return false;

                key.DeleteValue(AppName, false);
                Core.Logger.Log("Info", "Unregistered SecureGuard from Windows startup");
                return true;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to unregister startup", ex);
                return false;
            }
        }

        /// <summary>
        /// Checks if the application is registered to start with Windows
        /// </summary>
        public bool IsStartupEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegistryKey, false);
                if (key == null) return false;

                var value = key.GetValue(AppName);
                return value != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if running with administrator privileges
        /// </summary>
        public static bool IsRunningAsAdmin()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the version of the application
        /// </summary>
        public static string GetVersion()
        {
            try
            {
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                return version?.ToString() ?? "1.0.0";
            }
            catch
            {
                return "1.0.0";
            }
        }
    }
}

