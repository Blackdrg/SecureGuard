using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SecureGuard.Core
{
    public class BootScanner
    {
        private readonly ManualScanEngine _scanEngine;
        private readonly QuarantineManager _quarantineManager;

        public BootScanner(ManualScanEngine scanEngine, QuarantineManager quarantineManager)
        {
            _scanEngine = scanEngine;
            _quarantineManager = quarantineManager;
        }

        public async Task<BootScanResult> PerformBootScanAsync()
        {
            var result = new BootScanResult();
            Logger.Log("Info", "Starting boot-time scan");

            try
            {
                var scanPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                };

                foreach (var path in scanPaths)
                {
                    if (Directory.Exists(path))
                    {
                        var threats = await Task.Run(() => _scanEngine.ScanFolder(path));
                        result.ThreatsFound.AddRange(threats);
                    }
                }

                await ScanStartupItemsAsync(result);
                result.CompletedAt = DateTime.Now;
                Logger.Log("Info", $"Boot scan completed. Threats: {result.ThreatsFound.Count}");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Boot scan failed", ex);
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task ScanStartupItemsAsync(BootScanResult result)
        {
            await Task.Run(() =>
            {
                try
                {
                    var runKeys = new[]
                    {
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                    };

                    foreach (var keyPath in runKeys)
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                var value = key.GetValue(valueName)?.ToString() ?? "";
                                if (!string.IsNullOrEmpty(value))
                                {
                                    result.StartupItems.Add(new StartupItem
                                    {
                                        Name = valueName,
                                        Path = value,
                                        Location = keyPath
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) { Logger.Log("Error", "Startup scan error", ex); }
            });
        }

        public void ScheduleBootScan()
        {
            try
            {
                var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath)) return;
                using var key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                key?.SetValue("SecureGuardBootScan", $"\"{exePath}\" --bootscan");
                Logger.Log("Info", "Boot scan scheduled");
            }
            catch (Exception ex) { Logger.Log("Error", "Failed to schedule boot scan", ex); }
        }
    }

    public class BootScanResult
    {
        public List<string> ThreatsFound { get; set; } = new();
        public List<StartupItem> StartupItems { get; set; } = new();
        public DateTime StartedAt { get; set; } = DateTime.Now;
        public DateTime? CompletedAt { get; set; }
        public string? Error { get; set; }
    }

    public class StartupItem
    {
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public string Location { get; set; } = "";
    }
}

