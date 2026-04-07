using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.Privacy
{
    /// <summary>
    /// Privacy Protection - Detects webcam access, microphone access, and keyloggers
    /// </summary>
    public class PrivacyProtection : IDisposable
    {
        private CancellationTokenSource? _monitorCts;
        private bool _isRunning;
        
        // Known legitimate camera/microphone processes
        private static readonly HashSet<string> CameraProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "camera", "webcam", "video", "zoom", "teams", "skype", 
            "discord", "slack", "obs", "streamlabs", "xsplit"
        };

        // Known keylogger-related processes and modules
        private static readonly HashSet<string> KeyloggerProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "keylog", "keylogg", "keylogger", "keyloger", "keylog2", "spyware",
            "stealth", "hidden", "monitor", "record", "sniffer", "hook",
            "mouserecord", "keystrokerecorder", "activelogger", "refog", "refog"
        };

        // Suspicious modules that might indicate keylogging
        private static readonly HashSet<string> SuspiciousModules = new(StringComparer.OrdinalIgnoreCase)
        {
            "keyhook", "keylog", "keyboardhook", "lowlevelkeyboard", 
            "getasynckeystate", "whlhook", "klog", "keylogger", 
            "globalhook", "inputvoodoo", "steelseries"
        };

        public event EventHandler<PrivacyViolationEventArgs>? WebcamAccessDetected;
        public event EventHandler<PrivacyViolationEventArgs>? MicrophoneAccessDetected;
        public event EventHandler<PrivacyViolationEventArgs>? KeyloggerDetected;
        
        public bool IsRunning => _isRunning;
        public bool IsWebcamProtectionEnabled { get; set; } = true;
        public bool IsMicrophoneProtectionEnabled { get; set; } = true;
        public bool IsKeyloggerProtectionEnabled { get; set; } = true;

        public void Start()
        {
            if (_isRunning) return;
            
            _monitorCts = new CancellationTokenSource();
            Task.Run(() => MonitorPrivacy(_monitorCts.Token));
            
            _isRunning = true;
            Logger.Log("Info", "Privacy protection started");
        }

        public void Stop()
        {
            _monitorCts?.Cancel();
            _isRunning = false;
            Logger.Log("Info", "Privacy protection stopped");
        }

        private async Task MonitorPrivacy(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    // Monitor webcam access
                    if (IsWebcamProtectionEnabled)
                    {
                        await CheckWebcamAccess(token);
                    }
                    
                    // Monitor microphone access
                    if (IsMicrophoneProtectionEnabled)
                    {
                        await CheckMicrophoneAccess(token);
                    }
                    
                    // Monitor keyloggers
                    if (IsKeyloggerProtectionEnabled)
                    {
                        await CheckKeyloggers(token);
                    }
                    
                    await Task.Delay(3000, token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Privacy monitoring error: {ex.Message}", ex);
                    await Task.Delay(5000, token);
                }
            }
        }

        private async Task CheckWebcamAccess(CancellationToken token)
        {
            try
            {
                // Check for processes accessing camera devices
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        
                        // Check if process name suggests camera usage
                        if (CameraProcesses.Any(cp => processName.Contains(cp)))
                        {
                            // Check if it's actually accessing camera
                            if (IsProcessAccessingDevice(process, "camera"))
                            {
                                Logger.Log("Info", $"Webcam access detected: {process.ProcessName}");
                                WebcamAccessDetected?.Invoke(this, new PrivacyViolationEventArgs
                                {
                                    ProcessName = process.ProcessName,
                                    ProcessId = process.Id,
                                    DeviceType = "Webcam",
                                    Timestamp = DateTime.Now,
                                    IsAuthorized = IsAuthorizedApp(process.ProcessName)
                                });
                            }
                        }
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
                
                await Task.Delay(100, token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error checking webcam access", ex);
            }
        }

        private async Task CheckMicrophoneAccess(CancellationToken token)
        {
            try
            {
                // Check for processes accessing microphone
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        
                        // Audio recording processes
                        var audioProcesses = new[] { "zoom", "teams", "skype", "discord", 
                            "slack", "audacity", "obs", "streamlabs", "recorder" };
                        
                        if (audioProcesses.Any(ap => processName.Contains(ap)))
                        {
                            if (IsProcessAccessingDevice(process, "microphone"))
                            {
                                Logger.Log("Info", $"Microphone access detected: {process.ProcessName}");
                                MicrophoneAccessDetected?.Invoke(this, new PrivacyViolationEventArgs
                                {
                                    ProcessName = process.ProcessName,
                                    ProcessId = process.Id,
                                    DeviceType = "Microphone",
                                    Timestamp = DateTime.Now,
                                    IsAuthorized = IsAuthorizedApp(process.ProcessName)
                                });
                            }
                        }
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
                
                await Task.Delay(100, token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error checking microphone access", ex);
            }
        }

        private async Task CheckKeyloggers(CancellationToken token)
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        
                        // Check for known keylogger process names
                        if (KeyloggerProcesses.Any(kl => processName.Contains(kl)))
                        {
                            Logger.Log("Warning", $"Potential keylogger detected: {process.ProcessName}");
                            KeyloggerDetected?.Invoke(this, new PrivacyViolationEventArgs
                            {
                                ProcessName = process.ProcessName,
                                ProcessId = process.Id,
                                DeviceType = "Keylogger",
                                Details = "Known keylogger process name detected",
                                Timestamp = DateTime.Now,
                                IsAuthorized = false
                            });
                        }
                        
                        // Check for suspicious modules in all processes
                        try
                        {
                            if (process.MainModule != null)
                            {
                                foreach (ProcessModule module in process.Modules)
                                {
                                    var moduleName = module.ModuleName.ToLower();
                                    
                                    if (SuspiciousModules.Any(sm => moduleName.Contains(sm)))
                                    {
                                        Logger.Log("Warning", $"Suspicious module (possible keylogger): {module.ModuleName} in {process.ProcessName}");
                                        KeyloggerDetected?.Invoke(this, new PrivacyViolationEventArgs
                                        {
                                            ProcessName = process.ProcessName,
                                            ProcessId = process.Id,
                                            DeviceType = "Keylogger",
                                            Details = $"Suspicious module: {module.ModuleName}",
                                            Timestamp = DateTime.Now,
                                            IsAuthorized = false
                                        });
                                    }
                                }
                            }
                        }
                        catch { } // Access denied for some processes
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
                
                await Task.Delay(5000, token); // Check less frequently
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error checking keyloggers", ex);
            }
        }

        private bool IsProcessAccessingDevice(Process process, string deviceType)
        {
            // Simplified check - in production would use ETW or driver-level monitoring
            try
            {
                // Check process handle count (often higher when accessing devices)
                return process.HandleCount > 100;
            }
            catch
            {
                return false;
            }
        }

        private bool IsAuthorizedApp(string processName)
        {
            // List of known legitimate apps that need camera/mic access
            var authorizedApps = new[]
            {
                "zoom", "teams", "skype", "discord", "slack", "teams", 
                "outlook", "chrome", "firefox", "msedge", "safari",
                "obs", "streamlabs", "xsplit", "audacity"
            };
            
            var name = processName.ToLower();
            return authorizedApps.Any(app => name.Contains(app));
        }

        /// <summary>
        /// Get current privacy status
        /// </summary>
        public PrivacyStatus GetStatus()
        {
            return new PrivacyStatus
            {
                IsRunning = _isRunning,
                WebcamProtectionEnabled = IsWebcamProtectionEnabled,
                MicrophoneProtectionEnabled = IsMicrophoneProtectionEnabled,
                KeyloggerProtectionEnabled = IsKeyloggerProtectionEnabled,
                LastCheck = DateTime.Now
            };
        }

        /// <summary>
        /// Get list of recently accessed privacy events
        /// </summary>
        public List<PrivacyViolationEventArgs> GetRecentEvents(int count = 10)
        {
            // In production, would store events in a list/file
            return new List<PrivacyViolationEventArgs>();
        }

        public void Dispose()
        {
            Stop();
            _monitorCts?.Dispose();
        }
    }

    public class PrivacyViolationEventArgs : EventArgs
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string DeviceType { get; set; } = ""; // Webcam, Microphone, Keylogger
        public string Details { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public bool IsAuthorized { get; set; }
    }

    public class PrivacyStatus
    {
        public bool IsRunning { get; set; }
        public bool WebcamProtectionEnabled { get; set; }
        public bool MicrophoneProtectionEnabled { get; set; }
        public bool KeyloggerProtectionEnabled { get; set; }
        public DateTime LastCheck { get; set; }
    }
}

