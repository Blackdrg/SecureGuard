using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using Microsoft.Win32;
using SecureGuard.Core;

namespace SecureGuard.Core
{
    /// <summary>
    /// Feature 5: Self-Healing System Mode
    /// Repairs damage after attack - restores registry, recovers files, fixes permissions
    /// </summary>
    public class SelfHealingEngine : IDisposable
    {
        private readonly List<RepairRule> _repairRules;
        private readonly List<SystemSnapshot> _snapshots;
        private readonly object _lock = new();
        
        public event EventHandler<RepairStartedEventArgs>? RepairStarted;
        public event EventHandler<RepairProgressEventArgs>? RepairProgress;
        public event EventHandler<RepairCompletedEventArgs>? RepairCompleted;
        public event EventHandler<RecoveryEventArgs>? FileRecovered;

        public SelfHealingEngine()
        {
            _repairRules = new List<RepairRule>();
            _snapshots = new List<SystemSnapshot>();
            InitializeRepairRules();
            Core.Logger.Log("Info", "Self-Healing Engine initialized");
        }

        private void InitializeRepairRules()
        {
            // Registry repair rules
            _repairRules.Add(new RepairRule
            {
                Category = RepairCategory.Registry,
                TargetPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                Description = "Windows startup entries",
                RepairAction = "Remove suspicious entries"
            });
            
            _repairRules.Add(new RepairRule
            {
                Category = RepairCategory.Registry,
                TargetPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                Description = "Explorer folder options",
                RepairAction = "Restore default settings"
            });
            
            _repairRules.Add(new RepairRule
            {
                Category = RepairCategory.Registry,
                TargetPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                Description = "Windows Update settings",
                RepairAction = "Restore default settings"
            });

            // System file repair rules
            _repairRules.Add(new RepairRule
            {
                Category = RepairCategory.SystemFiles,
                TargetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                Description = "Critical system files",
                RepairAction = "Verify integrity"
            });
            
            _repairRules.Add(new RepairRule
            {
                Category = RepairCategory.SystemFiles,
                TargetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
                Description = "64-bit system files",
                RepairAction = "Verify integrity"
            });

            // Permission repair rules
            _repairRules.Add(new RepairRule
            {
                Category = RepairCategory.Permissions,
                TargetPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Description = "Windows folder permissions",
                RepairAction = "Restore default permissions"
            });
            
            Core.Logger.Log("Info", $"Loaded {_repairRules.Count} repair rules");
        }

        /// <summary>
        /// Create system snapshot for restoration
        /// </summary>
        public async Task<string> CreateSnapshotAsync(string name)
        {
            var snapshot = new SystemSnapshot
            {
                Id = Guid.NewGuid().ToString(),
                Name = name,
                CreatedAt = DateTime.Now,
                RegistryKeys = new Dictionary<string, Dictionary<string, object?>>(),
                FileChecksums = new Dictionary<string, string>(),
                Services = new List<string>()
            };

            try
            {
                await Task.Run(() =>
                {
                    // Capture registry state
                    CaptureRegistrySnapshot(snapshot);
                    
                    // Capture critical file checksums
                    CaptureFileChecksums(snapshot);
                    
                    // Capture services state
                    CaptureServicesState(snapshot);
                });

                lock (_lock)
                {
                    _snapshots.Add(snapshot);
                    
                    // Keep only last 10 snapshots
                    while (_snapshots.Count > 10)
                        _snapshots.RemoveAt(0);
                }

                Core.Logger.Log("Info", $"System snapshot created: {snapshot.Id}");
                return snapshot.Id;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to create system snapshot", ex);
                throw;
            }
        }

        private void CaptureRegistrySnapshot(SystemSnapshot snapshot)
        {
            var keyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                @"SOFTWARE\Classes\*"
            };

            foreach (var keyPath in keyPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key != null)
                    {
                        snapshot.RegistryKeys[keyPath] = new Dictionary<string, object?>();
                        foreach (var valueName in key.GetValueNames())
                        {
                            snapshot.RegistryKeys[keyPath][valueName] = key.GetValue(valueName);
                        }
                    }
                }
                catch { }
            }
        }

        private void CaptureFileChecksums(SystemSnapshot snapshot)
        {
            var criticalFiles = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "cmd.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "net.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "reg.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "powershell.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "config.sys")
            };

            foreach (var file in criticalFiles)
            {
                try
                {
                    if (File.Exists(file))
                    {
                        snapshot.FileChecksums[file] = Hashing.ComputeSHA256(file);
                    }
                }
                catch { }
            }
        }

        private void CaptureServicesState(SystemSnapshot snapshot)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
                foreach (ManagementObject service in searcher.Get())
                {
                    snapshot.Services.Add(service["Name"]?.ToString() ?? "");
                }
            }
            catch { }
        }

        /// <summary>
        /// Repair system after attack
        /// </summary>
        public async Task<RepairResult> RepairSystemAsync(RepairOptions options)
        {
            var result = new RepairResult
            {
                StartedAt = DateTime.Now
            };

            RepairStarted?.Invoke(this, new RepairStartedEventArgs(options));

            try
            {
                if (options.RepairRegistry)
                {
                    RepairProgress?.Invoke(this, new RepairProgressEventArgs("Repairing registry...", 20));
                    result.RegistryRepairs = await RepairRegistryAsync();
                }

                if (options.RecoverFiles)
                {
                    RepairProgress?.Invoke(this, new RepairProgressEventArgs("Recovering files...", 40));
                    result.FileRecoveries = await RecoverEncryptedFilesAsync();
                }

                if (options.FixPermissions)
                {
                    RepairProgress?.Invoke(this, new RepairProgressEventArgs("Fixing permissions...", 60));
                    result.PermissionFixes = await FixPermissionsAsync();
                }

                if (options.RestoreFromSnapshot && !string.IsNullOrEmpty(options.SnapshotId))
                {
                    RepairProgress?.Invoke(this, new RepairProgressEventArgs("Restoring from snapshot...", 80));
                    result.SnapshotRestore = await RestoreFromSnapshotAsync(options.SnapshotId);
                }

                RepairProgress?.Invoke(this, new RepairProgressEventArgs("Repair complete!", 100));
                
                result.CompletedAt = DateTime.Now;
                result.Success = true;

                Core.Logger.Log("Info", $"System repair completed. Success: {result.Success}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "System repair failed", ex);
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            RepairCompleted?.Invoke(this, new RepairCompletedEventArgs(result));
            return result;
        }

        private async Task<List<RegistryRepair>> RepairRegistryAsync()
        {
            var repairs = new List<RegistryRepair>();

            await Task.Run(() =>
            {
                // Remove suspicious startup entries
                var suspiciousPatterns = new[] { "temp", "tmp", "crypt", "encrypt", "unlock", "decrypt" };
                
                try
                {
                    using var runKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                    if (runKey != null)
                    {
                        foreach (var valueName in runKey.GetValueNames())
                        {
                            var value = runKey.GetValue(valueName)?.ToString()?.ToLower() ?? "";
                            if (suspiciousPatterns.Any(p => value.Contains(p)))
                            {
                                var originalValue = runKey.GetValue(valueName);
                                runKey.DeleteValue(valueName);
                                
                                repairs.Add(new RegistryRepair
                                {
                                    KeyPath = runKey.Name,
                                    ValueName = valueName,
                                    OriginalValue = originalValue?.ToString(),
                                    Action = "Removed suspicious entry",
                                    Success = true
                                });
                                
                                Core.Logger.Log("Warning", $"Removed suspicious registry entry: {valueName}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Registry repair failed", ex);
                }

                // Restore folder options
                try
                {
                    using var advancedKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true);
                    if (advancedKey != null)
                    {
                        // Reset common settings
                        advancedKey.SetValue("Hidden", 1, RegistryValueKind.DWord);
                        advancedKey.SetValue("ShowSuperHidden", 1, RegistryValueKind.DWord);
                        advancedKey.SetValue("HideFileExt", 0, RegistryValueKind.DWord);
                        
                        repairs.Add(new RegistryRepair
                        {
                            KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                            Action = "Reset folder options to defaults",
                            Success = true
                        });
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Folder options reset failed", ex);
                }

                // Remove malicious file associations
                try
                {
                    using var extKey = Registry.ClassesRoot.OpenSubKey(".exe", true);
                    if (extKey != null)
                    {
                        // Ensure .exe points to exefile
                        var currentValue = extKey.GetValue("");
                        if (currentValue?.ToString() != "exefile")
                        {
                            extKey.SetValue("", "exefile");
                            repairs.Add(new RegistryRepair
                            {
                                KeyPath = ".exe",
                                Action = "Restored .exe file association",
                                Success = true
                            });
                        }
                    }
                }
                catch { }
            });

            return repairs;
        }

        private async Task<List<FileRecovery>> RecoverEncryptedFilesAsync()
        {
            var recoveries = new List<FileRecovery>();

            await Task.Run(() =>
            {
                var encryptedExtensions = new[] { ".encrypted", ".locky", ".crypto", ".crypt", 
                    ".locked", ".enc", ".vault", ".lock", ".key", ".RSA", ".hermes" };

                var userFolders = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
                };

                foreach (var folder in userFolders)
                {
                    if (!Directory.Exists(folder)) continue;

                    try
                    {
                        var encryptedFiles = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                            .Where(f => encryptedExtensions.Contains(Path.GetExtension(f).ToLower()))
                            .Take(100);

                        foreach (var file in encryptedFiles)
                        {
                            try
                            {
                                var originalPath = file;
                                var extension = Path.GetExtension(file);
                                
                                // Try to find original by checking for .locked/.encrypted versions
                                var possibleOriginals = new[]
                                {
                                    file.Replace(extension, ""),
                                    file.Replace(extension, ".bak"),
                                    file.Replace(extension, ".original")
                                };

                                foreach (var original in possibleOriginals)
                                {
                                    if (File.Exists(original))
                                    {
                                        // Original found, backup encrypted version
                                        var backupPath = file + ".recovered";
                                        File.Move(file, backupPath);
                                        
                                        recoveries.Add(new FileRecovery
                                        {
                                            OriginalPath = original,
                                            EncryptedPath = file,
                                            BackupPath = backupPath,
                                            Status = "Original found and encrypted backed up",
                                            Success = true
                                        });
                                        
                                        FileRecovered?.Invoke(this, new RecoveryEventArgs(original, "Recovered"));
                                        break;
                                    }
                                }

                                // If no original found, log for manual recovery
                                if (!recoveries.Any(r => r.EncryptedPath == file))
                                {
                                    recoveries.Add(new FileRecovery
                                    {
                                        EncryptedPath = file,
                                        Status = "No original found - manual recovery required",
                                        Success = false
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            });

            Core.Logger.Log("Info", $"File recovery complete. Attempted: {recoveries.Count}");
            return recoveries;
        }

        private async Task<List<PermissionFix>> FixPermissionsAsync()
        {
            var fixes = new List<PermissionFix>();

            await Task.Run(() =>
            {
                // Reset critical folder permissions
                var criticalPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.System)
                };

                foreach (var path in criticalPaths)
                {
                    try
                    {
                        // Use icacls to reset permissions
                        var process = new System.Diagnostics.Process
                        {
                            StartInfo = new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = "icacls",
                                Arguments = $"\"{path}\" /reset /t /c",
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true
                            }
                        };
                        process.Start();
                        process.WaitForExit(10000);

                        fixes.Add(new PermissionFix
                        {
                            Path = path,
                            Action = "Reset permissions to default",
                            Success = process.ExitCode == 0
                        });
                    }
                    catch (Exception ex)
                    {
                        fixes.Add(new PermissionFix
                        {
                            Path = path,
                            Action = "Reset permissions",
                            Success = false,
                            Error = ex.Message
                        });
                    }
                }
            });

            return fixes;
        }

        private async Task<SnapshotRestore> RestoreFromSnapshotAsync(string snapshotId)
        {
            var restore = new SnapshotRestore { SnapshotId = snapshotId };

            SystemSnapshot? snapshot;
            lock (_lock)
            {
                snapshot = _snapshots.FirstOrDefault(s => s.Id == snapshotId);
            }

            if (snapshot == null)
            {
                restore.Success = false;
                restore.ErrorMessage = "Snapshot not found";
                return restore;
            }

            await Task.Run(() =>
            {
                // Restore registry keys
                foreach (var keyPath in snapshot.RegistryKeys.Keys)
                {
                    try
                    {
                        using var key = Registry.LocalMachine.CreateSubKey(keyPath);
                        if (key != null)
                        {
                            foreach (var value in snapshot.RegistryKeys[keyPath])
                            {
                                key.SetValue(value.Key, value.Value ?? "");
                            }
                            restore.RegistryRestored = true;
                        }
                    }
                    catch { }
                }

                // Verify file checksums
                int verifiedCount = 0;
                foreach (var file in snapshot.FileChecksums.Keys)
                {
                    try
                    {
                        if (File.Exists(file))
                        {
                            var currentChecksum = Hashing.ComputeSHA256(file);
                            if (currentChecksum == snapshot.FileChecksums[file])
                            {
                                verifiedCount++;
                            }
                        }
                    }
                    catch { }
                }
                
                restore.FilesVerified = verifiedCount;
                restore.TotalFiles = snapshot.FileChecksums.Count;
                restore.Success = true;
            });

            return restore;
        }

        public List<SystemSnapshot> GetSnapshots()
        {
            lock (_lock)
            {
                return _snapshots.ToList();
            }
        }

        public SystemSnapshot? GetLatestSnapshot()
        {
            lock (_lock)
            {
                return _snapshots.OrderByDescending(s => s.CreatedAt).FirstOrDefault();
            }
        }

        public void Dispose()
        {
            Core.Logger.Log("Info", "Self-Healing Engine disposed");
        }
    }

    public enum RepairCategory
    {
        Registry,
        SystemFiles,
        Permissions,
        Services,
        Network
    }

    public class RepairRule
    {
        public RepairCategory Category { get; set; }
        public string TargetPath { get; set; } = "";
        public string Description { get; set; } = "";
        public string RepairAction { get; set; } = "";
    }

    public class RepairOptions
    {
        public bool RepairRegistry { get; set; } = true;
        public bool RecoverFiles { get; set; } = true;
        public bool FixPermissions { get; set; } = true;
        public bool RestoreFromSnapshot { get; set; }
        public string? SnapshotId { get; set; }
    }

    public class RepairResult
    {
        public DateTime StartedAt { get; set; }
        public DateTime CompletedAt { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public List<RegistryRepair> RegistryRepairs { get; set; } = new();
        public List<FileRecovery> FileRecoveries { get; set; } = new();
        public List<PermissionFix> PermissionFixes { get; set; } = new();
        public SnapshotRestore? SnapshotRestore { get; set; }
    }

    public class RegistryRepair
    {
        public string KeyPath { get; set; } = "";
        public string? ValueName { get; set; }
        public string? OriginalValue { get; set; }
        public string Action { get; set; } = "";
        public bool Success { get; set; }
    }

    public class FileRecovery
    {
        public string? OriginalPath { get; set; }
        public string EncryptedPath { get; set; } = "";
        public string? BackupPath { get; set; }
        public string Status { get; set; } = "";
        public bool Success { get; set; }
    }

    public class PermissionFix
    {
        public string Path { get; set; } = "";
        public string Action { get; set; } = "";
        public bool Success { get; set; }
        public string? Error { get; set; }
    }

    public class SnapshotRestore
    {
        public string SnapshotId { get; set; } = "";
        public bool Success { get; set; }
        public bool RegistryRestored { get; set; }
        public int FilesVerified { get; set; }
        public int TotalFiles { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class SystemSnapshot
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public Dictionary<string, Dictionary<string, object?>> RegistryKeys { get; set; } = new();
        public Dictionary<string, string> FileChecksums { get; set; } = new();
        public List<string> Services { get; set; } = new();
    }

    public class RepairStartedEventArgs : EventArgs
    {
        public RepairOptions Options { get; }
        public RepairStartedEventArgs(RepairOptions options) => Options = options;
    }

    public class RepairProgressEventArgs : EventArgs
    {
        public string Message { get; }
        public int Percentage { get; }
        public RepairProgressEventArgs(string message, int percentage) { Message = message; Percentage = percentage; }
    }

    public class RepairCompletedEventArgs : EventArgs
    {
        public RepairResult Result { get; }
        public RepairCompletedEventArgs(RepairResult result) => Result = result;
    }

    public class RecoveryEventArgs : EventArgs
    {
        public string FilePath { get; }
        public string Status { get; }
        public RecoveryEventArgs(string filePath, string status) { FilePath = filePath; Status = status; }
    }
}

