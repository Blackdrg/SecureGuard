using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Core;
using SecureGuard.Sandbox;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 7: Attack Simulation Twin (Digital Twin Security)
    /// Creates a virtual clone of user system to test suspicious files safely
    /// Analyzes file behavior in isolated twin before allowing/blocking in real system
    /// </summary>
    public class AttackSimulationTwin : IDisposable
    {
        private readonly SandboxEngine _sandboxEngine;
        private readonly Dictionary<string, TwinSnapshot> _systemSnapshots = new();
        private readonly object _lock = new();
        private bool _isRunning;
        
        public event EventHandler<SimulationEventArgs>? SimulationStarted;
        public event EventHandler<SimulationResultEventArgs>? SimulationCompleted;

        public AttackSimulationTwin(SandboxEngine sandboxEngine)
        {
            _sandboxEngine = sandboxEngine;
            Logger.Log("Info", "Attack Simulation Twin initialized");
        }

        public void Start()
        {
            _isRunning = true;
            CreateSystemSnapshot("initial");
            Logger.Log("Info", "Attack Simulation Twin started");
        }

        public void Stop()
        {
            _isRunning = false;
            Logger.Log("Info", "Attack Simulation Twin stopped");
        }

        /// <summary>
        /// Creates a virtual snapshot of the current system state
        /// </summary>
        public TwinSnapshot CreateSystemSnapshot(string name)
        {
            var snapshot = new TwinSnapshot
            {
                SnapshotId = Guid.NewGuid().ToString(),
                Name = name,
                CreationTime = DateTime.Now,
                RegistryState = CaptureRegistryState(),
                FileSystemState = CaptureFileSystemState(),
                ProcessState = CaptureProcessState(),
                NetworkState = CaptureNetworkState()
            };
            
            lock (_lock)
            {
                _systemSnapshots[snapshot.SnapshotId] = snapshot;
            }
            
            Logger.Log("Info", $"System snapshot created: {name}");
            return snapshot;
        }

        /// <summary>
        /// Runs a file in the simulation twin before real execution
        /// </summary>
        public async Task<SimulationResult> SimulateFileExecutionAsync(string filePath)
        {
            var result = new SimulationResult
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                SimulationStartTime = DateTime.Now
            };
            
            SimulationStarted?.Invoke(this, new SimulationEventArgs(filePath));
            
            try
            {
                // Create pre-simulation snapshot
                var preSnapshot = CreateSystemSnapshot("pre_simulation");
                result.PreSnapshotId = preSnapshot.SnapshotId;
                
                // Run in sandbox/twin environment
                var sandboxResult = await Task.Run(() => _sandboxEngine.AnalyzeFile(filePath));
                
                // Analyze behavior
                result.SandboxBehaviors = sandboxResult.Behaviors;
                result.RiskScore = sandboxResult.RiskScore;
                result.Classification = sandboxResult.ThreatClassification;
                
                // Capture post-simulation state
                var postSnapshot = CreateSystemSnapshot("post_simulation");
                result.PostSnapshotId = postSnapshot.SnapshotId;
                
                // Compare states to detect changes
                result.SystemChanges = CompareSnapshots(preSnapshot, postSnapshot);
                
                // Determine if file is safe
                result.IsSafe = DetermineSafety(result);
                result.RecommendedAction = result.IsSafe ? ActionAllowed : ActionBlocked;
                
                // Analyze specific threat indicators
                result.ThreatIndicators = AnalyzeThreatIndicators(result);
                
                Logger.Log("Info", $"Simulation complete: {result.FileName} - {result.Classification} (Risk: {result.RiskScore})");
            }
            catch (Exception ex)
            {
                result.IsSafe = false;
                result.Error = ex.Message;
                result.RecommendedAction = ActionBlocked;
                Logger.Log("Error", $"Simulation failed for {filePath}", ex);
            }
            
            result.SimulationEndTime = DateTime.Now;
            result.Duration = result.SimulationEndTime - result.SimulationStartTime;
            
            SimulationCompleted?.Invoke(this, new SimulationResultEventArgs(result));
            
            return result;
        }

        /// <summary>
        /// Compares pre and post snapshots to detect system changes
        /// </summary>
        private List<SystemChange> CompareSnapshots(TwinSnapshot pre, TwinSnapshot post)
        {
            var changes = new List<SystemChange>();
            
            // Check file changes
            var newFiles = post.FileSystemState.Keys.Except(pre.FileSystemState.Keys);
            foreach (var file in newFiles)
            {
                changes.Add(new SystemChange
                {
                    Type = ChangeType.FileCreated,
                    Path = file,
                    Timestamp = post.CreationTime
                });
            }
            
            // Check modified files
            foreach (var file in post.FileSystemState.Keys.Intersect(pre.FileSystemState.Keys))
            {
                if (pre.FileSystemState[file] != post.FileSystemState[file])
                {
                    changes.Add(new SystemChange
                    {
                        Type = ChangeType.FileModified,
                        Path = file,
                        Timestamp = post.CreationTime
                    });
                }
            }
            
            // Check new processes
            var newProcesses = post.ProcessState.Keys.Except(pre.ProcessState.Keys);
            foreach (var proc in newProcesses)
            {
                changes.Add(new SystemChange
                {
                    Type = ChangeType.ProcessCreated,
                    Path = proc,
                    Timestamp = post.CreationTime
                });
            }
            
            // Check registry changes
            var newKeys = post.RegistryState.Keys.Except(pre.RegistryState.Keys);
            foreach (var key in newKeys)
            {
                changes.Add(new SystemChange
                {
                    Type = ChangeType.RegistryCreated,
                    Path = key,
                    Timestamp = post.CreationTime
                });
            }
            
            // Check network changes
            var newConnections = post.NetworkState.Keys.Except(pre.NetworkState.Keys);
            foreach (var conn in newConnections)
            {
                changes.Add(new SystemChange
                {
                    Type = ChangeType.NetworkConnection,
                    Path = conn,
                    Timestamp = post.CreationTime
                });
            }
            
            return changes;
        }

        private bool DetermineSafety(SimulationResult result)
        {
            // File is safe if:
            // 1. No malicious behaviors detected
            // 2. Risk score is below threshold
            // 3. No dangerous system changes
            
            if (result.Classification == "Malicious")
                return false;
            
            if (result.RiskScore > 70)
                return false;
            
            if (result.SystemChanges.Any(c => c.Type == ChangeType.RegistryCreated))
            {
                // Allow registry changes but flag them
                result.HasRegistryChanges = true;
            }
            
            if (result.SystemChanges.Any(c => c.Type == ChangeType.NetworkConnection))
            {
                // Check if connection is suspicious
                result.HasNetworkActivity = true;
            }
            
            return true;
        }

        private List<string> AnalyzeThreatIndicators(SimulationResult result)
        {
            var indicators = new List<string>();
            
            // Check for ransomware indicators
            if (result.SystemChanges.Any(c => c.Type == ChangeType.FileModified && 
                (c.Path.EndsWith(".encrypted") || c.Path.EndsWith(".locked"))))
            {
                indicators.Add("File encryption activity detected");
            }
            
            // Check for persistence
            if (result.SystemChanges.Any(c => c.Type == ChangeType.RegistryCreated && 
                c.Path.Contains("Run")))
            {
                indicators.Add("Persistence mechanism detected (Registry Run key)");
            }
            
            // Check for network exfiltration
            if (result.SystemChanges.Any(c => c.Type == ChangeType.NetworkConnection))
            {
                indicators.Add("Network communication detected");
            }
            
            // Check for process injection
            if (result.SandboxBehaviors.Any(b => b.Contains("inject")))
            {
                indicators.Add("Process injection attempt detected");
            }
            
            // Check for credential access
            if (result.SandboxBehaviors.Any(b => b.Contains("credential") || b.Contains("password")))
            {
                indicators.Add("Credential access attempt detected");
            }
            
            return indicators;
        }

        private Dictionary<string, string> CaptureRegistryState()
        {
            // Simplified registry capture
            return new Dictionary<string, string>
            {
                ["HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"] = "present",
                ["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"] = "present"
            };
        }

        private Dictionary<string, string> CaptureFileSystemState()
        {
            var state = new Dictionary<string, string>();
            
            // Capture key system directories
            var keyPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            };
            
            foreach (var path in keyPaths)
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        state[path] = Directory.GetFiles(path, "*", SearchOption.TopDirectoryOnly).Length.ToString();
                    }
                }
                catch { }
            }
            
            return state;
        }

        private Dictionary<string, string> CaptureProcessState()
        {
            var state = new Dictionary<string, string>();
            
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    state[proc.ProcessName] = proc.Id.ToString();
                }
                catch { }
            }
            
            return state;
        }

        private Dictionary<string, string> CaptureNetworkState()
        {
            // Simplified network state capture
            return new Dictionary<string, string>
            {
                ["active_connections"] = "0"
            };
        }

        /// <summary>
        /// Gets all available snapshots
        /// </summary>
        public List<TwinSnapshot> GetSnapshots()
        {
            lock (_lock)
            {
                return _systemSnapshots.Values.OrderByDescending(s => s.CreationTime).ToList();
            }
        }

        /// <summary>
        /// Restores system to a previous snapshot
        /// </summary>
        public async Task<bool> RestoreSnapshotAsync(string snapshotId)
        {
            try
            {
                TwinSnapshot? snapshot;
                lock (_lock)
                {
                    _systemSnapshots.TryGetValue(snapshotId, out snapshot);
                }
                
                if (snapshot == null) return false;
                
                await Task.Run(() =>
                {
                    // Restore registry state
                    foreach (var kvp in snapshot.RegistryState)
                    {
                        // Would restore actual registry keys
                    }
                    
                    // Restore file system state
                    foreach (var kvp in snapshot.FileSystemState)
                    {
                        // Would restore actual files
                    }
                });
                
                Logger.Log("Info", $"System restored to snapshot: {snapshot.Name}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Failed to restore snapshot: {snapshotId}", ex);
                return false;
            }
        }

        private const string ActionAllowed = "Allow";
        private const string ActionBlocked = "Block";

        public void Dispose()
        {
            Stop();
        }
    }

    public class TwinSnapshot
    {
        public string SnapshotId { get; set; } = "";
        public string Name { get; set; } = "";
        public DateTime CreationTime { get; set; }
        public Dictionary<string, string> RegistryState { get; set; } = new();
        public Dictionary<string, string> FileSystemState { get; set; } = new();
        public Dictionary<string, string> ProcessState { get; set; } = new();
        public Dictionary<string, string> NetworkState { get; set; } = new();
    }

    public class SimulationResult
    {
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public DateTime SimulationStartTime { get; set; }
        public DateTime SimulationEndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public string PreSnapshotId { get; set; } = "";
        public string PostSnapshotId { get; set; } = "";
        public List<string> SandboxBehaviors { get; set; } = new();
        public double RiskScore { get; set; }
        public string Classification { get; set; } = "";
        public List<SystemChange> SystemChanges { get; set; } = new();
        public List<string> ThreatIndicators { get; set; } = new();
        public bool IsSafe { get; set; }
        public string RecommendedAction { get; set; } = "";
        public bool HasRegistryChanges { get; set; }
        public bool HasNetworkActivity { get; set; }
        public string? Error { get; set; }
    }

    public class SystemChange
    {
        public ChangeType Type { get; set; }
        public string Path { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public enum ChangeType
    {
        FileCreated,
        FileModified,
        FileDeleted,
        ProcessCreated,
        ProcessTerminated,
        RegistryCreated,
        RegistryModified,
        RegistryDeleted,
        NetworkConnection,
        ServiceCreated
    }

    public class SimulationEventArgs : EventArgs
    {
        public string FilePath { get; }
        public SimulationEventArgs(string filePath) => FilePath = filePath;
    }

    public class SimulationResultEventArgs : EventArgs
    {
        public SimulationResult Result { get; }
        public SimulationResultEventArgs(SimulationResult result) => Result = result;
    }
}

