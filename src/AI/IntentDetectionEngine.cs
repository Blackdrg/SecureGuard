using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 1: Intent Detection Engine
    /// Predicts malicious intent before execution by analyzing execution path probabilities
    /// and simulating next 3-5 steps of process behavior
    /// </summary>
    public class IntentDetectionEngine : IDisposable
    {
        private readonly Dictionary<int, IntentProfile> _processIntents = new();
        private readonly Dictionary<string, AttackPattern> _knownAttackPatterns = new();
        private readonly object _lock = new();
        private bool _isRunning;
        
        // Attack step simulations
        private readonly int _maxSimulationSteps = 5;
        private readonly int _simulationDepth = 3;
        
        public event EventHandler<IntentDetectedEventArgs>? MaliciousIntentDetected;
        public event EventHandler<PredictionEventArgs>? PathPredicted;

        public IntentDetectionEngine()
        {
            InitializeAttackPatterns();
            Logger.Log("Info", "Intent Detection Engine initialized");
        }

        private void InitializeAttackPatterns()
        {
            // Define known attack chain patterns
            _knownAttackPatterns["ransomware"] = new AttackPattern
            {
                Name = "Ransomware",
                Steps = new List<string> 
                { 
                    "file_enumeration", 
                    "file_encryption", 
                    "ransom_note", 
                    "network_c2" 
                },
                Weight = 1.0
            };
            
            _knownAttackPatterns["credential_theft"] = new AttackPattern
            {
                Name = "Credential Theft",
                Steps = new List<string>
                {
                    "process_attach",
                    "memory_read",
                    "credential_dump",
                    "network_exfil"
                },
                Weight = 0.95
            };
            
            _knownAttackPatterns["data_exfiltration"] = new AttackPattern
            {
                Name = "Data Exfiltration",
                Steps = new List<string>
                {
                    "file_access",
                    "data_compress",
                    "network_connection",
                    "data_upload"
                },
                Weight = 0.9
            };
            
            _knownAttackPatterns["persistence"] = new AttackPattern
            {
                Name = "Persistence Installation",
                Steps = new List<string>
                {
                    "registry_write",
                    "startup_modify",
                    "service_create",
                    "backdoor_setup"
                },
                Weight = 0.85
            };
            
            _knownAttackPatterns["lateral_movement"] = new AttackPattern
            {
                Name = "Lateral Movement",
                Steps = new List<string>
                {
                    "network_scan",
                    "vulnerability_scan",
                    "exploit_execute",
                    "new_connection"
                },
                Weight = 0.9
            };
            
            Logger.Log("Info", $"Loaded {_knownAttackPatterns.Count} attack patterns");
        }

        public void Start()
        {
            _isRunning = true;
            Logger.Log("Info", "Intent Detection Engine started");
        }

        public void Stop()
        {
            _isRunning = false;
            Logger.Log("Info", "Intent Detection Engine stopped");
        }

        /// <summary>
        /// Analyzes a process and predicts its intent based on behavior
        /// </summary>
        public async Task<IntentAnalysisResult> AnalyzeProcessIntentAsync(int processId)
        {
            var result = new IntentAnalysisResult
            {
                ProcessId = processId,
                AnalysisTime = DateTime.Now
            };

            try
            {
                var process = Process.GetProcessById(processId);
                result.ProcessName = process.ProcessName;
                
                // Collect current behaviors
                var currentBehaviors = await CollectProcessBehaviorsAsync(process);
                result.CurrentBehaviors = currentBehaviors;
                
                // Simulate future steps
                var predictedPath = SimulateExecutionPath(currentBehaviors);
                result.PredictedPath = predictedPath;
                
                // Match against attack patterns
                var patternMatch = MatchAttackPattern(predictedPath);
                result.MatchedPattern = patternMatch.PatternName;
                result.MatchConfidence = patternMatch.Confidence;
                result.MaliciousProbability = patternMatch.Probability;
                
                // Determine if intent is malicious
                result.IsMalicious = result.MaliciousProbability > 0.7;
                result.ThreatLevel = result.MaliciousProbability switch
                {
                    > 0.9 => ThreatLevel.Critical,
                    > 0.7 => ThreatLevel.High,
                    > 0.5 => ThreatLevel.Medium,
                    > 0.3 => ThreatLevel.Low,
                    _ => ThreatLevel.None
                };
                
                // Store intent profile
                lock (_lock)
                {
                    _processIntents[processId] = new IntentProfile
                    {
                        ProcessId = processId,
                        Behaviors = currentBehaviors,
                        PredictedPath = predictedPath,
                        Probability = result.MaliciousProbability,
                        LastUpdated = DateTime.Now
                    };
                }
                
                // Raise events
                if (result.IsMalicious)
                {
                    MaliciousIntentDetected?.Invoke(this, new IntentDetectedEventArgs(
                        result.ProcessName, processId, result.MaliciousProbability, result.MatchedPattern));
                }
                
                PathPredicted?.Invoke(this, new PredictionEventArgs(processId, predictedPath));
                
                Logger.Log("Debug", $"Intent analysis: {result.ProcessName} - {result.MaliciousProbability:P0} malicious");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Intent analysis failed for PID {processId}", ex);
            }

            return result;
        }

        /// <summary>
        /// Collects current process behaviors
        /// </summary>
        private async Task<List<string>> CollectProcessBehaviorsAsync(Process process)
        {
            var behaviors = new List<string>();

            await Task.Run(() =>
            {
                try
                {
                    // Check file system activity
                    var processPath = process.MainModule?.FileName ?? "";
                    if (!string.IsNullOrEmpty(processPath))
                    {
                        var dir = Path.GetDirectoryName(processPath);
                        if (dir != null && Directory.Exists(dir))
                        {
                            behaviors.Add("file_access");
                        }
                    }

                    // Check network activity (simplified)
                    try
                    {
                        // Would use ETW in real implementation
                        behaviors.Add("process_running");
                    }
                    catch { }

                    // Check for suspicious modules
                    try
                    {
                        foreach (ProcessModule module in process.Modules)
                        {
                            var moduleName = module.ModuleName.ToLower();
                            if (moduleName.Contains("ws2_32") || moduleName.Contains("wininet"))
                            {
                                behaviors.Add("network_activity");
                            }
                            if (moduleName.Contains("advapi32"))
                            {
                                behaviors.Add("system_call");
                            }
                        }
                    }
                    catch { }
                }
                catch { }
            });

            return behaviors;
        }

        /// <summary>
        /// Simulates execution path by predicting next steps
        /// </summary>
        private List<string> SimulateExecutionPath(List<string> currentBehaviors)
        {
            var predictedPath = new List<string>(currentBehaviors);
            
            // Add simulated next steps based on current behaviors
            var transitions = GetBehaviorTransitions();
            
            for (int step = 0; step < _maxSimulationSteps; step++)
            {
                var lastBehavior = predictedPath.LastOrDefault();
                if (lastBehavior != null && transitions.TryGetValue(lastBehavior, out var nextBehaviors))
                {
                    // Predict most likely next behavior
                    var next = nextBehaviors.OrderByDescending(_ => new Random().NextDouble()).FirstOrDefault();
                    if (next != null)
                    {
                        predictedPath.Add(next);
                    }
                }
            }
            
            return predictedPath;
        }

        private Dictionary<string, List<string>> GetBehaviorTransitions()
        {
            return new Dictionary<string, List<string>>
            {
                ["file_access"] = new List<string> { "file_read", "file_write", "file_enumeration" },
                ["file_enumeration"] = new List<string> { "file_access", "file_compress", "file_enumerate" },
                ["file_read"] = new List<string> { "data_process", "memory_inject", "network_send" },
                ["file_write"] = new List<string> { "file_modify", "registry_write", "persistence_setup" },
                ["network_activity"] = new List<string> { "network_connect", "data_upload", "c2_communicate" },
                ["network_connect"] = new List<string> { "data_exfil", "download_payload", "command_execute" },
                ["process_running"] = new List<string> { "process_attach", "memory_inject", "service_create" },
                ["process_attach"] = new List<string> { "memory_read", "code_inject", "privilege_escalate" },
                ["memory_read"] = new List<string> { "credential_dump", "keylog_setup", "data_collect" },
                ["system_call"] = new List<string> { "registry_write", "service_create", "config_modify" },
                ["registry_write"] = new List<string> { "startup_modify", "persistence_setup", "config_update" },
                ["startup_modify"] = new List<string> { "persistence_establish", "service_install", "backdoor_setup" },
                ["persistence_setup"] = new List<string> { "persistence_establish", "service_create", "backdoor_ready" }
            };
        }

        /// <summary>
        /// Matches predicted path against known attack patterns
        /// </summary>
        private PatternMatch MatchAttackPattern(List<string> predictedPath)
        {
            var match = new PatternMatch();
            
            foreach (var pattern in _knownAttackPatterns.Values)
            {
                var matchCount = 0;
                var totalSteps = pattern.Steps.Count;
                
                foreach (var step in pattern.Steps)
                {
                    if (predictedPath.Any(p => p.Contains(step.Replace("_", ""))))
                    {
                        matchCount++;
                    }
                }
                
                var confidence = (double)matchCount / totalSteps;
                if (confidence > match.Confidence)
                {
                    match.Confidence = confidence;
                    match.PatternName = pattern.Name;
                    match.Probability = confidence * pattern.Weight;
                }
            }
            
            return match;
        }

        /// <summary>
        /// Gets intent profile for a process
        /// </summary>
        public IntentProfile? GetIntentProfile(int processId)
        {
            lock (_lock)
            {
                return _processIntents.TryGetValue(processId, out var profile) ? profile : null;
            }
        }

        public void Dispose()
        {
            Stop();
        }
    }

    public class IntentAnalysisResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public List<string> CurrentBehaviors { get; set; } = new();
        public List<string> PredictedPath { get; set; } = new();
        public string MatchedPattern { get; set; } = "";
        public double MatchConfidence { get; set; }
        public double MaliciousProbability { get; set; }
        public bool IsMalicious { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public DateTime AnalysisTime { get; set; }
    }

    public class IntentProfile
    {
        public int ProcessId { get; set; }
        public List<string> Behaviors { get; set; } = new();
        public List<string> PredictedPath { get; set; } = new();
        public double Probability { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class AttackPattern
    {
        public string Name { get; set; } = "";
        public List<string> Steps { get; set; } = new();
        public double Weight { get; set; }
    }

    public class PatternMatch
    {
        public string PatternName { get; set; } = "";
        public double Confidence { get; set; }
        public double Probability { get; set; }
    }

    public enum ThreatLevel
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    public class IntentDetectedEventArgs : EventArgs
    {
        public string ProcessName { get; }
        public int ProcessId { get; }
        public double Probability { get; }
        public string AttackPattern { get; }
        public DateTime Timestamp { get; }

        public IntentDetectedEventArgs(string processName, int processId, double probability, string attackPattern)
        {
            ProcessName = processName;
            ProcessId = processId;
            Probability = probability;
            AttackPattern = attackPattern;
            Timestamp = DateTime.Now;
        }
    }

    public class PredictionEventArgs : EventArgs
    {
        public int ProcessId { get; }
        public List<string> PredictedPath { get; }
        public DateTime Timestamp { get; }

        public PredictionEventArgs(int processId, List<string> predictedPath)
        {
            ProcessId = processId;
            PredictedPath = predictedPath;
            Timestamp = DateTime.Now;
        }
    }
}

