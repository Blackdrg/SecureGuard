using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 4: Attack Chain Reconstruction (Digital Forensics AI)
    /// Reconstructs and visualizes complete attack chains after threat detection
    /// Shows: Entry Point → Privilege Escalation → Persistence → Data Access → Exfiltration
    /// </summary>
    public class AttackChainReconstructor : IDisposable
    {
        private readonly List<AttackChain> _attackChains = new();
        private readonly object _lock = new();
        private bool _isRecording;
        
        // Attack stages
        private static readonly string[] AttackStages = new[]
        {
            "InitialAccess",
            "Execution",
            "Persistence",
            "PrivilegeEscalation",
            "DefenseEvasion",
            "CredentialAccess",
            "Discovery",
            "LateralMovement",
            "Collection",
            "Exfiltration",
            "Impact"
        };

        public event EventHandler<AttackChainEventArgs>? ChainReconstructed;

        public AttackChainReconstructor()
        {
            Logger.Log("Info", "Attack Chain Reconstructor initialized");
        }

        public void StartRecording()
        {
            _isRecording = true;
            Logger.Log("Info", "Attack chain recording started");
        }

        public void StopRecording()
        {
            _isRecording = false;
            Logger.Log("Info", "Attack chain recording stopped");
        }

        /// <summary>
        /// Records an attack step as part of an attack chain
        /// </summary>
        public void RecordAttackStep(AttackStep step)
        {
            if (!_isRecording) return;
            
            lock (_lock)
            {
                // Find or create attack chain
                var chain = _attackChains.FirstOrDefault(c => 
                    c.ThreatId == step.ThreatId && c.Status == ChainStatus.Active);
                
                if (chain == null)
                {
                    chain = new AttackChain
                    {
                        ThreatId = step.ThreatId,
                        StartTime = step.Timestamp,
                        Status = ChainStatus.Active
                    };
                    _attackChains.Add(chain);
                }
                
                // Add step to chain
                chain.Steps.Add(step);
                chain.LastStepTime = step.Timestamp;
                
                // Update chain metadata
                UpdateChainMetadata(chain, step);
                
                Logger.Log("Debug", $"Recorded attack step: {step.Stage} - {step.Description}");
            }
        }

        private void UpdateChainMetadata(AttackChain chain, AttackStep step)
        {
            // Update entry point
            if (step.Stage == "InitialAccess" && chain.EntryPoint == null)
            {
                chain.EntryPoint = step;
            }
            
            // Update severity based on stages
            var severityMap = new Dictionary<string, int>
            {
                ["InitialAccess"] = 1,
                ["Execution"] = 2,
                ["Persistence"] = 3,
                ["PrivilegeEscalation"] = 4,
                ["DefenseEvasion"] = 2,
                ["CredentialAccess"] = 4,
                ["Discovery"] = 2,
                ["LateralMovement"] = 3,
                ["Collection"] = 3,
                ["Exfiltration"] = 5,
                ["Impact"] = 5
            };
            
            var stageSeverity = severityMap.GetValueOrDefault(step.Stage, 1);
            if (stageSeverity > chain.MaxSeverity)
            {
                chain.MaxSeverity = stageSeverity;
            }
            
            // Determine attack type based on chain
            chain.AttackType = DetermineAttackType(chain);
            
            // Calculate completeness
            chain.Completeness = CalculateCompleteness(chain);
            
            // Determine if chain is complete (reached impact)
            if (step.Stage == "Impact")
            {
                chain.Status = ChainStatus.Complete;
                chain.EndTime = step.Timestamp;
                
                ChainReconstructed?.Invoke(this, new AttackChainEventArgs(chain));
            }
        }

        private string DetermineAttackType(AttackChain chain)
        {
            var stages = chain.Steps.Select(s => s.Stage).ToHashSet();
            
            if (stages.Contains("Exfiltration") && stages.Contains("CredentialAccess"))
                return "Data Theft Attack";
            if (stages.Contains("Impact") && stages.Contains("Encryption"))
                return "Ransomware Attack";
            if (stages.Contains("LateralMovement"))
                return "Lateral Movement Attack";
            if (stages.Contains("Persistence") && stages.Contains("PrivilegeEscalation"))
                return "Advanced Persistent Threat";
            if (stages.Contains("Collection") && stages.Contains("Exfiltration"))
                return "Espionage Attack";
            
            return "Malware Infection";
        }

        private double CalculateCompleteness(AttackChain chain)
        {
            var coveredStages = chain.Steps.Select(s => s.Stage).ToHashSet();
            return (double)coveredStages.Count / AttackStages.Length;
        }

        /// <summary>
        /// Reconstructs attack chain from threat data
        /// </summary>
        public async Task<AttackChain?> ReconstructChainAsync(string threatId)
        {
            return await Task.Run(() =>
            {
                lock (_lock)
                {
                    return _attackChains.FirstOrDefault(c => c.ThreatId == threatId);
                }
            });
        }

        /// <summary>
        /// Gets all attack chains
        /// </summary>
        public List<AttackChain> GetAllChains()
        {
            lock (_lock)
            {
                return _attackChains.OrderByDescending(c => c.LastStepTime).ToList();
            }
        }

        /// <summary>
        /// Gets active attack chains
        /// </summary>
        public List<AttackChain> GetActiveChains()
        {
            lock (_lock)
            {
                return _attackChains
                    .Where(c => c.Status == ChainStatus.Active)
                    .OrderByDescending(c => c.LastStepTime)
                    .ToList();
            }
        }

        /// <summary>
        /// Generates attack chain visualization data
        /// </summary>
        public AttackChainVisualization GetVisualization(string threatId)
        {
            var visualization = new AttackChainVisualization();
            
            lock (_lock)
            {
                var chain = _attackChains.FirstOrDefault(c => c.ThreatId == threatId);
                if (chain == null) return visualization;
                
                visualization.ChainId = chain.Id;
                visualization.ThreatId = chain.ThreatId;
                visualization.AttackType = chain.AttackType;
                visualization.StartTime = chain.StartTime;
                visualization.EndTime = chain.EndTime ?? DateTime.Now;
                visualization.Status = chain.Status.ToString();
                visualization.Completeness = chain.Completeness;
                
                // Generate timeline nodes
                foreach (var step in chain.Steps.OrderBy(s => s.Timestamp))
                {
                    visualization.Nodes.Add(new TimelineNode
                    {
                        Id = step.Id,
                        Stage = step.Stage,
                        Title = GetStageTitle(step.Stage),
                        Description = step.Description,
                        Timestamp = step.Timestamp,
                        Details = step.Details,
                        MitreTechnique = step.MitreTechnique,
                        Severity = step.Severity
                    });
                }
                
                // Generate connections between nodes
                for (int i = 0; i < visualization.Nodes.Count - 1; i++)
                {
                    visualization.Connections.Add(new NodeConnection
                    {
                        From = visualization.Nodes[i].Id,
                        To = visualization.Nodes[i + 1].Id
                    });
                }
                
                // Calculate attack duration
                if (chain.StartTime != default && chain.LastStepTime != default)
                {
                    visualization.Duration = chain.LastStepTime - chain.StartTime;
                }
            }
            
            return visualization;
        }

        private string GetStageTitle(string stage)
        {
            return stage switch
            {
                "InitialAccess" => "Initial Access",
                "Execution" => "Execution",
                "Persistence" => "Persistence",
                "PrivilegeEscalation" => "Privilege Escalation",
                "DefenseEvasion" => "Defense Evasion",
                "CredentialAccess" => "Credential Access",
                "Discovery" => "Discovery",
                "LateralMovement" => "Lateral Movement",
                "Collection" => "Collection",
                "Exfiltration" => "Exfiltration",
                "Impact" => "Impact",
                _ => stage
            };
        }

        /// <summary>
        /// Exports attack chain to forensic report
        /// </summary>
        public async Task<string> ExportForensicReportAsync(string threatId)
        {
            var chain = await ReconstructChainAsync(threatId);
            if (chain == null) return "No attack chain found";
            
            var report = new ForensicReport
            {
                ReportId = Guid.NewGuid().ToString(),
                GeneratedTime = DateTime.Now,
                AttackChain = chain,
                Visualization = GetVisualization(threatId)
            };
            
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            });
            
            // Save to file
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "forensics", $"{threatId}_report.json");
            
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, json);
            
            Logger.Log("Info", $"Forensic report generated: {path}");
            
            return path;
        }

        /// <summary>
        /// Gets attack chain statistics
        /// </summary>
        public ChainStatistics GetStatistics()
        {
            lock (_lock)
            {
                return new ChainStatistics
                {
                    TotalChains = _attackChains.Count,
                    ActiveChains = _attackChains.Count(c => c.Status == ChainStatus.Active),
                    CompleteChains = _attackChains.Count(c => c.Status == ChainStatus.Complete),
                    AverageDuration = _attackChains.Any(c => c.EndTime.HasValue) 
                        ? TimeSpan.FromTicks((long)_attackChains
                            .Where(c => c.EndTime.HasValue)
                            .Average(c => (c.EndTime!.Value - c.StartTime).Ticks))
                        : TimeSpan.Zero,
                    MostCommonAttackType = _attackChains
                        .GroupBy(c => c.AttackType)
                        .OrderByDescending(g => g.Count())
                        .FirstOrDefault()?.Key ?? "Unknown",
                    AttackTypes = _attackChains
                        .GroupBy(c => c.AttackType)
                        .ToDictionary(g => g.Key, g => g.Count())
                };
            }
        }

        public void Dispose()
        {
            StopRecording();
        }
    }

    public class AttackStep
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string ThreatId { get; set; } = "";
        public string Stage { get; set; } = "";
        public string Description { get; set; } = "";
        public string Details { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string SourceProcess { get; set; } = "";
        public string TargetProcess { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string MitreTechnique { get; set; } = "";
        public int Severity { get; set; }
    }

    public class AttackChain
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string ThreatId { get; set; } = "";
        public string AttackType { get; set; } = "";
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public DateTime LastStepTime { get; set; }
        public ChainStatus Status { get; set; }
        public List<AttackStep> Steps { get; set; } = new();
        public AttackStep? EntryPoint { get; set; }
        public int MaxSeverity { get; set; }
        public double Completeness { get; set; }
    }

    public class AttackChainVisualization
    {
        public string ChainId { get; set; } = "";
        public string ThreatId { get; set; } = "";
        public string AttackType { get; set; } = "";
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public string Status { get; set; } = "";
        public double Completeness { get; set; }
        public List<TimelineNode> Nodes { get; set; } = new();
        public List<NodeConnection> Connections { get; set; } = new();
    }

    public class TimelineNode
    {
        public string Id { get; set; } = "";
        public string Stage { get; set; } = "";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Details { get; set; } = "";
        public string MitreTechnique { get; set; } = "";
        public int Severity { get; set; }
    }

    public class NodeConnection
    {
        public string From { get; set; } = "";
        public string To { get; set; } = "";
    }

    public class ChainStatistics
    {
        public int TotalChains { get; set; }
        public int ActiveChains { get; set; }
        public int CompleteChains { get; set; }
        public TimeSpan AverageDuration { get; set; }
        public string MostCommonAttackType { get; set; } = "";
        public Dictionary<string, int> AttackTypes { get; set; } = new();
    }

    public class ForensicReport
    {
        public string ReportId { get; set; } = "";
        public DateTime GeneratedTime { get; set; }
        public AttackChain AttackChain { get; set; } = new();
        public AttackChainVisualization Visualization { get; set; } = new();
    }

    public enum ChainStatus
    {
        Active,
        Complete,
        Contained,
        Eradicated
    }

    public class AttackChainEventArgs : EventArgs
    {
        public AttackChain Chain { get; }
        
        public AttackChainEventArgs(AttackChain chain)
        {
            Chain = chain;
        }
    }
}

