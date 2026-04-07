using System;

namespace SecureGuard.Core
{
    public enum ThreatSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public enum ThreatAction
    {
        Allowed,
        Blocked,
        Quarantined,
        Deleted,
        Repaired
    }

    public class ThreatLogEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string ThreatName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ThreatSeverity Severity { get; set; } = ThreatSeverity.Low;
        public ThreatAction ActionTaken { get; set; } = ThreatAction.Allowed;
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string DetectionMethod { get; set; } = string.Empty;
        public string FileHash { get; set; } = string.Empty;
        public string ProcessName { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public string DestinationIp { get; set; } = string.Empty;
    }
}
