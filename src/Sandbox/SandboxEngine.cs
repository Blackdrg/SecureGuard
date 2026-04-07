using System;
using System.Collections.Generic;

namespace SecureGuard.Sandbox
{
    public class SandboxEngine : IDisposable
    {
        private readonly List<SandboxResult> _results = new();
        private bool _isRunning;
        
        public event EventHandler<SandboxEventArgs>? ThreatDetected;
        
        public void Start()
        {
            _isRunning = true;
            Core.Logger.Log("Info", "Sandbox Engine started");
        }
        
        public void Stop()
        {
            _isRunning = false;
            Core.Logger.Log("Info", "Sandbox Engine stopped");
        }
        
        public SandboxResult AnalyzeFile(string filePath)
        {
            var result = new SandboxResult
            {
                FilePath = filePath,
                StartTime = DateTime.Now,
                Status = "Running"
            };
            
            try
            {
                result.Behaviors = AnalyzeBehaviors(filePath);
                result.ThreatClassification = ClassifyThreat(result.Behaviors);
                result.RiskScore = CalculateRiskScore(result.Behaviors);
                result.Status = result.ThreatClassification == "Malicious" ? "Malicious" : "Safe";
            }
            catch (Exception ex)
            {
                result.Status = "Error";
                result.Error = ex.Message;
            }
            
            result.EndTime = DateTime.Now;
            _results.Add(result);
            
            if (result.Status == "Malicious")
                ThreatDetected?.Invoke(this, new SandboxEventArgs(result));
            
            return result;
        }
        
        private List<string> AnalyzeBehaviors(string filePath)
        {
            var behaviors = new List<string>();
            behaviors.Add("Process creation attempted");
            behaviors.Add("Registry modification attempted");
            return behaviors;
        }
        
        private string ClassifyThreat(List<string> behaviors)
        {
            foreach (var behavior in behaviors)
            {
                if (behavior.Contains("malicious") || behavior.Contains("inject"))
                    return "Malicious";
            }
            return "Safe";
        }
        
        private double CalculateRiskScore(List<string> behaviors) => behaviors.Count * 10.0;
        
        public List<SandboxResult> GetResults() => _results;
        
        public void Dispose() => Stop();
    }
    
    public class SandboxResult
    {
        public string FilePath { get; set; } = "";
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string Status { get; set; } = "";
        public List<string> Behaviors { get; set; } = new();
        public string ThreatClassification { get; set; } = "";
        public double RiskScore { get; set; }
        public string? Error { get; set; }
    }
    
    public class SandboxEventArgs : EventArgs
    {
        public SandboxResult Result { get; }
        public SandboxEventArgs(SandboxResult result) => Result = result;
    }
}
