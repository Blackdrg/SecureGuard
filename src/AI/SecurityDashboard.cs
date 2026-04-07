using System;
using System.Collections.Generic;
using System.Timers;

namespace SecureGuard.AI
{
    public class SecurityDashboard : IDisposable
    {
        private readonly Timer _updateTimer;
        private int _attackAttempts;
        private double _securityScore = 100.0;
        private int _threatsBlocked;
        private int _vulnerabilitiesFound;
        
        public event EventHandler<SecurityScoreEventArgs>? SecurityScoreChanged;
        public event EventHandler<AttackEventArgs>? AttackDetected;

        public SecurityDashboard()
        {
            _updateTimer = new Timer(5000);
            _updateTimer.Elapsed += OnUpdateTimer;
            Core.Logger.Log("Info", "Security Dashboard initialized");
        }

        public void Start()
        {
            _updateTimer.Start();
            Core.Logger.Log("Info", "Security Dashboard started");
        }

        public void Stop()
        {
            _updateTimer.Stop();
            Core.Logger.Log("Info", "Security Dashboard stopped");
        }

        private void OnUpdateTimer(object? sender, ElapsedEventArgs e)
        {
            UpdateSecurityScore();
        }

        private void UpdateSecurityScore()
        {
            var newScore = 100.0;
            newScore -= _vulnerabilitiesFound * 5;
            newScore -= _attackAttempts * 2;
            newScore += _threatsBlocked * 0.5;
            _securityScore = Math.Max(0, Math.Min(100, newScore));
            SecurityScoreChanged?.Invoke(this, new SecurityScoreEventArgs(_securityScore));
        }

        public void RecordAttackAttempt(string attackType)
        {
            _attackAttempts++;
            AttackDetected?.Invoke(this, new AttackEventArgs(attackType, _attackAttempts));
            Core.Logger.Log("Warning", $"Attack attempt recorded: {attackType}");
        }

        public void RecordThreatBlocked()
        {
            _threatsBlocked++;
            Core.Logger.Log("Info", $"Threats blocked: {_threatsBlocked}");
        }

        public void RecordVulnerability(string vulnerability)
        {
            _vulnerabilitiesFound++;
            Core.Logger.Log("Warning", $"Vulnerability found: {vulnerability}");
        }

        public DashboardData GetDashboardData()
        {
            return new DashboardData
            {
                SecurityScore = _securityScore,
                ThreatsBlocked = _threatsBlocked,
                AttackAttempts = _attackAttempts,
                Vulnerabilities = _vulnerabilitiesFound,
                ProtectionStatus = _securityScore > 70 ? "Protected" : "At Risk",
                LastUpdated = DateTime.Now
            };
        }

        public void Dispose() 
        { 
            Stop(); 
            _updateTimer.Dispose(); 
        }
    }

    public class SecurityScoreEventArgs : EventArgs
    {
        public double Score { get; }
        public DateTime Timestamp { get; }
        public SecurityScoreEventArgs(double score) 
        { 
            Score = score; 
            Timestamp = DateTime.Now; 
        }
    }

    public class AttackEventArgs : EventArgs
    {
        public string AttackType { get; }
        public int TotalAttempts { get; }
        public DateTime Timestamp { get; }
        public AttackEventArgs(string attackType, int totalAttempts) 
        { 
            AttackType = attackType; 
            TotalAttempts = totalAttempts; 
            Timestamp = DateTime.Now; 
        }
    }

    public class DashboardData
    {
        public double SecurityScore { get; set; }
        public int ThreatsBlocked { get; set; }
        public int AttackAttempts { get; set; }
        public int Vulnerabilities { get; set; }
        public string ProtectionStatus { get; set; } = "";
        public DateTime LastUpdated { get; set; }
    }
}
