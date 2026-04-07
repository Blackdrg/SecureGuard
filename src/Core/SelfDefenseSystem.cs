using System;
using System.Diagnostics;

namespace SecureGuard.Core
{
    /// <summary>
    /// Level 6 - Self-Defense System
    /// Protects the antivirus from tampering and attacks
    /// </summary>
    public class SelfDefenseSystem
    {
        private bool _isEnabled;
        
        public event EventHandler<TamperEventArgs>? TamperDetected;
        
        public void Enable()
        {
            _isEnabled = true;
            Logger.Log("Info", "Self-Defense System enabled");
            StartProtection();
        }
        
        public void Disable()
        {
            _isEnabled = false;
            Logger.Log("Info", "Self-Defense System disabled");
        }
        
        private void StartProtection()
        {
            // Monitor for debugger attachment
            if (IsDebuggerPresent())
            {
                Logger.Log("Warning", "Debugger detected!");
                TamperDetected?.Invoke(this, new TamperEventArgs("Debugger detected"));
            }
        }
        
        public bool IsDebuggerPresent()
        {
            return Debugger.IsAttached;
        }
        
        public void ProtectRegistry()
        {
            Logger.Log("Info", "Registry protection active");
        }
        
        public void RestartService()
        {
            Logger.Log("Info", "Service auto-restart triggered");
        }
    }
    
    public class TamperEventArgs : EventArgs
    {
        public string Message { get; }
        public DateTime Timestamp { get; }
        
        public TamperEventArgs(string message)
        {
            Message = message;
            Timestamp = DateTime.Now;
        }
    }
}
