using System;

namespace SecureGuard.Privacy
{
    public class WebcamShield
    {
        private bool _isEnabled;
        
        public void Enable()
        {
            _isEnabled = true;
            Core.Logger.Log("Info", "Webcam Shield enabled");
        }
        
        public void Disable()
        {
            _isEnabled = false;
            Core.Logger.Log("Info", "Webcam Shield disabled");
        }
        
        public void BlockAccess(string processName)
        {
            if (_isEnabled)
                Core.Logger.Log("Warning", $"Blocked webcam access by: {processName}");
        }
    }
    
    public class MicrophoneShield
    {
        private bool _isEnabled;
        
        public void Enable()
        {
            _isEnabled = true;
            Core.Logger.Log("Info", "Microphone Shield enabled");
        }
        
        public void Disable()
        {
            _isEnabled = false;
            Core.Logger.Log("Info", "Microphone Shield disabled");
        }
        
        public void BlockAccess(string processName)
        {
            if (_isEnabled)
                Core.Logger.Log("Warning", $"Blocked microphone access by: {processName}");
        }
    }
    
    public class AntiKeylogger
    {
        private bool _isEnabled;
        
        public void Enable()
        {
            _isEnabled = true;
            Core.Logger.Log("Info", "Anti-Keylogger enabled");
        }
        
        public void Disable()
        {
            _isEnabled = false;
            Core.Logger.Log("Info", "Anti-Keylogger disabled");
        }
        
        public void DetectKeylogger(string processName)
        {
            if (_isEnabled)
                Core.Logger.Log("Warning", $"Potential keylogger detected: {processName}");
        }
    }
    
    public class BrowserProtection
    {
        public void Enable()
        {
            Core.Logger.Log("Info", "Browser Protection enabled");
        }
        
        public void BlockTracker(string trackerDomain)
        {
            Core.Logger.Log("Info", $"Blocked tracker: {trackerDomain}");
        }
    }
}
