using System.ServiceProcess;

namespace SecureGuard.Service
{
    public class SecureGuardService : ServiceBase
    {
        private Core.RealTimeProtectionEngine _rtpEngine;

        public SecureGuardService()
        {
            ServiceName = "SecureGuardService";
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = true;
            _rtpEngine = new Core.RealTimeProtectionEngine();
        }

        protected override void OnStart(string[] args)
        {
            // Start real-time protection modules
            _rtpEngine.StartFileSystemMonitoring();
            _rtpEngine.StartProcessMonitoring();
            // TODO: Start other modules as needed
        }

        protected override void OnStop()
        {
            // TODO: Cleanup resources
            // Optionally stop monitoring
        }
    }

    static class Program
    {
        static void Main()
        {
            ServiceBase.Run(new SecureGuardService());
        }
    }
}
