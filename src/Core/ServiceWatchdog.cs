using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;

namespace SecureGuard.Core
{
    public static class ServiceWatchdog
    {
        public static void Monitor(string serviceName)
        {
            new Thread(() =>
            {
                while (true)
                {
                    var sc = new ServiceController(serviceName);
                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        try { sc.Start(); } catch { }
                    }
                    Thread.Sleep(10000);
                }
            }) { IsBackground = true }.Start();
        }
    }
}
