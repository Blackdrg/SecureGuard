using System;
using Microsoft.Win32;
using Microsoft.VisualBasic;

namespace SecureGuard.Core
{
    public static class CompatibilityChecker
    {
        public static bool IsCompatible()
        {
            var osVersion = Environment.OSVersion.Version;
            var ram = GetTotalPhysicalMemory();
            var cpuCount = Environment.ProcessorCount;
            // Example: Require Windows 10+, 2GB+ RAM, 2+ CPUs
            return osVersion.Major >= 10 && ram >= 2L * 1024 * 1024 * 1024 && cpuCount >= 2;
        }

        private static ulong GetTotalPhysicalMemory()
        {
            // Use Win32 API for Windows
            var searcher = new System.Management.ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                return (ulong)(obj["TotalPhysicalMemory"] ?? 0);
            }
            return 0;
        }
    }
}
