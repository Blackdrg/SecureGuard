using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Memory Scanner module for Level 2 Real-Time Protection
    /// Scans running processes for malicious memory patterns
    /// </summary>
    public class MemoryScanner : IDisposable
    {
        private readonly MultiLayerDetectionEngine _detectionEngine;
        private CancellationTokenSource? _scanCancellation;
        private bool _isScanning;

        public event EventHandler<MemoryThreatDetectedEventArgs>? ThreatDetected;
        public event EventHandler<ScanProgressEventArgs>? ScanProgress;

        // P/Invoke declarations
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesRead);

        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        // Known malicious memory patterns (simplified for demonstration)
        private static readonly byte[][] MaliciousPatterns = new byte[][]
        {
            new byte[] { 0x90, 0x90, 0x90, 0x90 }, // NOP sled
            new byte[] { 0xCC, 0xCC, 0xCC, 0xCC },   // Debug interrupt
            new byte[] { 0xE8, 0x00, 0x00, 0x00 },  // Call near
            new byte[] { 0xEB, 0x00, 0x00, 0x00 },  // JMP short
        };

        public MemoryScanner(MultiLayerDetectionEngine detectionEngine)
        {
            _detectionEngine = detectionEngine;
        }

        /// <summary>
        /// Scans all running processes for memory threats
        /// </summary>
        public List<MemoryThreatInfo> ScanAllProcesses(IProgress<int>? progress = null)
        {
            var threats = new List<MemoryThreatInfo>();
            _isScanning = true;
            _scanCancellation = new CancellationTokenSource();

            try
            {
                var processes = Process.GetProcesses();
                var total = processes.Length;
                var current = 0;

                foreach (var process in processes)
                {
                    if (_scanCancellation.Token.IsCancellationRequested)
                        break;

                    try
                    {
                        var processThreats = ScanProcess(process);
                        threats.AddRange(processThreats);

                        foreach (var threat in processThreats)
                        {
                            ThreatDetected?.Invoke(this, new MemoryThreatDetectedEventArgs(
                                process.ProcessName,
                                threat.ThreatDescription,
                                threat.Severity));
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("Warning", $"Could not scan process: {process.ProcessName}", ex);
                    }
                    finally
                    {
                        process.Dispose();
                        current++;
                        progress?.Report((current * 100) / total);
                        ScanProgress?.Invoke(this, new ScanProgressEventArgs(current, total, process.ProcessName));
                    }
                }
            }
            finally
            {
                _isScanning = false;
            }

            return threats;
        }

        /// <summary>
        /// Scans a specific process for memory threats
        /// </summary>
        public List<MemoryThreatInfo> ScanProcess(Process process)
        {
            var threats = new List<MemoryThreatInfo>();

            try
            {
                var hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, (uint)process.Id);
                if (hProcess == IntPtr.Zero)
                    return threats;

                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        try
                        {
                            var moduleThreats = ScanMemoryRegion(hProcess, module.BaseAddress, (int)module.ModuleMemorySize);
                            threats.AddRange(moduleThreats);
                        }
                        catch
                        {
                            // Skip inaccessible modules
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Warning", $"Error scanning process {process.ProcessName}", ex);
            }

            return threats;
        }

        private List<MemoryThreatInfo> ScanMemoryRegion(IntPtr hProcess, IntPtr baseAddress, int size)
        {
            var threats = new List<MemoryThreatInfo>();
            const int bufferSize = 4096;

            for (int offset = 0; offset < size; offset += bufferSize)
            {
                var buffer = new byte[bufferSize];
                if (ReadProcessMemory(hProcess, baseAddress + offset, buffer, (uint)bufferSize, out uint bytesRead) && bytesRead > 0)
                {
                    // Check for malicious patterns
                    for (int i = 0; i < MaliciousPatterns.Length; i++)
                    {
                        var pattern = MaliciousPatterns[i];
                        if (ContainsPattern(buffer, pattern))
                        {
                            threats.Add(new MemoryThreatInfo
                            {
                                ProcessId = (int)GetProcessId(hProcess),
                                ProcessName = "",
                                Address = baseAddress + offset,
                                ThreatType = "Malicious Pattern",
                                ThreatDescription = $"Suspicious memory pattern detected at offset {offset}",
                                Severity = ThreatSeverity.High
                            });
                        }
                    }
                }
            }

            return threats;
        }

        private bool ContainsPattern(byte[] buffer, byte[] pattern)
        {
            if (buffer.Length < pattern.Length) return false;

            for (int i = 0; i <= buffer.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }

        [DllImport("kernel32.dll")]
        private static extern uint GetProcessId(IntPtr hProcess);

        /// <summary>
        /// Cancels an ongoing memory scan
        /// </summary>
        public void CancelScan()
        {
            _scanCancellation?.Cancel();
        }

        public bool IsScanning => _isScanning;

        public void Dispose()
        {
            CancelScan();
            _scanCancellation?.Dispose();
        }
    }

    public class MemoryThreatInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public IntPtr Address { get; set; }
        public string ThreatType { get; set; } = "";
        public string ThreatDescription { get; set; } = "";
        public ThreatSeverity Severity { get; set; }
    }


    public class MemoryThreatDetectedEventArgs : EventArgs
    {
        public string ProcessName { get; }
        public string ThreatDescription { get; }
        public ThreatSeverity Severity { get; }
        public DateTime Timestamp { get; }

        public MemoryThreatDetectedEventArgs(string processName, string threatDescription, ThreatSeverity severity)
        {
            ProcessName = processName;
            ThreatDescription = threatDescription;
            Severity = severity;
            Timestamp = DateTime.Now;
        }
    }

    public class ScanProgressEventArgs : EventArgs
    {
        public int Current { get; }
        public int Total { get; }
        public string CurrentProcess { get; }
        public DateTime Timestamp { get; }

        public ScanProgressEventArgs(int current, int total, string currentProcess)
        {
            Current = current;
            Total = total;
            CurrentProcess = currentProcess;
            Timestamp = DateTime.Now;
        }
    }
}

