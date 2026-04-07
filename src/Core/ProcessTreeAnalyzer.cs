using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    public class ProcessTreeAnalyzer : IDisposable
    {
        private bool _isRunning;
        private CancellationTokenSource? _cts;
        private readonly Dictionary<int, List<int>> _processTree = new();
        private readonly object _lock = new();

        public event EventHandler<SuspiciousProcessEventArgs>? SuspiciousProcessDetected;
        public event EventHandler<PrivilegeEscalationEventArgs>? PrivilegeEscalationDetected;
        public event EventHandler<CodeInjectionEventArgs>? CodeInjectionDetected;

        public ProcessTreeAnalyzer()
        {
            Logger.Log("Info", "Process Tree Analyzer initialized");
        }

        public void Start()
        {
            if (_isRunning) return;
            _cts = new CancellationTokenSource();
            _isRunning = true;
            Task.Run(() => AnalyzeProcessTree(_cts.Token));
            Logger.Log("Info", "Process Tree Analyzer started");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts?.Cancel();
            Logger.Log("Info", "Process Tree Analyzer stopped");
        }

        private async Task AnalyzeProcessTree(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    BuildProcessTree();
                    DetectSuspiciousProcesses();
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Process tree analysis error", ex);
                }
                await Task.Delay(5000, token);
            }
        }

        private void BuildProcessTree()
        {
            lock (_lock)
            {
                _processTree.Clear();
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    try
                    {
                        if (proc.Id != 0)
                        {
                            var parentId = GetParentProcessId(proc);
                            if (parentId > 0)
                            {
                                if (!_processTree.ContainsKey(parentId))
                                    _processTree[parentId] = new List<int>();
                                _processTree[parentId].Add(proc.Id);
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        private int GetParentProcessId(Process process)
        {
            try
            {
                var query = $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {process.Id}";
                using var searcher = new System.Management.ManagementObjectSearcher(query);
                foreach (var obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ParentProcessId"]);
                }
            }
            catch { }
            return 0;
        }

        private void DetectSuspiciousProcesses()
        {
            var suspiciousNames = new[] { "mimikatz", "pwdump", "procdump", "lsass", "netcat" };
            lock (_lock)
            {
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    try
                    {
                        var name = proc.ProcessName.ToLower();
                        if (suspiciousNames.Any(s => name.Contains(s)))
                        {
                            SuspiciousProcessDetected?.Invoke(this, new SuspiciousProcessEventArgs(proc.ProcessName, proc.Id, "Known hacking tool"));
                        }
                    }
                    catch { }
                }
            }
        }

        public List<ProcessInfo> GetProcessTree()
        {
            var result = new List<ProcessInfo>();
            lock (_lock)
            {
                foreach (var kvp in _processTree)
                {
                    try
                    {
                        var parent = Process.GetProcessById(kvp.Key);
                        result.Add(new ProcessInfo { ProcessId = kvp.Key, ProcessName = parent.ProcessName, ChildProcesses = kvp.Value.Count });
                    }
                    catch { }
                }
            }
            return result;
        }

        public void Dispose() { Stop(); _cts?.Dispose(); }
    }

    public class SuspiciousProcessEventArgs : EventArgs
    {
        public string ProcessName { get; }
        public int ProcessId { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public SuspiciousProcessEventArgs(string processName, int processId, string reason)
        {
            ProcessName = processName;
            ProcessId = processId;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }

    public class PrivilegeEscalationEventArgs : EventArgs
    {
        public string ProcessName { get; }
        public int ProcessId { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public PrivilegeEscalationEventArgs(string processName, int processId, string reason)
        {
            ProcessName = processName;
            ProcessId = processId;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }

    public class CodeInjectionEventArgs : EventArgs
    {
        public string ProcessName { get; }
        public int ProcessId { get; }
        public string InjectionType { get; }
        public DateTime Timestamp { get; }

        public CodeInjectionEventArgs(string processName, int processId, string injectionType)
        {
            ProcessName = processName;
            ProcessId = processId;
            InjectionType = injectionType;
            Timestamp = DateTime.Now;
        }
    }

    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public int ChildProcesses { get; set; }
    }
}

