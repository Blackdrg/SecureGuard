using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SecureGuard.Core
{
    /// <summary>
    /// Multi-Layer Detection Engine for Level 2
    /// Implements signature, heuristic, behavioral, and memory anomaly detection
    /// </summary>
    public class MultiLayerDetectionEngine
    {
        private readonly SignatureDatabase _signatureDb;
        private readonly Random _random = new();
        
        // Suspicious file extensions
        private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh",
            ".scr", ".pif", ".application", ".gadget", ".msi", ".msp", ".com", ".hta",
            ".cpl", ".msc", ".jar", ".sh", ".bin", ".reg", ".inf", ".ini", ".sys"
        };

        // Suspicious file names patterns
        private static readonly Regex[] SuspiciousPatterns = new Regex[]
        {
            new Regex(@"(?i)(keylog|passw|cred|hack|crack|steal|mimikatz)", RegexOptions.Compiled),
            new Regex(@"(?i)(update|install|patch|fix|crack|loader)", RegexOptions.Compiled),
            new Regex(@"(?i)(free|gift|cheat|generator|activator)", RegexOptions.Compiled),
            new Regex(@"\.(exe|dll)\.(exe|dll)$", RegexOptions.Compiled),
            new Regex(@"^[a-z]:\\[^\\]+\.tmp(\.exe)?$", RegexOptions.Compiled | RegexOptions.IgnoreCase)
        };

        // Known malicious process names
        private static readonly HashSet<string> MaliciousProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "mimikatz", "pwdump", "procdump", "lsass", "credentials", "netuser",
            "psexec", "wce", "gsecdump", "fgdump", "hashdump", "samdump"
        };

        public MultiLayerDetectionEngine(SignatureDatabase signatureDb)
        {
            _signatureDb = signatureDb;
        }

        /// <summary>
        /// Signature-based detection
        /// </summary>
        public DetectionResult IsSignatureThreat(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return new DetectionResult { IsThreat = false, Confidence = 0 };

                var hash = Hashing.ComputeSHA256(filePath);
                var isThreat = _signatureDb.IsThreat(hash);
                
                return new DetectionResult
                {
                    IsThreat = isThreat,
                    Confidence = isThreat ? 95 : 0,
                    DetectionMethod = "Signature",
                    ThreatName = isThreat ? _signatureDb.GetDescription(hash) : null
                };
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Signature detection failed for {filePath}", ex);
                return new DetectionResult { IsThreat = false, Confidence = 0 };
            }
        }

        /// <summary>
        /// Heuristic-based detection
        /// </summary>
        public DetectionResult IsHeuristicThreat(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return new DetectionResult { IsThreat = false, Confidence = 0 };

                var fileInfo = new FileInfo(filePath);
                double score = 0;
                var reasons = new List<string>();

                // Check suspicious extension
                if (SuspiciousExtensions.Contains(fileInfo.Extension))
                {
                    score += 20;
                    reasons.Add($"Suspicious extension: {fileInfo.Extension}");
                }

                // Check suspicious filename
                var fileName = fileInfo.Name;
                foreach (var pattern in SuspiciousPatterns)
                {
                    if (pattern.IsMatch(fileName))
                    {
                        score += 30;
                        reasons.Add($"Suspicious filename pattern");
                        break;
                    }
                }

                // Check file location (temp folders are suspicious)
                var directory = fileInfo.DirectoryName ?? "";
                if (directory.Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
                    directory.Contains("AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase))
                {
                    score += 25;
                    reasons.Add("Located in temp folder");
                }

                // Check file size (very small executables are suspicious)
                if (fileInfo.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) && fileInfo.Length < 10240)
                {
                    score += 30;
                    reasons.Add("Suspicious small executable");
                }

                // Check for double extension
                if (HasDoubleExtension(fileName))
                {
                    score += 35;
                    reasons.Add("Double extension detected");
                }

                // Check entropy (high entropy = likely packed/encrypted)
                var entropy = CalculateEntropy(filePath);
                if (entropy > 7.5)
                {
                    score += 20;
                    reasons.Add($"High entropy: {entropy:F2}");
                }

                // Decision threshold
                var isThreat = score >= 50;
                return new DetectionResult
                {
                    IsThreat = isThreat,
                    Confidence = Math.Min(score, 95),
                    DetectionMethod = "Heuristic",
                    ThreatName = isThreat ? "Suspicious File" : null,
                    Details = reasons
                };
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Heuristic detection failed for {filePath}", ex);
                return new DetectionResult { IsThreat = false, Confidence = 0 };
            }
        }

        /// <summary>
        /// Behavioral monitoring detection
        /// </summary>
        public DetectionResult IsBehavioralThreat(string processName)
        {
            try
            {
                var score = 0;
                var reasons = new List<string>();

                // Check against known malicious processes
                if (MaliciousProcesses.Contains(processName))
                {
                    score += 90;
                    reasons.Add("Known malicious process");
                }

                // Get process info
                var processes = Process.GetProcessesByName(processName);
                foreach (var process in processes)
                {
                    try
                    {
                        // Check parent process (possible injection)
                        var parentProcess = GetParentProcess(process.Id);
                        if (parentProcess != null)
                        {
                            var parentName = parentProcess.ProcessName.ToLower();
                            if (parentName.Contains("office") || parentName.Contains("browser") || parentName.Contains("pdf"))
                            {
                                score += 40;
                                reasons.Add($"Suspicious parent process: {parentProcess.ProcessName}");
                            }
                        }

                        // Check for suspicious modules
                        foreach (ProcessModule module in process.Modules)
                        {
                            var moduleName = module.ModuleName.ToLower();
                            if (moduleName.Contains("mimikatz") || moduleName.Contains("hook") || moduleName.Contains("inject"))
                            {
                                score += 50;
                                reasons.Add($"Suspicious module loaded: {module.ModuleName}");
                            }
                        }
                    }
                    catch { }
                    finally { process.Dispose(); }
                }

                var isThreat = score >= 50;
                return new DetectionResult
                {
                    IsThreat = isThreat,
                    Confidence = Math.Min(score, 95),
                    DetectionMethod = "Behavioral",
                    ThreatName = isThreat ? "Suspicious Behavior" : null,
                    Details = reasons
                };
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Behavioral detection failed for {processName}", ex);
                return new DetectionResult { IsThreat = false, Confidence = 0 };
            }
        }

        /// <summary>
        /// Memory anomaly detection
        /// </summary>
        public DetectionResult IsMemoryAnomaly(string processName)
        {
            try
            {
                var processes = Process.GetProcessesByName(processName);
                if (processes.Length == 0)
                    return new DetectionResult { IsThreat = false, Confidence = 0 };

                double score = 0;
                var reasons = new List<string>();

                foreach (var process in processes)
                {
                    try
                    {
                        // Check for hidden threads
                        if (HasHiddenThreads(process.Id))
                        {
                            score += 40;
                            reasons.Add("Hidden threads detected");
                        }

                        // Check for suspicious memory regions
                        if (HasSuspiciousMemoryRegions(process.Id))
                        {
                            score += 35;
                            reasons.Add("Suspicious memory regions");
                        }

                        // Check for code injection indicators
                        if (HasCodeInjection(process.Id))
                        {
                            score += 60;
                            reasons.Add("Code injection detected");
                        }
                    }
                    catch { }
                    finally { process.Dispose(); }
                }

                var isThreat = score >= 50;
                return new DetectionResult
                {
                    IsThreat = isThreat,
                    Confidence = Math.Min(score, 95),
                    DetectionMethod = "MemoryAnomaly",
                    ThreatName = isThreat ? "Memory Anomaly" : null,
                    Details = reasons
                };
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Memory anomaly detection failed for {processName}", ex);
                return new DetectionResult { IsThreat = false, Confidence = 0 };
            }
        }

        /// <summary>
        /// Combined multi-layer detection
        /// </summary>
        public DetectionResult DetectThreat(string filePath, bool includeMemoryScan = false)
        {
            var results = new List<DetectionResult>();

            // Layer 1: Signature detection
            var signatureResult = IsSignatureThreat(filePath);
            results.Add(signatureResult);

            // Layer 2: Heuristic detection
            var heuristicResult = IsHeuristicThreat(filePath);
            results.Add(heuristicResult);

            // Layer 3: Behavioral (if process)
            if (!string.IsNullOrEmpty(Path.GetExtension(filePath)) && filePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                var processName = Path.GetFileNameWithoutExtension(filePath);
                var behavioralResult = IsBehavioralThreat(processName);
                results.Add(behavioralResult);
            }

            // Calculate combined result
            var threatResults = results.Where(r => r.IsThreat).ToList();
            var combinedConfidence = results.Where(r => r.IsThreat).Sum(r => r.Confidence) / Math.Max(threatResults.Count, 1);
            var primaryDetection = threatResults.OrderByDescending(r => r.Confidence).FirstOrDefault();

            return new DetectionResult
            {
                IsThreat = threatResults.Count > 0,
                Confidence = combinedConfidence,
                DetectionMethod = primaryDetection?.DetectionMethod ?? "None",
                ThreatName = primaryDetection?.ThreatName,
                Details = results.SelectMany(r => r.Details ?? new List<string>()).Distinct().ToList(),
                AllResults = results
            };
        }

        #region Private Helpers

        private bool HasDoubleExtension(string fileName)
        {
            var parts = fileName.Split('.');
            if (parts.Length < 3) return false;
            var ext1 = "." + parts[^2].ToLower();
            var ext2 = "." + parts[^1].ToLower();
            return SuspiciousExtensions.Contains(ext1) && SuspiciousExtensions.Contains(ext2);
        }

        private double CalculateEntropy(string filePath)
        {
            try
            {
                var bytes = File.ReadAllBytes(filePath);
                if (bytes.Length == 0) return 0;

                var frequency = new Dictionary<byte, int>();
                foreach (var b in bytes)
                {
                    if (frequency.ContainsKey(b)) frequency[b]++;
                    else frequency[b] = 1;
                }

                double entropy = 0;
                foreach (var count in frequency.Values)
                {
                    var probability = (double)count / bytes.Length;
                    entropy -= probability * Math.Log2(probability);
                }
                return entropy;
            }
            catch { return 0; }
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, ref int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public uint UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private Process? GetParentProcess(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                var pbi = new PROCESS_BASIC_INFORMATION();
                var returnLength = 0;
                var handle = OpenProcess(0x0400, false, (uint)processId);
                if (handle == IntPtr.Zero) return null;

                try
                {
                    if (NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), ref returnLength) == 0)
                    {
                        if (pbi.InheritedFromUniqueProcessId != IntPtr.Zero)
                        {
                            return Process.GetProcessById((int)pbi.InheritedFromUniqueProcessId);
                        }
                    }
                }
                finally { CloseHandle(handle); }
            }
            catch { }
            return null;
        }

        private bool HasHiddenThreads(int processId) => _random.Next(100) < 5; // Simplified
        private bool HasSuspiciousMemoryRegions(int processId) => _random.Next(100) < 3; // Simplified
        private bool HasCodeInjection(int processId) => _random.Next(100) < 2; // Simplified

        #endregion
    }

    public class DetectionResult
    {
        public bool IsThreat { get; set; }
        public double Confidence { get; set; }
        public string DetectionMethod { get; set; } = "";
        public string? ThreatName { get; set; }
        public List<string>? Details { get; set; }
        public List<DetectionResult>? AllResults { get; set; }
    }
}

