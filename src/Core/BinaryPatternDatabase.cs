using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Binary Pattern Signatures Database
    /// Provides binary pattern-based malware detection using PE header analysis,
    /// import/export function patterns, section characteristics, and entry point signatures
    /// </summary>
    public class BinaryPatternDatabase
    {
        private readonly string _dbPath;
        private Dictionary<string, BinarySignature> _signatures = new();

        // PE header patterns for common malware
        private static readonly List<BinarySignature> BinarySignatures = new()
        {
            // PE Header Anomalies
            new BinarySignature
            {
                Pattern = "4D5A", // MZ header
                Type = SignatureType.PEHeader,
                Name = "Suspicious MZ Header",
                Description = "PE executable header detected",
                Severity = ThreatSeverity.Low,
                Family = "Generic"
            },
            
            // Suspicious Entry Point
            new BinarySignature
            {
                Pattern = "E8??????FF15",
                Type = SignatureType.EntryPoint,
                Name = "Call and Indirect Call Pattern",
                Description = "Common call pattern at entry point",
                Severity = ThreatSeverity.Medium,
                Family = "Suspicious"
            },

            // Shellcode Patterns
            new BinarySignature
            {
                Pattern = "90909090909090",
                Type = SignatureType.Shellcode,
                Name = "NOP Sled Detection",
                Description = "Multiple NOP instructions (possible shellcode)",
                Severity = ThreatSeverity.Medium,
                Family = "Shellcode"
            },

            // Stack Pivot Detection
            new BinarySignature
            {
                Pattern = "8B0C2445894C2408",
                Type = SignatureType.Exploit,
                Name = "Stack Pivot Pattern",
                Description = "Possible stack pivot technique",
                Severity = ThreatSeverity.High,
                Family = "Exploit"
            },

            // API Hashing Pattern
            new BinarySignature
            {
                Pattern = "8B??24??8B??????33??894424",
                Type = SignatureType.Packing,
                Name = "API Hashing Pattern",
                Description = "Common API hashing implementation",
                Severity = ThreatSeverity.Medium,
                Family = "Packing"
            },

            // Self-modifying code
            new BinarySignature
            {
                Pattern = "C600??C746??????E8",
                Type = SignatureType.Packing,
                Name = "Self-Modifying Code",
                Description = "Code modifies itself at runtime",
                Severity = ThreatSeverity.Medium,
                Family = "Packer"
            },

            // TLS Callback
            new BinarySignature
            {
                Pattern = "558BEC83C4F0B8????????E8????????E8",
                Type = SignatureType.AntiDebug,
                Name = "TLS Callback Pattern",
                Description = "Thread Local Storage callback",
                Severity = ThreatSeverity.Low,
                Family = "Generic"
            },

            // Import Table
            new BinarySignature
            {
                Pattern = "00000000",
                Type = SignatureType.AntiVM,
                Name = "Empty Import Table",
                Description = "Import table appears empty (possible packed)",
                Severity = ThreatSeverity.Medium,
                Family = "Packer"
            }
        };

        // Known malicious import patterns
        private static readonly Dictionary<string, MaliciousImport> MaliciousImports = new()
        {
            ["VirtualAlloc"] = new MaliciousImport { Category = "Memory", Risk = "Allocates executable memory", Severity = ThreatSeverity.Medium },
            ["VirtualAllocEx"] = new MaliciousImport { Category = "Memory", Risk = "Remote process memory allocation", Severity = ThreatSeverity.High },
            ["VirtualProtect"] = new MaliciousImport { Category = "Memory", Risk = "Changes memory protection", Severity = ThreatSeverity.Medium },
            ["VirtualProtectEx"] = new MaliciousImport { Category = "Memory", Risk = "Changes remote memory protection", Severity = ThreatSeverity.High },
            ["CreateRemoteThread"] = new MaliciousImport { Category = "Injection", Risk = "Remote thread execution", Severity = ThreatSeverity.Critical },
            ["WriteProcessMemory"] = new MaliciousImport { Category = "Injection", Risk = "Writes to remote process", Severity = ThreatSeverity.Critical },
            ["ReadProcessMemory"] = new MaliciousImport { Category = "Injection", Risk = "Reads from remote process", Severity = ThreatSeverity.High },
            ["OpenProcess"] = new MaliciousImport { Category = "Process", Risk = "Opens process handle", Severity = ThreatSeverity.Medium },
            ["OpenProcessToken"] = new MaliciousImport { Category = "Privilege", Risk = "Opens process token", Severity = ThreatSeverity.High },
            ["AdjustTokenPrivileges"] = new MaliciousImport { Category = "Privilege", Risk = "Modifies token privileges", Severity = ThreatSeverity.High },
            ["LoadLibrary"] = new MaliciousImport { Category = "Module", Risk = "Loads DLL", Severity = ThreatSeverity.Low },
            ["LoadLibraryA"] = new MaliciousImport { Category = "Module", Risk = "Loads DLL (ASCII)", Severity = ThreatSeverity.Low },
            ["LoadLibraryW"] = new MaliciousImport { Category = "Module", Risk = "Loads DLL (Unicode)", Severity = ThreatSeverity.Low },
            ["GetProcAddress"] = new MaliciousImport { Category = "Module", Risk = "Gets function address", Severity = ThreatSeverity.Medium },
            ["CreateProcess"] = new MaliciousImport { Category = "Process", Risk = "Creates new process", Severity = ThreatSeverity.Medium },
            ["ShellExecute"] = new MaliciousImport { Category = "Execution", Risk = "Executes shell command", Severity = ThreatSeverity.Medium },
            ["WinExec"] = new MaliciousImport { Category = "Execution", Risk = "Executes application", Severity = ThreatSeverity.Medium },
            ["UrlDownloadToFile"] = new MaliciousImport { Category = "Network", Risk = "Downloads file from URL", Severity = ThreatSeverity.High },
            ["InternetOpen"] = new MaliciousImport { Category = "Network", Risk = "Opens internet session", Severity = ThreatSeverity.Low },
            ["InternetOpenUrl"] = new MaliciousImport { Category = "Network", Risk = "Opens URL", Severity = ThreatSeverity.High },
            ["InternetReadFile"] = new MaliciousImport { Category = "Network", Risk = "Reads from internet", Severity = ThreatSeverity.Medium },
            ["SetWindowsHook"] = new MaliciousImport { Category = "Hooking", Risk = "Sets Windows hook", Severity = ThreatSeverity.High },
            ["SetWindowsHookEx"] = new MaliciousImport { Category = "Hooking", Risk = "Sets Windows hook (extended)", Severity = ThreatSeverity.High },
            ["UnhookWindowsHook"] = new MaliciousImport { Category = "Hooking", Risk = "Removes Windows hook", Severity = ThreatSeverity.High },
            ["FindWindow"] = new MaliciousImport { Category = "Spyware", Risk = "Finds window", Severity = ThreatSeverity.Medium },
            ["SetForegroundWindow"] = new MaliciousImport { Category = "Spyware", Risk = "Sets foreground window", Severity = ThreatSeverity.Medium },
            ["GetAsyncKeyState"] = new MaliciousImport { Category = "Keylogger", Risk = "Gets key state", Severity = ThreatSeverity.High },
            ["GetKeyboardState"] = new MaliciousImport { Category = "Keylogger", Risk = "Gets keyboard state", Severity = ThreatSeverity.High },
            ["MapVirtualKey"] = new MaliciousImport { Category = "Keylogger", Risk = "Maps virtual key", Severity = ThreatSeverity.Medium },
            ["RegOpenKey"] = new MaliciousImport { Category = "Registry", Risk = "Opens registry key", Severity = ThreatSeverity.Low },
            ["RegCreateKey"] = new MaliciousImport { Category = "Registry", Risk = "Creates registry key", Severity = ThreatSeverity.Medium },
            ["RegSetValue"] = new MaliciousImport { Category = "Registry", Risk = "Sets registry value", Severity = ThreatSeverity.Medium },
            ["RegDeleteKey"] = new MaliciousImport { Category = "Registry", Risk = "Deletes registry key", Severity = ThreatSeverity.Medium },
            ["NtCreateSection"] = new MaliciousImport { Category = "Injection", Risk = "Creates section (NT)", Severity = ThreatSeverity.Critical },
            ["NtMapViewOfSection"] = new MaliciousImport { Category = "Injection", Risk = "Maps section (NT)", Severity = ThreatSeverity.Critical },
            ["NtUnmapViewOfSection"] = new MaliciousImport { Category = "Injection", Risk = "Unmaps section (NT)", Severity = ThreatSeverity.Critical },
            ["CreateService"] = new MaliciousImport { Category = "Persistence", Risk = "Creates Windows service", Severity = ThreatSeverity.High },
            ["StartService"] = new MaliciousImport { Category = "Persistence", Risk = "Starts Windows service", Severity = ThreatSeverity.High },
            ["StopService"] = new MaliciousImport { Category = "Attack", Risk = "Stops Windows service", Severity = ThreatSeverity.High },
            ["AddPrinter"] = new MaliciousImport { Category = "Persistence", Risk = "Adds printer", Severity = ThreatSeverity.Medium },
            ["AddMonitor"] = new MaliciousImport { Category = "Persistence", Risk = "Adds monitor", Severity = ThreatSeverity.Medium }
        };

        // Suspicious section names
        private static readonly Dictionary<string, string> SuspiciousSectionNames = new(StringComparer.OrdinalIgnoreCase)
        {
            [".upx0"] = "UPX Packer",
            [".upx1"] = "UPX Packer",
            [".upx2"] = "UPX Packer",
            [".aspack"] = "ASPack Packer",
            [".aspack1"] = "ASPack Packer",
            [".aspack2"] = "ASPack Packer",
            [".petite"] = "Petite Packer",
            [".themida"] = "Themida Packer",
            [".vmp0"] = "VMProtect Packer",
            [".vmp1"] = "VMProtect Packer",
            [".vmp2"] = "VMProtect Packer",
            [".packed"] = "Generic Packer",
            [".winlicense"] = "WinLicense Packer",
            [".armadillo"] = "Armadillo Packer",
            [".pecompact"] = "PECompact Packer",
            [".mew"] = "MEW Packer",
            [".nspack"] = "NSPack Packer",
            [".wwpack"] = "WWPack Packer",
            [".fsg"] = "FSG Packer",
            [".text!"] = "Obfuscated Section",
            [".data!"] = "Obfuscated Section",
            [".rdata!"] = "Obfuscated Section",
            [".stub"] = "Stub Section",
            [".adata"] = "Assembly Data",
            [".ida"] = "IDA Disassembler",
            [".idb"] = "IDA Database",
            [".pdata"] = "Exception Data",
            [".reloc"] = "Relocation Data"
        };

        public BinaryPatternDatabase(string path)
        {
            _dbPath = path;
            LoadOrGenerate();
        }

        private void LoadOrGenerate()
        {
            try
            {
                if (File.Exists(_dbPath))
                {
                    var json = File.ReadAllText(_dbPath);
                    _signatures = JsonSerializer.Deserialize<Dictionary<string, BinarySignature>>(json) ?? new();
                }

                if (_signatures.Count == 0)
                {
                    foreach (var sig in BinarySignatures)
                    {
                        var hash = ComputePatternHash(sig.Pattern);
                        _signatures[hash] = sig;
                    }
                    Save();
                    Logger.Log("Info", $"Generated {_signatures.Count} binary pattern signatures");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load binary pattern database", ex);
            }
        }

        public void Save()
        {
            try
            {
                var directory = Path.GetDirectoryName(_dbPath);
                if (!string.IsNullOrEmpty(directory))
                    Directory.CreateDirectory(directory);

                var json = JsonSerializer.Serialize(_signatures, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_dbPath, json);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save binary pattern database", ex);
            }
        }

        private string ComputePatternHash(string pattern)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(pattern);
            var hash = sha256.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").Substring(0, 16);
        }

        /// <summary>
        /// Analyze PE file for binary patterns
        /// </summary>
        public async Task<BinaryAnalysisResult> AnalyzeFileAsync(string filePath)
        {
            var result = new BinaryAnalysisResult
            {
                FilePath = filePath,
                AnalyzedAt = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "File not found";
                    return result;
                }

                var fileBytes = await File.ReadAllBytesAsync(filePath);
                result.FileSize = fileBytes.Length;

                // Check PE header
                if (fileBytes.Length < 64 || fileBytes[0] != 0x4D || fileBytes[1] != 0x5A)
                {
                    result.IsPEFile = false;
                    return result;
                }

                result.IsPEFile = true;

                // Get PE header offset
                var peOffset = BitConverter.ToInt32(fileBytes, 0x3C);
                if (peOffset + 24 > fileBytes.Length)
                {
                    result.Error = "Invalid PE header";
                    return result;
                }

                // Parse PE headers
                result = ParsePEHeaders(fileBytes, peOffset, result);

                // Check for suspicious patterns
                result = ScanBinaryPatterns(fileBytes, result);

                // Analyze sections
                result = AnalyzeSections(fileBytes, peOffset, result);

                // Analyze imports
                result = AnalyzeImports(fileBytes, peOffset, result);

                // Calculate overall threat score
                result.OverallScore = CalculateThreatScore(result);

                result.IsSuspicious = result.OverallScore > 0.5;

                Logger.Log("Debug", $"Binary analysis: {filePath} - Score: {result.OverallScore:F2}");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Binary analysis failed for {filePath}", ex);
                result.Error = ex.Message;
            }

            return result;
        }

        private BinaryAnalysisResult ParsePEHeaders(byte[] fileBytes, int peOffset, BinaryAnalysisResult result)
        {
            try
            {
                // Read PE signature
                var peSignature = Encoding.ASCII.GetString(fileBytes, peOffset, 4);
                result.PESignature = peSignature;

                // Read COFF header
                var machine = BitConverter.ToUInt16(fileBytes, peOffset + 4);
                result.MachineType = machine switch
                {
                    0x014C => "x86",
                    0x8664 => "x64",
                    0x01C0 => "ARM",
                    0xAA64 => "ARM64",
                    _ => "Unknown"
                };

                // Number of sections
                var numSections = BitConverter.ToUInt16(fileBytes, peOffset + 6);
                result.SectionCount = numSections;

                // Optional header
                var optionalHeaderOffset = peOffset + 20;
                if (optionalHeaderOffset + 2 < fileBytes.Length)
                {
                    var magic = BitConverter.ToUInt16(fileBytes, optionalHeaderOffset);
                    result.Is64Bit = magic == 0x20B;
                    result.IsDotNET = magic == 0x10B; // Could be .NET
                }

                // Entry point RVA
                var entryPointRva = BitConverter.ToUInt32(fileBytes, optionalHeaderOffset + 16);
                result.EntryPointRVA = entryPointRva;

                // Image base
                var imageBase = BitConverter.ToUInt64(fileBytes, optionalHeaderOffset + 24);
                result.ImageBase = imageBase;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to parse PE headers", ex);
            }

            return result;
        }

        private BinaryAnalysisResult ScanBinaryPatterns(byte[] fileBytes, BinaryAnalysisResult result)
        {
            var fileContent = Encoding.ASCII.GetString(fileBytes);

            // Check each signature pattern
            foreach (var sig in _signatures.Values)
            {
                try
                {
                    bool matched = false;
                    var pattern = sig.Pattern.Replace("??", ".");

                    if (sig.Type == SignatureType.PEHeader)
                    {
                        matched = fileBytes.Length > 1 && 
                                 (fileBytes[0] == 0x4D && fileBytes[1] == 0x5A);
                    }
                    else
                    {
                        matched = fileContent.Contains(sig.Pattern) || 
                                 ContainsPattern(fileBytes, sig.Pattern);
                    }

                    if (matched)
                    {
                        result.MatchedPatterns.Add(new BinaryPatternMatch
                        {
                            Pattern = sig.Pattern,
                            Type = sig.Type.ToString(),
                            Name = sig.Name,
                            Severity = sig.Severity,
                            Family = sig.Family
                        });

                        result.ThreatScore += sig.Severity switch
                        {
                            ThreatSeverity.Critical => 0.4,
                            ThreatSeverity.High => 0.3,
                            ThreatSeverity.Medium => 0.2,
                            ThreatSeverity.Low => 0.1,
                            _ => 0.1
                        };
                    }
                }
                catch { }
            }

            // Check for high entropy (packed/encrypted)
            var entropy = CalculateEntropy(fileBytes);
            result.Entropy = entropy;
            if (entropy > 7.0)
            {
                result.ThreatScore += 0.3;
                result.IsPacked = true;
                result.SuspiciousIndicators.Add("High entropy detected (possibly packed/encrypted)");
            }

            // Check for small file size with executable header
            if (fileBytes.Length < 10240 && result.IsPEFile)
            {
                result.ThreatScore += 0.2;
                result.SuspiciousIndicators.Add("Small executable size (possible shellcode)");
            }

            return result;
        }

        private bool ContainsPattern(byte[] data, string pattern)
        {
            try
            {
                var hex = pattern.Replace("?", "").Replace(" ", "");
                if (hex.Length % 2 != 0) return false;

                var searchBytes = new byte[hex.Length / 2];
                for (int i = 0; i < searchBytes.Length; i++)
                {
                    searchBytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                }

                for (int i = 0; i <= data.Length - searchBytes.Length; i++)
                {
                    bool found = true;
                    for (int j = 0; j < searchBytes.Length; j++)
                    {
                        if (pattern[(j * 3)] != '?' && data[i + j] != searchBytes[j])
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found) return true;
                }
            }
            catch { }
            return false;
        }

        private BinaryAnalysisResult AnalyzeSections(byte[] fileBytes, int peOffset, BinaryAnalysisResult result)
        {
            try
            {
                var numSections = result.SectionCount;
                var sectionOffset = peOffset + 20 + (result.Is64Bit ? 96 : 96); // Size of optional header

                for (int i = 0; i < numSections && sectionOffset + 40 < fileBytes.Length; i++)
                {
                    var sectionName = Encoding.ASCII.GetString(fileBytes, sectionOffset, 8).TrimEnd('\0');
                    
                    // Check for suspicious section names
                    if (SuspiciousSectionNames.TryGetValue(sectionName, out var packer))
                    {
                        result.IsPacked = true;
                        result.SuspiciousIndicators.Add($"Suspicious section: {sectionName} ({packer})");
                        result.ThreatScore += 0.2;
                    }

                    // Check section characteristics
                    var characteristics = BitConverter.ToUInt32(fileBytes, sectionOffset + 36);
                    
                    // Executable section
                    if ((characteristics & 0x20000000) != 0)
                    {
                        result.ExecutableSections++;
                    }

                    // Writable and executable (suspicious)
                    if ((characteristics & 0x20000000) != 0 && (characteristics & 0x80000000) != 0)
                    {
                        result.SuspiciousIndicators.Add($"Section {sectionName} is writable and executable");
                        result.ThreatScore += 0.15;
                    }

                    // Read-only section with code
                    if ((characteristics & 0x40000000) != 0 && (characteristics & 0x20000000) != 0)
                    {
                        result.SuspiciousIndicators.Add($"Section {sectionName} is read-only with executable code (packed)");
                        result.ThreatScore += 0.1;
                    }

                    sectionOffset += 40;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to analyze sections", ex);
            }

            return result;
        }

        private BinaryAnalysisResult AnalyzeImports(byte[] fileBytes, int peOffset, BinaryAnalysisResult result)
        {
            try
            {
                // Simplified import table parsing
                var importDescriptorOffset = peOffset + 20 + (result.Is64Bit ? 96 : 96) + 2 * result.SectionCount * 40;
                
                // Look for common malicious imports in the file
                var content = Encoding.ASCII.GetString(fileBytes);
                
                foreach (var import in MaliciousImports)
                {
                    if (content.Contains(import.Key))
                    {
                        result.DetectedImports.Add(new DetectedImport
                        {
                            Name = import.Key,
                            Category = import.Value.Category,
                            Risk = import.Value.Risk,
                            Severity = import.Value.Severity
                        });

                        result.ThreatScore += import.Value.Severity switch
                        {
                            ThreatSeverity.Critical => 0.3,
                            ThreatSeverity.High => 0.2,
                            ThreatSeverity.Medium => 0.1,
                            ThreatSeverity.Low => 0.05,
                            _ => 0.05
                        };
                    }
                }

                // Check for suspicious import count
                var suspiciousImportCount = result.DetectedImports.Count(i => i.Severity >= ThreatSeverity.High);
                if (suspiciousImportCount >= 5)
                {
                    result.SuspiciousIndicators.Add($"High number of suspicious imports: {suspiciousImportCount}");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to analyze imports", ex);
            }

            return result;
        }

        private double CalculateThreatScore(BinaryAnalysisResult result)
        {
            // Cap at 1.0
            return Math.Min(1.0, result.ThreatScore);
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;

            var frequency = new int[256];
            foreach (var b in data)
            {
                frequency[b]++;
            }

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] == 0) continue;
                var probability = (double)frequency[i] / data.Length;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }

        public int SignatureCount => _signatures.Count;

        public Dictionary<string, string> GetSuspiciousSectionNames() => SuspiciousSectionNames;

        public Dictionary<string, MaliciousImport> GetMaliciousImports() => MaliciousImports;
    }

    #region Data Classes

    public class BinarySignature
    {
        public string Pattern { get; set; } = "";
        public SignatureType Type { get; set; }
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;
        public string Family { get; set; } = "";
    }

    public enum SignatureType
    {
        PEHeader,
        EntryPoint,
        Shellcode,
        Exploit,
        Packing,
        AntiDebug,
        AntiVM,
        Network,
        Persistence
    }

    public class BinaryAnalysisResult
    {
        public string FilePath { get; set; } = "";
        public long FileSize { get; set; }
        public bool IsPEFile { get; set; }
        public string PESignature { get; set; } = "";
        public string MachineType { get; set; } = "";
        public bool Is64Bit { get; set; }
        public bool IsDotNET { get; set; }
        public uint EntryPointRVA { get; set; }
        public ulong ImageBase { get; set; }
        public int SectionCount { get; set; }
        public int ExecutableSections { get; set; }
        public double Entropy { get; set; }
        public bool IsPacked { get; set; }
        public bool IsSuspicious { get; set; }
        public double ThreatScore { get; set; }
        public double OverallScore { get; set; }
        public string? Error { get; set; }
        public DateTime AnalyzedAt { get; set; }

        public List<BinaryPatternMatch> MatchedPatterns { get; set; } = new();
        public List<string> SuspiciousIndicators { get; set; } = new();
        public List<DetectedImport> DetectedImports { get; set; } = new();
    }

    public class BinaryPatternMatch
    {
        public string Pattern { get; set; } = "";
        public string Type { get; set; } = "";
        public string Name { get; set; } = "";
        public ThreatSeverity Severity { get; set; }
        public string Family { get; set; } = "";
    }

    public class DetectedImport
    {
        public string Name { get; set; } = "";
        public string Category { get; set; } = "";
        public string Risk { get; set; } = "";
        public ThreatSeverity Severity { get; set; }
    }

    public class MaliciousImport
    {
        public string Category { get; set; } = "";
        public string Risk { get; set; } = "";
        public ThreatSeverity Severity { get; set; }
    }

    #endregion
}

