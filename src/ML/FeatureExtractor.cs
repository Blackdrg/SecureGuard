using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.ML
{
    /// <summary>
    /// Feature Extractor for ML models
    /// Extracts features from PE files for malware classification
    /// Compatible with EMBER dataset features
    /// </summary>
    public class FeatureExtractor
    {
        // Suspicious API calls commonly used by malware
        private readonly HashSet<string> _suspiciousAPIs = new(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory", "ReadProcessMemory",
            "OpenProcess", "OpenProcessToken", "AdjustTokenPrivileges",
            "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
            "CreateProcess", "CreateProcessA", "CreateProcessW", "ShellExecute", "WinExec",
            "UrlDownloadToFile", "InternetOpen", "InternetOpenUrl", "InternetReadFile", "InternetWriteFile",
            "SetWindowsHook", "SetWindowsHookEx", "UnhookWindowsHook",
            "FindWindow", "SetForegroundWindow", "GetForegroundWindow", "GetWindowText",
            "GetAsyncKeyState", "GetKeyboardState", "MapVirtualKey",
            "RegOpenKey", "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegEnumKey",
            "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
            "CreateService", "StartService", "StopService",
            "AddPrinter", "AddMonitor", "WmiQuery",
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "EnumProcesses", "EnumProcessModules", "GetModuleBaseName",
            "LdrLoadDll", "LdrGetProcedureAddress", "RtlCreateUserThread"
        };

        // Packer signatures
        private readonly HashSet<string> _packerSignatures = new(StringComparer.OrdinalIgnoreCase)
        {
            "UPX", "ASPack", "Petite", "Themida", "VMProtect", "Armadillo",
            "PECompact", "MEW", "NSPack", "WWPack", "EXPACK", "FSG",
            "Karakurt", "ProCrypt", "VMP", "Themida", "WinLicense",
            "Obsidium", "SG", "StarForce", "ProtectID"
        };

        // Known good software publishers
        private readonly HashSet<string> _knownGoodPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Google LLC", "Adobe Inc.", "Mozilla Corporation",
            "Apple Inc.", "Intel Corporation", "NVIDIA Corporation", "AMD",
            "Oracle Corporation", "VMware Inc.", "Amazon.com Inc.", "Cisco Systems Inc.",
            "IBM Corporation", "Dell Inc.", "HP Inc.", "Lenovo"
        };

        // Suspicious directory paths
        private readonly string[] _suspiciousPaths = new[]
        {
            "temp", "tmp", "appdata", "local\\temp", "downloads"
        };

        /// <summary>
        /// Extract all features from a PE file for ML model input
        /// </summary>
        public async Task<PEFeatures> ExtractFeaturesAsync(string filePath)
        {
            var features = new PEFeatures
            {
                FilePath = filePath,
                ExtractionTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    features.Error = "File not found";
                    return features;
                }

                var fileInfo = new FileInfo(filePath);
                features.FileSize = (float)fileInfo.Length;

                // Skip very small files
                if (fileInfo.Length < 512)
                {
                    features.IsTooSmall = true;
                    return features;
                }

                // Extract features in parallel
                var task1 = Task.Run(() => ExtractBasicFeatures(filePath, features));
                var task2 = Task.Run(() => ExtractPEHeaderFeatures(filePath, features));
                var task3 = Task.Run(() => ExtractSectionFeatures(filePath, features));
                var task4 = Task.Run(() => ExtractImportFeatures(filePath, features));
                var task5 = Task.Run(() => ExtractEntropyFeatures(filePath, features));
                var task6 = Task.Run(() => ExtractStringFeatures(filePath, features));
                var task7 = Task.Run(() => ExtractBehavioralFeatures(filePath, features));

                await Task.WhenAll(task1, task2, task3, task4, task5, task6, task7);

                features.ExtractionSuccessful = true;
                Core.Logger.Log("Debug", $"Features extracted for: {filePath}");
            }
            catch (Exception ex)
            {
                features.Error = ex.Message;
                Core.Logger.Log("Error", $"Feature extraction failed for {filePath}", ex);
            }

            return features;
        }

        private void ExtractBasicFeatures(string filePath, PEFeatures features)
        {
            var fileInfo = new FileInfo(filePath);
            
            // File size (normalized)
            features.FileSize = (float)fileInfo.Length;
            features.FileSizeKB = features.FileSize / 1024.0f;
            features.FileSizeMB = features.FileSize / (1024.0f * 1024.0f);

            // Time-based features
            var ageDays = (DateTime.Now - fileInfo.CreationTime).TotalDays;
            features.DaysSinceCreation = (float)ageDays;
            features.DaysSinceModified = (float)((DateTime.Now - fileInfo.LastWriteTime).TotalDays);
            features.IsRecentlyCreated = ageDays < 7;
            features.IsRecentlyModified = (DateTime.Now - fileInfo.LastWriteTime).TotalDays < 7;

            // Extension
            features.Extension = fileInfo.Extension.ToLower();

            // Location-based risk
            features.LocationRisk = CalculateLocationRisk(filePath);
        }

        private void ExtractPEHeaderFeatures(string filePath, PEFeatures features)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var reader = new BinaryReader(stream);

                // Check MZ header
                if (stream.Length < 64) return;
                
                var mzHeader = reader.ReadBytes(2);
                if (mzHeader[0] != 0x4D || mzHeader[1] != 0x5A) // "MZ"
                {
                    features.IsPEFile = false;
                    return;
                }

                features.IsPEFile = true;

                // Get PE offset
                stream.Seek(0x3C, SeekOrigin.Begin);
                var peOffsetBytes = reader.ReadBytes(4);
                var peOffset = BitConverter.ToInt32(peOffsetBytes, 0);

                if (peOffset > stream.Length - 24) return;

                // PE Header
                stream.Seek(peOffset, SeekOrigin.Begin);
                var peSignature = reader.ReadBytes(4);
                if (peSignature[0] != 0x50 || peSignature[1] != 0x45) // "PE\0\0"
                {
                    return;
                }

                // COFF Header
                var machine = reader.ReadInt16();
                features.MachineType = machine;
                features.Isx86 = machine == 0x014C;
                features.Isx64 = machine == 0x8664;

                var numberOfSections = reader.ReadInt16();
                features.NumberOfSections = numberOfSections;

                var timestamp = reader.ReadInt32();
                features.PETimestamp = timestamp;

                // Optional Header
                var optionalHeaderSize = reader.ReadInt16();
                features.OptionalHeaderSize = optionalHeaderSize;

                var characteristics = reader.ReadInt16();
                features.IsDll = (characteristics & 0x2000) != 0;
                features.IsExecutable = (characteristics & 0x0002) != 0;
                features.IsSystem = (characteristics & 0x1000) != 0;

                // Optional Header values
                if (optionalHeaderSize >= 2)
                {
                    var magic = reader.ReadInt16();
                    features.IsPE32 = magic == 0x10B;
                    features.IsPE32Plus = magic == 0x20B;
                }

                // Read more optional header fields for features
                if (stream.Position + 60 <= stream.Length)
                {
                    // Subsystem
                    stream.Seek(peOffset + 0x5C, SeekOrigin.Begin);
                    if (stream.Position < stream.Length - 2)
                    {
                        var subsystem = reader.ReadInt16();
                        features.Subsystem = subsystem;
                        features.IsConsole = subsystem == 3;
                        features.IsGUI = subsystem == 2;
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "PE header extraction error", ex);
            }
        }

        private void ExtractSectionFeatures(string filePath, PEFeatures features)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var reader = new BinaryReader(stream);

                if (stream.Length < 64) return;

                // Get PE offset
                stream.Seek(0x3C, SeekOrigin.Begin);
                var peOffsetBytes = reader.ReadBytes(4);
                var peOffset = BitConverter.ToInt32(peOffsetBytes, 0);

                // Number of sections
                stream.Seek(peOffset + 6, SeekOrigin.Begin);
                var sectionCount = reader.ReadInt16();
                features.NumberOfSections = sectionCount;

                // Section table starts at offset + 24
                var sectionTableOffset = peOffset + 24;
                
                float totalRawSize = 0;
                float totalVirtualSize = 0;
                int sectionWithCode = 0;
                int sectionWithData = 0;
                int sectionWithResources = 0;

                for (int i = 0; i < sectionCount && i < 10; i++)
                {
                    var sectionOffset = sectionTableOffset + (i * 40);
                    if (sectionOffset + 40 > stream.Length) break;

                    stream.Seek(sectionOffset, SeekOrigin.Begin);
                    var sectionName = Encoding.ASCII.GetString(reader.ReadBytes(8)).TrimEnd('\0');
                    var virtualSize = reader.ReadInt32();
                    var virtualAddress = reader.ReadInt32();
                    var rawSize = reader.ReadInt32();
                    var rawOffset = reader.ReadInt32();
                    var characteristics = reader.ReadInt32();

                    totalRawSize += rawSize;
                    totalVirtualSize += virtualSize;

                    // Section characteristics
                    if ((characteristics & 0x20000000) != 0) sectionWithCode++; // IMAGE_SCN_CNT_CODE
                    if ((characteristics & 0x40000000) != 0) sectionWithData++; // IMAGE_SCN_CNT_INITIALIZED_DATA
                    if ((characteristics & 0x80000000) != 0) sectionWithResources++; // IMAGE_SCN_CNT_UNINITIALIZED_DATA
                }

                features.SectionWithCodeCount = sectionWithCode;
                features.SectionWithDataCount = sectionWithData;
                features.SectionWithResourcesCount = sectionWithResources;
                features.TotalRawSize = totalRawSize;
                features.TotalVirtualSize = totalVirtualSize;

                // Calculate size ratio
                if (totalVirtualSize > 0)
                {
                    features.SizeRatio = totalRawSize / totalVirtualSize;
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Section extraction error", ex);
            }
        }

        private void ExtractImportFeatures(string filePath, PEFeatures features)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var reader = new BinaryReader(stream);

                if (stream.Length < 512) return;

                // Read first 512KB for import analysis
                var bufferSize = (int)Math.Min(512 * 1024, stream.Length);
                var buffer = reader.ReadBytes(bufferSize);
                var content = Encoding.ASCII.GetString(buffer).ToLower();

                // Count suspicious APIs
                foreach (var api in _suspiciousAPIs)
                {
                    if (content.Contains(api.ToLower()))
                    {
                        features.SuspiciousAPICount++;
                        if (!features.SuspiciousAPIs.Contains(api))
                        {
                            features.SuspiciousAPIs.Add(api);
                        }
                    }
                }

                // Check for specific dangerous API combinations
                features.HasProcessInjection = content.Contains("virtualallocex") && 
                    (content.Contains("writeremotethread") || content.Contains("writeprocessmemory"));
                
                features.HasRegistryManipulation = content.Contains("regopenkey") || 
                    content.Contains("regsetvalue") || content.Contains("regcreatekey");
                
                features.HasNetworkAPIs = content.Contains("internetopen") || 
                    content.Contains("internetconnect") || content.Contains("httpsendrequest");
                
                features.HasCryptography = content.Contains("cryptencrypt") || 
                    content.Contains("bcrypt") || content.Contains("rsa") ||
                    content.Contains("aes") || content.Contains("md5") || content.Contains("sha");

                // Known DLL imports (approximation)
                var dllImports = new[] { "kernel32.dll", "user32.dll", "advapi32.dll", 
                    "ntdll.dll", "ws2_32.dll", "wininet.dll", "crypt32.dll" };
                
                foreach (var dll in dllImports)
                {
                    if (content.Contains(dll))
                    {
                        features.KnownDllCount++;
                    }
                }

                // Import hash calculation (simplified)
                features.ImportHash = CalculateSimpleImportHash(buffer);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Import extraction error", ex);
            }
        }

        private void ExtractEntropyFeatures(string filePath, PEFeatures features)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                
                // Calculate entropy of entire file (first 1MB for performance)
                var bufferSize = (int)Math.Min(1024 * 1024, stream.Length);
                var buffer = new byte[bufferSize];
                var bytesRead = stream.Read(buffer, 0, bufferSize);
                
                if (bytesRead > 0)
                {
                    features.OverallEntropy = CalculateEntropy(buffer, bytesRead);
                    features.IsHighEntropy = features.OverallEntropy > 6.5f;
                    features.IsVeryHighEntropy = features.OverallEntropy > 7.5f;
                }

                // Calculate section entropies
                stream.Seek(0, SeekOrigin.Begin);
                var sectionData = new byte[Math.Min(65536, stream.Length)];
                var sectionBytesRead = stream.Read(sectionData, 0, sectionData.Length);
                
                if (sectionBytesRead > 0)
                {
                    // First 4KB (often contains headers)
                    var headerEntropy = CalculateEntropy(sectionData, Math.Min(4096, sectionBytesRead));
                    features.HeaderEntropy = headerEntropy;

                    // Middle section
                    var middleStart = sectionBytesRead / 2;
                    var middleSize = Math.Min(4096, sectionBytesRead - middleStart);
                    if (middleSize > 0)
                    {
                        features.MiddleEntropy = CalculateEntropy(sectionData.Skip(middleStart).Take(middleSize).ToArray(), middleSize);
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Entropy extraction error", ex);
            }
        }

        private void ExtractStringFeatures(string filePath, PEFeatures features)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var bufferSize = (int)Math.Min(1024 * 1024, stream.Length);
                var buffer = new byte[bufferSize];
                var bytesRead = stream.Read(buffer, 0, bufferSize);

                // Count strings
                int stringCount = 0;
                int urlCount = 0;
                int ipCount = 0;
                int pathsCount = 0;

                var content = Encoding.ASCII.GetString(buffer);
                
                // Simple string count (sequences of 4+ printable chars)
                var stringMatches = System.Text.RegularExpressions.Regex.Matches(content, @"[a-zA-Z0-9_]{4,}");
                stringCount = stringMatches.Count;

                // URLs
                var urlMatches = System.Text.RegularExpressions.Regex.Matches(content, @"https?://[^\s]+");
                urlCount = urlMatches.Count;

                // IP addresses (simplified)
                var ipMatches = System.Text.RegularExpressions.Regex.Matches(content, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
                ipCount = ipMatches.Count;

                // Windows paths
                var pathMatches = System.Text.RegularExpressions.Regex.Matches(content, @"[A-Za-z]:\\[^:*?""<>|\r\n]+");
                pathsCount = pathMatches.Count;

                features.StringCount = stringCount;
                features.URLCount = urlCount;
                features.IPAddressCount = ipCount;
                features.PathCount = pathsCount;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "String extraction error", ex);
            }
        }

        private void ExtractBehavioralFeatures(string filePath, PEFeatures features)
        {
            // Check for packer signatures
            try
            {
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[Math.Min(65536, stream.Length)];
                stream.Read(buffer, 0, buffer.Length);
                
                var content = Encoding.ASCII.GetString(buffer);
                
                foreach (var packer in _packerSignatures)
                {
                    if (content.Contains(packer, StringComparison.OrdinalIgnoreCase))
                    {
                        features.IsPacked = true;
                        features.PackerSignature = packer;
                        break;
                    }
                }

                // Check for known good signature
                features.IsSigned = CheckDigitalSignature(filePath);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Behavioral extraction error", ex);
            }
        }

        private double CalculateEntropy(byte[] data, int length)
        {
            if (length == 0) return 0;

            var frequency = new int[256];
            for (int i = 0; i < length; i++)
            {
                frequency[data[i]]++;
            }

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] == 0) continue;
                var probability = (double)frequency[i] / length;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }

        private float CalculateLocationRisk(string filePath)
        {
            var lowerPath = filePath.ToLower();
            
            foreach (var suspicious in _suspiciousPaths)
            {
                if (lowerPath.Contains(suspicious))
                {
                    return 0.7f;
                }
            }

            // Check Windows directory
            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            if (lowerPath.StartsWith(windowsDir))
            {
                return 0.2f;
            }

            // Check Program Files
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLower();
            if (lowerPath.StartsWith(programFiles))
            {
                return 0.1f;
            }

            return 0.5f;
        }

        private bool CheckDigitalSignature(string filePath)
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = $"(Get-AuthenticodeSignature '{filePath}').Status",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var status = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();
                
                return status == "Valid";
            }
            catch
            {
                return false;
            }
        }

        private string CalculateSimpleImportHash(byte[] data)
        {
            // Simplified import hash - in reality would parse import table
            var hash = 0;
            foreach (var b in data.Take(1000))
            {
                hash = ((hash << 5) - hash) + b;
            }
            return hash.ToString("X8");
        }

        /// <summary>
        /// Convert features to dictionary for ML model input
        /// </summary>
        public Dictionary<string, float> ToFeatureDictionary(PEFeatures features)
        {
            return new Dictionary<string, float>
            {
                // Basic features
                ["file_size"] = features.FileSize,
                ["file_size_kb"] = features.FileSizeKB,
                ["days_since_creation"] = features.DaysSinceCreation,
                ["days_since_modified"] = features.DaysSinceModified,
                ["location_risk"] = features.LocationRisk,

                // PE header features
                ["is_pe_file"] = features.IsPEFile ? 1.0f : 0.0f,
                ["is_x86"] = features.Isx86 ? 1.0f : 0.0f,
                ["is_x64"] = features.Isx64 ? 1.0f : 0.0f,
                ["is_dll"] = features.IsDll ? 1.0f : 0.0f,
                ["is_executable"] = features.IsExecutable ? 1.0f : 0.0f,
                ["is_pe32"] = features.IsPE32 ? 1.0f : 0.0f,
                ["is_pe32plus"] = features.IsPE32Plus ? 1.0f : 0.0f,
                ["is_console"] = features.IsConsole ? 1.0f : 0.0f,
                ["is_gui"] = features.IsGUI ? 1.0f : 0.0f,
                ["optional_header_size"] = features.OptionalHeaderSize,

                // Section features
                ["number_of_sections"] = features.NumberOfSections,
                ["section_with_code"] = features.SectionWithCodeCount,
                ["section_with_data"] = features.SectionWithDataCount,
                ["section_with_resources"] = features.SectionWithResourcesCount,
                ["total_raw_size"] = features.TotalRawSize,
                ["total_virtual_size"] = features.TotalVirtualSize,
                ["size_ratio"] = features.SizeRatio,

                // Import features
                ["suspicious_api_count"] = features.SuspiciousAPICount,
                ["known_dll_count"] = features.KnownDllCount,
                ["has_process_injection"] = features.HasProcessInjection ? 1.0f : 0.0f,
                ["has_registry_manipulation"] = features.HasRegistryManipulation ? 1.0f : 0.0f,
                ["has_network_apis"] = features.HasNetworkAPIs ? 1.0f : 0.0f,
                ["has_cryptography"] = features.HasCryptography ? 1.0f : 0.0f,

                // Entropy features
                ["overall_entropy"] = (float)features.OverallEntropy,
                ["header_entropy"] = (float)features.HeaderEntropy,
                ["middle_entropy"] = (float)features.MiddleEntropy,
                ["is_high_entropy"] = features.IsHighEntropy ? 1.0f : 0.0f,
                ["is_very_high_entropy"] = features.IsVeryHighEntropy ? 1.0f : 0.0f,

                // String features
                ["string_count"] = features.StringCount,
                ["url_count"] = features.URLCount,
                ["ip_address_count"] = features.IPAddressCount,
                ["path_count"] = features.PathCount,

                // Behavioral features
                ["is_packed"] = features.IsPacked ? 1.0f : 0.0f,
                ["is_signed"] = features.IsSigned ? 1.0f : 0.0f,
                ["is_recently_created"] = features.IsRecentlyCreated ? 1.0f : 0.0f,
                ["is_recently_modified"] = features.IsRecentlyModified ? 1.0f : 0.0f
            };
        }
    }

    /// <summary>
    /// PE File Features for ML model input
    /// </summary>
    public class PEFeatures
    {
        public string FilePath { get; set; } = "";
        public DateTime ExtractionTime { get; set; }
        public bool ExtractionSuccessful { get; set; }
        public string? Error { get; set; }
        public bool IsTooSmall { get; set; }

        // Basic features
        public float FileSize { get; set; }
        public float FileSizeKB { get; set; }
        public float FileSizeMB { get; set; }
        public float DaysSinceCreation { get; set; }
        public float DaysSinceModified { get; set; }
        public float LocationRisk { get; set; }
        public string Extension { get; set; } = "";

        // PE Header features
        public bool IsPEFile { get; set; }
        public bool Isx86 { get; set; }
        public bool Isx64 { get; set; }
        public bool IsDll { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsSystem { get; set; }
        public bool IsPE32 { get; set; }
        public bool IsPE32Plus { get; set; }
        public bool IsConsole { get; set; }
        public bool IsGUI { get; set; }
        public int MachineType { get; set; }
        public int Subsystem { get; set; }
        public int OptionalHeaderSize { get; set; }
        public int PETimestamp { get; set; }

        // Section features
        public int NumberOfSections { get; set; }
        public int SectionWithCodeCount { get; set; }
        public int SectionWithDataCount { get; set; }
        public int SectionWithResourcesCount { get; set; }
        public float TotalRawSize { get; set; }
        public float TotalVirtualSize { get; set; }
        public float SizeRatio { get; set; }

        // Import features
        public int SuspiciousAPICount { get; set; }
        public List<string> SuspiciousAPIs { get; set; } = new();
        public int KnownDllCount { get; set; }
        public bool HasProcessInjection { get; set; }
        public bool HasRegistryManipulation { get; set; }
        public bool HasNetworkAPIs { get; set; }
        public bool HasCryptography { get; set; }
        public string ImportHash { get; set; } = "";

        // Entropy features
        public double OverallEntropy { get; set; }
        public double HeaderEntropy { get; set; }
        public double MiddleEntropy { get; set; }
        public bool IsHighEntropy { get; set; }
        public bool IsVeryHighEntropy { get; set; }

        // String features
        public int StringCount { get; set; }
        public int URLCount { get; set; }
        public int IPAddressCount { get; set; }
        public int PathCount { get; set; }

        // Behavioral features
        public bool IsPacked { get; set; }
        public string? PackerSignature { get; set; }
        public bool IsSigned { get; set; }
        public bool IsRecentlyCreated { get; set; }
        public bool IsRecentlyModified { get; set; }
    }
}

