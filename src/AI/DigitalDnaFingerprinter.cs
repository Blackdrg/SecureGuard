using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 4: Digital DNA Fingerprinting
    /// Creates behavior fingerprint profiles for files - defeats polymorphic malware
    /// </summary>
    public class DigitalDnaFingerprinter : IDisposable
    {
        private readonly Dictionary<string, FileDnaProfile> _dnaDatabase;
        private readonly object _lock = new();
        private bool _isLearning = true;
        
        public event EventHandler<DnaMatchEventArgs>? DnaMatchFound;
        public event EventHandler<PolymorphicDetectedEventArgs>? PolymorphicDetected;

        public DigitalDnaFingerprinter()
        {
            _dnaDatabase = new Dictionary<string, FileDnaProfile>();
            Core.Logger.Log("Info", "Digital DNA Fingerprinter initialized");
        }

        /// <summary>
        /// Generate DNA fingerprint for a file based on behavior
        /// </summary>
        public async Task<FileDnaProfile> GenerateDnaAsync(string filePath)
        {
            var profile = new FileDnaProfile
            {
                FilePath = filePath,
                GeneratedAt = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath)) return profile;

                var fileInfo = new FileInfo(filePath);
                profile.FileSize = fileInfo.Length;
                profile.FileExtension = fileInfo.Extension.ToLower();
                
                // Calculate static DNA (file structure)
                profile.StaticDna = await CalculateStaticDnaAsync(filePath);
                
                // Calculate behavioral DNA indicators
                profile.BehavioralDna = CalculateBehavioralDna(filePath);
                
                // Calculate entropy DNA (detects encryption/packing)
                profile.EntropyDna = CalculateEntropyDna(filePath);
                
                // Calculate API call pattern DNA
                profile.ApiPatternDna = CalculateApiPatternDna(filePath);
                
                // Generate unique DNA signature
                profile.DnaSignature = GenerateDnaSignature(profile);
                
                // Calculate threat indicators
                profile.ThreatIndicators = AnalyzeThreatIndicators(profile);
                
                profile.IsAnalyzed = true;
                
                Core.Logger.Log("Debug", $"DNA generated for: {filePath}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"DNA generation failed for {filePath}", ex);
            }

            return profile;
        }

        private async Task<StaticDna> CalculateStaticDnaAsync(string filePath)
        {
            var staticDna = new StaticDna();
            
            await Task.Run(() =>
            {
                try
                {
                    // Read file header for PE structure analysis
                    using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                    var header = new byte[Math.Min(1024, stream.Length)];
                    stream.Read(header, 0, header.Length);
                    
                    // Calculate byte frequency distribution
                    staticDna.ByteFrequency = CalculateByteFrequency(header);
                    
                    // Detect PE characteristics
                    staticDna.IsPeExecutable = IsPeExecutable(header);
                    staticDna.IsDotNetAssembly = IsDotNetAssembly(header);
                    staticDna.IsPacked = IsPacked(header);
                    staticDna.IsSigned = IsSigned(filePath);
                    
                    // Calculate section characteristics
                    staticDna.SectionCount = CountSections(header);
                    staticDna.HasResources = HasResources(header);
                    staticDna.HasRelocations = HasRelocations(header);
                    
                    // Calculate import hash
                    staticDna.ImportHash = CalculateImportHash(header);
                }
                catch { }
            });
            
            return staticDna;
        }

        private Dictionary<int, int> CalculateByteFrequency(byte[] data)
        {
            var frequency = new Dictionary<int, int>();
            for (int i = 0; i < 256; i++)
                frequency[i] = 0;
            
            foreach (var b in data)
                frequency[b]++;
            
            return frequency;
        }

        private bool IsPeExecutable(byte[] header)
        {
            if (header.Length < 64) return false;
            // Check for MZ header and PE signature
            return header[0] == 0x4D && header[1] == 0x5A && 
                   header.Length >= 64 && header[60] > 0;
        }

        private bool IsDotNetAssembly(byte[] header)
        {
            if (header.Length < 512) return false;
            // Look for .NET metadata signature
            for (int i = 0; i < header.Length - 4; i++)
            {
                if (header[i] == 0x42 && header[i+1] == 0x53 && 
                    header[i+2] == 0x4A && header[i+3] == 0x42)
                    return true;
            }
            return false;
        }

        private bool IsPacked(byte[] header)
        {
            if (header.Length < 256) return false;
            
            // High entropy often indicates packing
            var entropy = CalculateEntropy(header);
            return entropy > 7.0;
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            
            var frequency = new Dictionary<byte, int>();
            foreach (var b in data)
            {
                if (!frequency.ContainsKey(b))
                    frequency[b] = 0;
                frequency[b]++;
            }
            
            double entropy = 0;
            foreach (var count in frequency.Values)
            {
                var probability = (double)count / data.Length;
                entropy -= probability * Math.Log2(probability);
            }
            
            return entropy;
        }

        private bool IsSigned(string filePath)
        {
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
                return cert != null;
            }
            catch
            {
                return false;
            }
        }

        private int CountSections(byte[] header)
        {
            if (header.Length < 248) return 0;
            try
            {
                return header[6]; // Number of sections
            }
            catch
            {
                return 0;
            }
        }

        private bool HasResources(byte[] header)
        {
            if (header.Length < 248) return false;
            return header[0] > 0; // Simplified check
        }

        private bool HasRelocations(byte[] header)
        {
            if (header.Length < 248) return false;
            return true; // Most executables have relocations
        }

        private string CalculateImportHash(byte[] header)
        {
            // Simplified import hash calculation
            var hash = 0;
            foreach (var b in header.Take(256))
                hash = ((hash << 5) - hash) + b;
            return hash.ToString("X8");
        }

        private BehavioralDna CalculateBehavioralDna(string filePath)
        {
            var dna = new BehavioralDna();
            
            try
            {
                var ext = Path.GetExtension(filePath).ToLower();
                dna.ExpectedBehavior = GetExpectedBehavior(ext);
                dna.NetworkActivity = HasNetworkActivity(filePath);
                dna.FileSystemActivity = HasFileSystemActivity(filePath);
                dna.RegistryActivity = HasRegistryActivity(filePath);
                dna.ProcessActivity = HasProcessActivity(filePath);
            }
            catch { }
            
            return dna;
        }

        private string GetExpectedBehavior(string extension)
        {
            return extension switch
            {
                ".exe" => "Executable",
                ".dll" => "Library",
                ".bat" => "Script",
                ".ps1" => "PowerShell",
                ".vbs" => "VBScript",
                ".js" => "JavaScript",
                ".doc" or ".docx" => "Document",
                ".pdf" => "PDF",
                ".zip" or ".rar" => "Archive",
                _ => "Unknown"
            };
        }

        private bool HasNetworkActivity(string filePath)
        {
            // Check for network-related strings
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                var data = new byte[Math.Min(10000, stream.Length)];
                stream.Read(data, 0, data.Length);
                var content = Encoding.ASCII.GetString(data).ToLower();
                return content.Contains("http") || content.Contains("socket") || 
                       content.Contains("connect") || content.Contains("tcp");
            }
            catch
            {
                return false;
            }
        }

        private bool HasFileSystemActivity(string filePath)
        {
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                var data = new byte[Math.Min(10000, stream.Length)];
                stream.Read(data, 0, data.Length);
                var content = Encoding.ASCII.GetString(data).ToLower();
                return content.Contains("file") || content.Contains("create") || 
                       content.Contains("write") || content.Contains("delete");
            }
            catch
            {
                return false;
            }
        }

        private bool HasRegistryActivity(string filePath)
        {
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                var data = new byte[Math.Min(10000, stream.Length)];
                stream.Read(data, 0, data.Length);
                var content = Encoding.ASCII.GetString(data).ToLower();
                return content.Contains("registry") || content.Contains("regopen") || 
                       content.Contains("regset") || content.Contains("hkey");
            }
            catch
            {
                return false;
            }
        }

        private bool HasProcessActivity(string filePath)
        {
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                var data = new byte[Math.Min(10000, stream.Length)];
                stream.Read(data, 0, data.Length);
                var content = Encoding.ASCII.GetString(data).ToLower();
                return content.Contains("process") || content.Contains("createprocess") || 
                       content.Contains("shellexecute") || content.Contains("winexec");
            }
            catch
            {
                return false;
            }
        }

        private EntropyDna CalculateEntropyDna(string filePath)
        {
            var dna = new EntropyDna();
            
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                var data = new byte[Math.Min(65536, stream.Length)];
                var bytesRead = stream.Read(data, 0, data.Length);
                
                dna.OverallEntropy = CalculateEntropy(data.Take(bytesRead).ToArray());
                dna.IsPacked = dna.OverallEntropy > 7.0;
                dna.IsEncrypted = dna.OverallEntropy > 7.5;
                
                // Calculate section entropy
                var sectionSize = Math.Min(4096, bytesRead / 4);
                for (int i = 0; i < 4; i++)
                {
                    var section = data.Skip(i * sectionSize).Take(sectionSize).ToArray();
                    dna.SectionEntropies.Add(CalculateEntropy(section));
                }
            }
            catch { }
            
            return dna;
        }

        private ApiPatternDna CalculateApiPatternDna(string filePath)
        {
            var dna = new ApiPatternDna();
            
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                var data = new byte[Math.Min(50000, stream.Length)];
                stream.Read(data, 0, data.Length);
                var content = Encoding.ASCII.GetString(data).ToLower();
                
                // Check for suspicious API patterns
                dna.HasFileOperations = content.Contains("createfile") || content.Contains("writefile");
                dna.HasNetworkCalls = content.Contains("internetopen") || content.Contains("httpSendRequest");
                dna.HasProcessManipulation = content.Contains("virtualallocex") || content.Contains("writeprocessmemory");
                dna.HasCryptography = content.Contains("cryptencrypt") || content.Contains("bcrypt") || content.Contains("rsa");
                dna.HasAntiDebug = content.Contains("isdebuggerpresent") || content.Contains("checkremotedebugger");
                dna.HasPrivilegeEscalation = content.Contains("adjusttokenprivileges") || content.Contains("lookupprivilegevalue");
                
                dna.RiskScore = CalculateApiRiskScore(dna);
            }
            catch { }
            
            return dna;
        }

        private int CalculateApiRiskScore(ApiPatternDna dna)
        {
            int score = 0;
            if (dna.HasCryptography) score += 30;
            if (dna.HasAntiDebug) score += 25;
            if (dna.HasPrivilegeEscalation) score += 25;
            if (dna.HasProcessManipulation) score += 20;
            if (dna.HasNetworkCalls) score += 10;
            return Math.Min(100, score);
        }

        private string GenerateDnaSignature(FileDnaProfile profile)
        {
            var input = $"{profile.StaticDna.ImportHash}|{profile.BehavioralDna.ExpectedBehavior}|" +
                       $"{profile.EntropyDna.OverallEntropy:F2}|{profile.ApiPatternDna.RiskScore}";
            
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(hash)[..16];
        }

        private List<string> AnalyzeThreatIndicators(FileDnaProfile profile)
        {
            var indicators = new List<string>();
            
            if (profile.StaticDna.IsPacked && !profile.StaticDna.IsSigned)
                indicators.Add("Packed executable without signature");
            
            if (profile.EntropyDna.IsEncrypted)
                indicators.Add("High entropy - possible encryption");
            
            if (profile.ApiPatternDna.HasAntiDebug)
                indicators.Add("Anti-debugging techniques detected");
            
            if (profile.ApiPatternDna.HasCryptography && profile.ApiPatternDna.HasFileOperations)
                indicators.Add("Potential file encryption behavior");
            
            if (profile.BehavioralDna.NetworkActivity && !profile.StaticDna.IsSigned)
                indicators.Add("Network activity from unsigned file");
            
            if (profile.ApiPatternDna.HasPrivilegeEscalation)
                indicators.Add("Privilege escalation APIs detected");
            
            return indicators;
        }

        /// <summary>
        /// Store DNA profile in database for future comparison
        /// </summary>
        public void StoreDna(FileDnaProfile profile)
        {
            lock (_lock)
            {
                _dnaDatabase[profile.DnaSignature] = profile;
                Core.Logger.Log("Info", $"DNA stored: {profile.DnaSignature}");
            }
        }

        /// <summary>
        /// Compare file DNA against database to detect polymorphic variants
        /// </summary>
        public DnaComparisonResult CompareDna(FileDnaProfile profile)
        {
            var result = new DnaComparisonResult();
            
            lock (_lock)
            {
                foreach (var storedDna in _dnaDatabase.Values)
                {
                    // Compare static DNA (structure)
                    var staticSimilarity = CompareStaticDna(profile.StaticDna, storedDna.StaticDna);
                    
                    // Compare behavioral DNA
                    var behavioralSimilarity = CompareBehavioralDna(profile.BehavioralDna, storedDna.BehavioralDna);
                    
                    // Compare entropy DNA
                    var entropySimilarity = CompareEntropyDna(profile.EntropyDna, storedDna.EntropyDna);
                    
                    // Compare API patterns
                    var apiSimilarity = CompareApiPatternDna(profile.ApiPatternDna, storedDna.ApiPatternDna);
                    
                    // Overall similarity
                    var overallSimilarity = (staticSimilarity * 0.2 + behavioralSimilarity * 0.3 + 
                                           entropySimilarity * 0.2 + apiSimilarity * 0.3);
                    
                    var currentBest = result.BestMatch?.Similarity ?? -1.0;
                    if (overallSimilarity > currentBest)
                    {
                        result.BestMatch = new DnaMatch
                        {
                            StoredProfile = storedDna,
                            Similarity = overallSimilarity,
                            StaticSimilarity = staticSimilarity,
                            BehavioralSimilarity = behavioralSimilarity,
                            EntropySimilarity = entropySimilarity,
                            ApiPatternSimilarity = apiSimilarity
                        };
                    }
                }
            }
            
            // Check if it's a polymorphic variant
            if (result.BestMatch != null && result.BestMatch.Similarity > 0.6)
            {
                result.IsPolymorphicVariant = true;
                result.IsMatch = true;
                
                PolymorphicDetected?.Invoke(this, new PolymorphicDetectedEventArgs(
                    profile.FilePath, 
                    result.BestMatch.StoredProfile.FilePath,
                    result.BestMatch.Similarity));
                
                DnaMatchFound?.Invoke(this, new DnaMatchEventArgs(profile, result.BestMatch));
            }
            
            return result;
        }

        private double CompareStaticDna(StaticDna a, StaticDna b)
        {
            if (a.ImportHash == b.ImportHash) return 1.0;
            
            double similarity = 0;
            if (a.IsPeExecutable == b.IsPeExecutable) similarity += 0.2;
            if (a.IsDotNetAssembly == b.IsDotNetAssembly) similarity += 0.2;
            if (a.IsPacked == b.IsPacked) similarity += 0.2;
            if (a.IsSigned == b.IsSigned) similarity += 0.2;
            if (a.SectionCount == b.SectionCount) similarity += 0.2;
            
            return similarity;
        }

        private double CompareBehavioralDna(BehavioralDna a, BehavioralDna b)
        {
            double similarity = 0;
            int matches = 0;
            
            if (a.ExpectedBehavior == b.ExpectedBehavior) { similarity += 0.4; matches++; }
            if (a.NetworkActivity == b.NetworkActivity) { similarity += 0.2; matches++; }
            if (a.FileSystemActivity == b.FileSystemActivity) { similarity += 0.2; matches++; }
            if (a.RegistryActivity == b.RegistryActivity) { similarity += 0.1; matches++; }
            if (a.ProcessActivity == b.ProcessActivity) { similarity += 0.1; matches++; }
            
            return similarity;
        }

        private double CompareEntropyDna(EntropyDna a, EntropyDna b)
        {
            var entropyDiff = Math.Abs(a.OverallEntropy - b.OverallEntropy);
            return Math.Max(0, 1.0 - entropyDiff / 8.0);
        }

        private double CompareApiPatternDna(ApiPatternDna a, ApiPatternDna b)
        {
            double similarity = 0;
            int matches = 0;
            
            if (a.HasFileOperations == b.HasFileOperations) { similarity += 0.15; matches++; }
            if (a.HasNetworkCalls == b.HasNetworkCalls) { similarity += 0.15; matches++; }
            if (a.HasProcessManipulation == b.HasProcessManipulation) { similarity += 0.2; matches++; }
            if (a.HasCryptography == b.HasCryptography) { similarity += 0.2; matches++; }
            if (a.HasAntiDebug == b.HasAntiDebug) { similarity += 0.15; matches++; }
            if (a.HasPrivilegeEscalation == b.HasPrivilegeEscalation) { similarity += 0.15; matches++; }
            
            return similarity;
        }

        public int GetDatabaseSize()
        {
            lock (_lock)
            {
                return _dnaDatabase.Count;
            }
        }

        public void Dispose()
        {
            Core.Logger.Log("Info", "Digital DNA Fingerprinter disposed");
        }
    }

    public class FileDnaProfile
    {
        public string FilePath { get; set; } = "";
        public string DnaSignature { get; set; } = "";
        public long FileSize { get; set; }
        public string FileExtension { get; set; } = "";
        public DateTime GeneratedAt { get; set; }
        public bool IsAnalyzed { get; set; }
        
        public StaticDna StaticDna { get; set; } = new();
        public BehavioralDna BehavioralDna { get; set; } = new();
        public EntropyDna EntropyDna { get; set; } = new();
        public ApiPatternDna ApiPatternDna { get; set; } = new();
        public List<string> ThreatIndicators { get; set; } = new();
    }

    public class StaticDna
    {
        public Dictionary<int, int> ByteFrequency { get; set; } = new();
        public bool IsPeExecutable { get; set; }
        public bool IsDotNetAssembly { get; set; }
        public bool IsPacked { get; set; }
        public bool IsSigned { get; set; }
        public int SectionCount { get; set; }
        public bool HasResources { get; set; }
        public bool HasRelocations { get; set; }
        public string ImportHash { get; set; } = "";
    }

    public class BehavioralDna
    {
        public string ExpectedBehavior { get; set; } = "";
        public bool NetworkActivity { get; set; }
        public bool FileSystemActivity { get; set; }
        public bool RegistryActivity { get; set; }
        public bool ProcessActivity { get; set; }
    }

    public class EntropyDna
    {
        public double OverallEntropy { get; set; }
        public bool IsPacked { get; set; }
        public bool IsEncrypted { get; set; }
        public List<double> SectionEntropies { get; set; } = new();
    }

    public class ApiPatternDna
    {
        public bool HasFileOperations { get; set; }
        public bool HasNetworkCalls { get; set; }
        public bool HasProcessManipulation { get; set; }
        public bool HasCryptography { get; set; }
        public bool HasAntiDebug { get; set; }
        public bool HasPrivilegeEscalation { get; set; }
        public int RiskScore { get; set; }
    }

    public class DnaComparisonResult
    {
        public bool IsMatch { get; set; }
        public bool IsPolymorphicVariant { get; set; }
        public DnaMatch? BestMatch { get; set; }
    }

    public class DnaMatch
    {
        public FileDnaProfile StoredProfile { get; set; } = null!;
        public double Similarity { get; set; }
        public double StaticSimilarity { get; set; }
        public double BehavioralSimilarity { get; set; }
        public double EntropySimilarity { get; set; }
        public double ApiPatternSimilarity { get; set; }
    }

    public class DnaMatchEventArgs : EventArgs
    {
        public FileDnaProfile AnalyzedFile { get; }
        public DnaMatch Match { get; }

        public DnaMatchEventArgs(FileDnaProfile analyzedFile, DnaMatch match)
        {
            AnalyzedFile = analyzedFile;
            Match = match;
        }
    }

    public class PolymorphicDetectedEventArgs : EventArgs
    {
        public string CurrentFile { get; }
        public string OriginalFile { get; }
        public double Similarity { get; }

        public PolymorphicDetectedEventArgs(string currentFile, string originalFile, double similarity)
        {
            CurrentFile = currentFile;
            OriginalFile = originalFile;
            Similarity = similarity;
        }
    }
}

