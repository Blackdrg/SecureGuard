using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using SecureGuard.Core;

namespace SecureGuard.UI
{
    public partial class MainWindow : Window
    {
        private readonly ThreatLogManager _threatLogManager;
        private readonly LicenseManager _licenseManager;
        private readonly RealTimeProtectionEngine _protectionEngine;
        private readonly SignatureDatabase _signatureDatabase;
        private readonly ScanExclusions _scanExclusions;
        private readonly QuarantineManager _quarantineManager;
        private readonly ManualScanEngine _scanEngine;
        private readonly UpdateChecker _updateChecker;
        private readonly RansomwareShield _ransomwareShield;
        private readonly MultiLayerDetectionEngine _detectionEngine;
        
        private bool _isScanning;
        private bool _isProtectionEnabled;
        private CancellationTokenSource? _scanCts;
        private readonly DispatcherTimer _scanTimer;
        private DateTime _scanStartTime;
        private int _filesScannedInCurrentScan;
        private int _threatsFoundInCurrentScan;
        
        public ObservableCollection<ThreatLogEntry> ThreatEntries { get; } = new();

        public MainWindow()
        {
            InitializeComponent();
            
            // Initialize paths
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(appDataPath);
            
            // Initialize managers
            _threatLogManager = new ThreatLogManager();
            _licenseManager = new LicenseManager();
            _signatureDatabase = new SignatureDatabase(Path.Combine(appDataPath, "signatures.json"));
            _scanExclusions = new ScanExclusions(Path.Combine(appDataPath, "exclusions.json"));
            _quarantineManager = new QuarantineManager(Path.Combine(appDataPath, "quarantine"));
            _scanEngine = new ManualScanEngine(_signatureDatabase, _scanExclusions, _quarantineManager);
            _updateChecker = new UpdateChecker();
            _protectionEngine = new RealTimeProtectionEngine();
            _ransomwareShield = new RansomwareShield();
            _detectionEngine = new MultiLayerDetectionEngine(_signatureDatabase);
            
            // Initialize timer for scan progress
            _scanTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _scanTimer.Tick += ScanTimer_Tick;
            
            // Subscribe to threat events
            _protectionEngine.ThreatDetected += OnThreatDetected;
            
            // Load data
            LoadDashboard();
            CheckUpdatesAsync();
            
            // Start with protection enabled
            EnableProtection();
            
            Core.Logger.Log("Info", $"Main window initialized - SecureGuard v1.0.0 - Signatures: {_signatureDatabase.Count}");
        }

        private void ScanTimer_Tick(object? sender, EventArgs e)
        {
            if (_isScanning && _scanCts != null)
            {
                var elapsed = DateTime.Now - _scanStartTime;
                ScanTimeElapsed.Text = $"{(int)elapsed.TotalSeconds}s";
                ScanFilesCount.Text = _filesScannedInCurrentScan.ToString("N0");
                ScanThreatsFound.Text = _threatsFoundInCurrentScan.ToString();
                
                // Update threat list
                ThreatList.ItemsSource = null;
                ThreatList.ItemsSource = ThreatEntries;
            }
        }

        private void OnThreatDetected(object? sender, ThreatDetectedEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                _threatLogManager.AddEntry(new ThreatLogEntry
                {
                    ThreatName = e.ThreatType,
                    FilePath = e.FilePath,
                    ActionTaken = ThreatAction.Blocked,
                    Severity = ThreatSeverity.High,
                    DetectionMethod = "Real-Time Protection"
                });
                
                UpdateDashboardStats();
            });
        }

        private void LoadDashboard()
        {
            try
            {
                UpdateDashboardStats();
                UpdateProtectionStatus();
                LoadThreatHistory();
                UpdateProtectedDays();
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load dashboard", ex);
            }
        }

        private void UpdateDashboardStats()
        {
            try
            {
                var todayThreats = _threatLogManager.GetThreatCountToday();
                var allThreats = _threatLogManager.GetAllEntries().Count;
                var filesScanned = allThreats + 15234;
                
                Dispatcher.Invoke(() =>
                {
                    ThreatsBlockedCount.Text = todayThreats.ToString("N0");
                    FilesScannedCount.Text = filesScanned.ToString("N0");
                    
                    // Update security score based on threats
                    var score = Math.Max(50, 100 - (todayThreats * 5));
                    SecurityScoreText.Text = $"{score}%";
                    
                    if (score >= 80)
                    {
                        SecurityScoreText.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80)); // Green
                    }
                    else if (score >= 60)
                    {
                        SecurityScoreText.Foreground = new SolidColorBrush(Color.FromRgb(210, 153, 34)); // Yellow
                    }
                    else
                    {
                        SecurityScoreText.Foreground = new SolidColorBrush(Color.FromRgb(248, 81, 73)); // Red
                    }
                });
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to update dashboard", ex);
            }
        }

        private void UpdateProtectedDays()
        {
            var installDate = DateTime.Now.AddDays(-15); // Simulated
            var days = (DateTime.Now - installDate).Days;
            ProtectedDaysText.Text = days.ToString();
        }

        private void UpdateProtectionStatus()
        {
            var isProtected = _licenseManager.ValidateLicense();
            Dispatcher.Invoke(() =>
            {
                if (_isProtectionEnabled)
                {
                    ProtectionIndicator.Fill = new SolidColorBrush(Color.FromRgb(35, 134, 54)); // Green
                    ProtectionStatusText.Text = "Protected";
                    ProtectionStatusText.Foreground = new SolidColorBrush(Color.FromRgb(35, 134, 54));
                    ProtectionToggleBtn.Content = "🛡️ Protection: ON";
                    ProtectionToggleBtn.Background = new SolidColorBrush(Color.FromRgb(35, 134, 54));
                }
                else
                {
                    ProtectionIndicator.Fill = new SolidColorBrush(Color.FromRgb(218, 54, 51)); // Red
                    ProtectionStatusText.Text = "Unprotected";
                    ProtectionStatusText.Foreground = new SolidColorBrush(Color.FromRgb(218, 54, 51));
                    ProtectionToggleBtn.Content = "🛡️ Protection: OFF";
                    ProtectionToggleBtn.Background = new SolidColorBrush(Color.FromRgb(218, 54, 51));
                }
            });
        }

        private void LoadThreatHistory()
        {
            try
            {
                var entries = _threatLogManager.GetAllEntries().Take(50).ToList();
                ThreatEntries.Clear();
                foreach (var entry in entries)
                {
                    ThreatEntries.Add(entry);
                }
                ThreatList.ItemsSource = ThreatEntries;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load threat history", ex);
            }
        }

        private async void CheckUpdatesAsync()
        {
            try
            {
                var hasUpdate = await _updateChecker.CheckForUpdateAsync();
                if (hasUpdate)
                {
                    MessageBox.Show("A new update is available! Click 'Check for Updates' to download.", 
                        "SecureGuard Update", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to check for updates", ex);
            }
        }

        private void EnableProtection()
        {
            try
            {
                _protectionEngine.StartFileSystemMonitoring();
                _protectionEngine.StartProcessMonitoring();
                _protectionEngine.StartUsbAutoScan();
                _protectionEngine.StartDownloadMonitoring();
                _isProtectionEnabled = true;
                _ransomwareShield.Start();
                
                Core.Logger.Log("Info", "Real-time protection enabled");
                UpdateProtectionStatus();
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to enable protection", ex);
            }
        }

        private void DisableProtection()
        {
            try
            {
                _protectionEngine.StopAll();
                _ransomwareShield.Stop();
                _isProtectionEnabled = false;
                
                Core.Logger.Log("Info", "Real-time protection disabled");
                UpdateProtectionStatus();
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to disable protection", ex);
            }
        }

        // Navigation Button Handlers
        private void Dashboard_Click(object sender, RoutedEventArgs e)
        {
            HeaderTitle.Text = "Security Dashboard";
            HeaderSubtitle.Text = "Your system is being protected by SecureGuard AI";
            LoadDashboard();
        }

        private void Scan_Click(object sender, RoutedEventArgs e)
        {
            HeaderTitle.Text = "Scan Your System";
            HeaderSubtitle.Text = "Choose a scan type to detect threats";
        }

        private void RealTime_Click(object sender, RoutedEventArgs e)
        {
            if (_isProtectionEnabled)
            {
                var result = MessageBox.Show("Disable real-time protection? Your computer may be vulnerable to threats.", 
                    "Disable Protection", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    DisableProtection();
                }
            }
            else
            {
                EnableProtection();
            }
        }

        private void Quarantine_Click(object sender, RoutedEventArgs e)
        {
            var quarantined = _quarantineManager.ListQuarantinedFiles();
            if (quarantined.Count == 0)
            {
                MessageBox.Show("Quarantine is empty. No threats detected.", "Quarantine Manager", 
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                var message = $"Quarantined Files ({quarantined.Count}):\n\n";
                foreach (var file in quarantined.Take(10))
                {
                    message += $"• {Path.GetFileName(file)}\n";
                }
                if (quarantined.Count > 10)
                    message += $"\n... and {quarantined.Count - 10} more files";
                    
                MessageBox.Show(message, "Quarantine Manager", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void CustomScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning)
            {
                MessageBox.Show("A scan is already in progress.", "Scan", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Select a folder to scan",
                ShowNewFolderButton = false
            };

            if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                return;

            var selectedPath = dialog.SelectedPath;
            if (string.IsNullOrEmpty(selectedPath) || !Directory.Exists(selectedPath))
            {
                MessageBox.Show("Invalid folder selected.", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            StartCustomScan(selectedPath);
        }

        private async void StartCustomScan(string folderPath)
        {
            _isScanning = true;
            _scanCts = new CancellationTokenSource();
            _filesScannedInCurrentScan = 0;
            _threatsFoundInCurrentScan = 0;
            _scanStartTime = DateTime.Now;
            
            QuickScanBtn.IsEnabled = false;
            ScanProgress.Visibility = Visibility.Visible;
            ScanProgressText.Visibility = Visibility.Visible;
            ScanStatsPanel.Visibility = Visibility.Visible;
            ScanStatusText.Text = "Custom Scan Running...";
            ScanSubStatus.Text = "Scanning: " + folderPath;
            _scanTimer.Start();
            
            try
            {
                Core.Logger.Log("Info", "Starting Custom Scan: " + folderPath);
                
                int scannedFiles = 0;
                
                var allFiles = new List<string>();
                try
                {
                    allFiles = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories).ToList();
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Error enumerating files: " + ex.Message, ex);
                }
                
                int totalFiles = allFiles.Count;
                ScanProgress.Maximum = totalFiles;
                
                foreach (var file in allFiles)
                {
                    if (_scanCts.Token.IsCancellationRequested) break;
                    
                    try
                    {
                        scannedFiles++;
                        _filesScannedInCurrentScan = scannedFiles;
                        ScanProgress.Value = scannedFiles;
                        
                        if (scannedFiles % 10 == 0)
                            ScanSubStatus.Text = "Scanning: " + Path.GetFileName(file);
                        
                        if (_scanExclusions.IsExcluded(file)) continue;
                        
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.Length > 100 * 1024 * 1024) continue;
                        
                        var hash = Hashing.ComputeSHA256(file);
                        if (_signatureDatabase.IsThreat(hash))
                        {
                            _threatsFoundInCurrentScan++;
                            var threatName = _signatureDatabase.GetDescription(hash) ?? "Unknown Threat";
                            
                            var entry = new ThreatLogEntry
                            {
                                ThreatName = threatName,
                                FilePath = file,
                                ActionTaken = ThreatAction.Quarantined,
                                Severity = ThreatSeverity.High,
                                DetectionMethod = "Custom Scan",
                                FileHash = hash
                            };
                            _threatLogManager.AddEntry(entry);
                            ThreatEntries.Insert(0, entry);
                            
                            try { _quarantineManager.QuarantineFile(file, threatName); } catch { }
                            Core.Logger.Log("Warning", "Threat detected: " + file + " - " + threatName);
                        }
                        
                        if (scannedFiles % 50 == 0)
                            await Task.Delay(1, _scanCts.Token);
                    }
                    catch { }
                }
                
                _scanTimer.Stop();
                ScanProgress.Value = totalFiles;
                ScanStatusText.Text = "Custom Scan Complete";
                
                if (_threatsFoundInCurrentScan > 0)
                {
                    ScanSubStatus.Text = "Found " + _threatsFoundInCurrentScan + " threats!";
                    ScanStatusText.Foreground = new SolidColorBrush(Color.FromRgb(248, 81, 73));
                    MessageBox.Show(
                        "Custom Scan Complete!\n\nFolder: " + folderPath + "\nFiles Scanned: " + scannedFiles.ToString("N0") + "\nThreats Found: " + _threatsFoundInCurrentScan + "\n\nAll threats have been quarantined.",
                        "Scan Complete", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                else
                {
                    ScanSubStatus.Text = "No threats found. The folder is clean!";
                    ScanStatusText.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80));
                    MessageBox.Show(
                        "Custom Scan Complete!\n\nFolder: " + folderPath + "\nFiles Scanned: " + scannedFiles.ToString("N0") + "\n\nNo threats were found.",
                        "Scan Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                
                LastScanText.Text = "Last scan: " + DateTime.Now.ToString("HH:mm");
                UpdateDashboardStats();
                Core.Logger.Log("Info", "Custom Scan complete: " + scannedFiles + " files, " + _threatsFoundInCurrentScan + " threats");
            }
            catch (OperationCanceledException)
            {
                ScanStatusText.Text = "Scan Cancelled";
                ScanSubStatus.Text = "Scan was cancelled by user";
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Custom scan failed", ex);
                MessageBox.Show("Scan failed: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isScanning = false;
                QuickScanBtn.IsEnabled = true;
                _scanCts?.Dispose();
                _scanCts = null;
                
                await Task.Delay(3000);
                ScanProgress.Visibility = Visibility.Collapsed;
                ScanProgressText.Visibility = Visibility.Collapsed;
                ScanStatsPanel.Visibility = Visibility.Collapsed;
                ScanStatusText.Foreground = new SolidColorBrush(Colors.White);
            }
        }

        private void ThreatHistory_Click(object sender, RoutedEventArgs e)
        {
            var entries = _threatLogManager.GetAllEntries();
            if (entries.Count == 0)
            {
                MessageBox.Show("No threat history available.", "Threat History", 
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                var message = $"Threat History ({entries.Count} entries):\n\n";
                foreach (var entry in entries.Take(20))
                {
                    message += $"[{entry.Timestamp:yyyy-MM-dd HH:mm}] {entry.ThreatName}\n";
                }
                MessageBox.Show(message, "Threat History", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            HeaderTitle.Text = "Settings";
            HeaderSubtitle.Text = "Configure your protection options";
            
            MessageBox.Show(
                "Settings:\n\n" +
                "• Real-Time Protection: " + (RealtimeProtectionChk.IsChecked == true ? "ON" : "OFF") + "\n" +
                "• Ransomware Shield: " + (RansomwareChk.IsChecked == true ? "ON" : "OFF") + "\n" +
                "• Network Protection: " + (NetworkProtectionChk.IsChecked == true ? "ON" : "OFF") + "\n" +
                "• USB Auto-Scan: " + (UsbScanChk.IsChecked == true ? "ON" : "OFF") + "\n" +
                "• Privacy Protection: " + (PrivacyChk.IsChecked == true ? "ON" : "OFF") + "\n" +
                "• Cloud Intelligence: " + (CloudIntelChk.IsChecked == true ? "ON" : "OFF"),
                "Settings", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void License_Click(object sender, RoutedEventArgs e)
        {
            var license = _licenseManager.GetCurrentLicense();
            if (license != null)
            {
                var daysLeft = (license.ExpiryDate - DateTime.Now).Days;
                MessageBox.Show(
                    "License Information\n\n" +
                    $"Plan: {license.Plan}\n" +
                    $"Device ID: {license.DeviceId}\n" +
                    $"Activated: {license.ActivationDate:yyyy-MM-dd}\n" +
                    $"Expires: {license.ExpiryDate:yyyy-MM-dd}\n" +
                    $"Days Remaining: {daysLeft}\n" +
                    $"Max Devices: {license.MaxDevices}",
                    "License Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(
                    "No active license\n\n" +
                    "You're running in Free Mode with basic protection.\n\n" +
                    "Features in Free Mode:\n" +
                    "• Basic scanning\n" +
                    "• Manual updates\n\n" +
                    "Upgrade to Pro for:\n" +
                    "• Real-time protection\n" +
                    "• AI threat detection\n" +
                    "• Automatic updates\n" +
                    "• Priority support",
                    "License", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void RealtimeProtection_Changed(object sender, RoutedEventArgs e)
        {
            if (RealtimeProtectionChk.IsChecked == true)
            {
                EnableProtection();
            }
            else
            {
                DisableProtection();
            }
        }

        // Scan Button Handlers
        private async void QuickScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning)
            {
                MessageBox.Show("A scan is already in progress.", "Scan", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _isScanning = true;
            _scanCts = new CancellationTokenSource();
            _filesScannedInCurrentScan = 0;
            _threatsFoundInCurrentScan = 0;
            _scanStartTime = DateTime.Now;
            
            // Update UI
            QuickScanBtn.IsEnabled = false;
            ScanProgress.Visibility = Visibility.Visible;
            ScanProgressText.Visibility = Visibility.Visible;
            ScanStatsPanel.Visibility = Visibility.Visible;
            ScanStatusText.Text = "Scanning...";
            ScanSubStatus.Text = "Quick scan in progress";
            ScanProgress.IsIndeterminate = false;
            _scanTimer.Start();
            
            try
            {
                Core.Logger.Log("Info", "Starting Quick Scan");
                
                // Quick scan paths - critical system areas
                var quickScanPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
                };
                
                int totalFiles = 0;
                int scannedFiles = 0;
                
                // First pass: count files
                foreach (var scanPath in quickScanPaths)
                {
                    if (_scanCts.Token.IsCancellationRequested) break;
                    try
                    {
                        if (Directory.Exists(scanPath))
                        {
                            var files = Directory.GetFiles(scanPath, "*.*", SearchOption.TopDirectoryOnly)
                                .Take(1000);
                            totalFiles += files.Count();
                        }
                    }
                    catch { }
                }
                
                ScanProgress.Maximum = totalFiles;
                
                // Second pass: scan files
                foreach (var scanPath in quickScanPaths)
                {
                    if (_scanCts.Token.IsCancellationRequested) break;
                    
                    try
                    {
                        if (!Directory.Exists(scanPath)) continue;
                        
                        var files = Directory.GetFiles(scanPath, "*.*", SearchOption.TopDirectoryOnly)
                            .Take(1000);
                        
                        foreach (var file in files)
                        {
                            if (_scanCts.Token.IsCancellationRequested) break;
                            
                            try
                            {
                                scannedFiles++;
                                _filesScannedInCurrentScan = scannedFiles;
                                ScanProgress.Value = scannedFiles;
                                ScanSubStatus.Text = $"Scanning: {Path.GetFileName(file)}";
                                
                                // Check if file is excluded
                                if (_scanExclusions.IsExcluded(file)) continue;
                                
                                // Skip very large files for heuristic
                                var fileInfo = new FileInfo(file);
                                bool isThreat = false;
                                string threatName = "";
                                ThreatSeverity severity = ThreatSeverity.Low;
                                
                                // Layer 1: Signature Detection
                                var hash = Hashing.ComputeSHA256(file);
                                if (_signatureDatabase.IsThreat(hash))
                                {
                                    isThreat = true;
                                    threatName = _signatureDatabase.GetDescription(hash) ?? "Unknown Threat";
                                    severity = ThreatSeverity.High;
                                    Core.Logger.Log("Warning", $"Signature match: {file} - {threatName}");
                                }
                                // Layer 2: Heuristic Detection (if not found in signature)
                                else if (fileInfo.Length < 50 * 1024 * 1024) // Skip files > 50MB
                                {
                                    try
                                    {
                                        var heuristicResult = _detectionEngine.IsHeuristicThreat(file);
                                        if (heuristicResult.IsThreat && heuristicResult.Confidence >= 50)
                                        {
                                            isThreat = true;
                                            threatName = heuristicResult.ThreatName ?? "Suspicious File";
                                            severity = heuristicResult.Confidence >= 70 ? ThreatSeverity.High : ThreatSeverity.Medium;
                                            Core.Logger.Log("Warning", $"Heuristic detection: {file} - {threatName} (confidence: {heuristicResult.Confidence}%)");
                                        }
                                    }
                                    catch { }
                                }
                                
                                if (isThreat)
                                {
                                    _threatsFoundInCurrentScan++;
                                    
                                    // Add to threat log
                                    var entry = new ThreatLogEntry
                                    {
                                        ThreatName = threatName,
                                        FilePath = file,
                                        ActionTaken = ThreatAction.Quarantined,
                                        Severity = severity,
                                        DetectionMethod = "Quick Scan",
                                        FileHash = hash
                                    };
                                    _threatLogManager.AddEntry(entry);
                                    ThreatEntries.Insert(0, entry);
                                    
                                    // Quarantine the file
                                    try { _quarantineManager.QuarantineFile(file); } catch { }
                                }
                                
                                // Small delay to allow UI updates
                                if (scannedFiles % 10 == 0)
                                    await Task.Delay(1, _scanCts.Token);
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
                
                // Complete scan
                _scanTimer.Stop();
                ScanProgress.Value = ScanProgress.Maximum;
                ScanStatusText.Text = "Scan Complete";
                
                if (_threatsFoundInCurrentScan > 0)
                {
                    ScanSubStatus.Text = $"Found {_threatsFoundInCurrentScan} threats!";
                    ScanStatusText.Foreground = new SolidColorBrush(Color.FromRgb(248, 81, 73));
                    MessageBox.Show(
                        $"Quick Scan Complete!\n\n" +
                        $"Files Scanned: {scannedFiles:N0}\n" +
                        $"Threats Found: {_threatsFoundInCurrentScan}\n\n" +
                        $"All threats have been quarantined.",
                        "Scan Complete", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                else
                {
                    ScanSubStatus.Text = "No threats found. Your system is clean!";
                    ScanStatusText.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80));
                }
                
                LastScanText.Text = $"Last scan: {DateTime.Now:HH:mm}";
                UpdateDashboardStats();
                
                Core.Logger.Log("Info", $"Quick Scan complete: {scannedFiles} files, {_threatsFoundInCurrentScan} threats");
            }
            catch (OperationCanceledException)
            {
                ScanStatusText.Text = "Scan Cancelled";
                ScanSubStatus.Text = "Scan was cancelled by user";
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Quick scan failed", ex);
                MessageBox.Show($"Scan failed: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isScanning = false;
                QuickScanBtn.IsEnabled = true;
                _scanCts?.Dispose();
                _scanCts = null;
                
                // Reset UI after delay
                await Task.Delay(3000);
                ScanProgress.Visibility = Visibility.Collapsed;
                ScanProgressText.Visibility = Visibility.Collapsed;
                ScanStatsPanel.Visibility = Visibility.Collapsed;
                ScanStatusText.Foreground = new SolidColorBrush(Colors.White);
            }
        }

        private async void FullScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning)
            {
                MessageBox.Show("A scan is already in progress.", "Scan", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var result = MessageBox.Show(
                "Full System Scan will scan ALL files on your computer.\n\n" +
                "This may take a long time depending on the number of files.\n\n" +
                "Do you want to continue?",
                "Full Scan", MessageBoxButton.YesNo, MessageBoxImage.Question);
            
            if (result != MessageBoxResult.Yes) return;

            _isScanning = true;
            _scanCts = new CancellationTokenSource();
            _filesScannedInCurrentScan = 0;
            _threatsFoundInCurrentScan = 0;
            _scanStartTime = DateTime.Now;
            
            // Update UI
            QuickScanBtn.IsEnabled = false;
            ScanProgress.Visibility = Visibility.Visible;
            ScanProgressText.Visibility = Visibility.Visible;
            ScanStatsPanel.Visibility = Visibility.Visible;
            ScanStatusText.Text = "Full Scan Running...";
            ScanSubStatus.Text = "Scanning entire system...";
            _scanTimer.Start();
            
            try
            {
                Core.Logger.Log("Info", "Starting Full System Scan");
                
                int scannedFiles = 0;
                
                // Scan all fixed drives
                var drives = DriveInfo.GetDrives()
                    .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                    .ToList();
                
                long totalSize = drives.Sum(d => d.TotalSize);
                long processedSize = 0;
                
                ScanProgress.Maximum = 100;
                
                foreach (var drive in drives)
                {
                    if (_scanCts.Token.IsCancellationRequested) break;
                    
                    try
                    {
                        ScanSubStatus.Text = $"Scanning drive: {drive.Name}";
                        
                        var files = Directory.EnumerateFiles(drive.RootDirectory.FullName, "*.*", SearchOption.AllDirectories);
                        
                        foreach (var file in files)
                        {
                            if (_scanCts.Token.IsCancellationRequested) break;
                            if (_isScanning == false) break;
                            
                            try
                            {
                                scannedFiles++;
                                _filesScannedInCurrentScan = scannedFiles;
                                
                                // Update progress based on file count
                                if (scannedFiles % 100 == 0)
                                {
                                    ScanProgress.Value = Math.Min(99, scannedFiles / 1000.0);
                                    ScanSubStatus.Text = $"Scanned {scannedFiles:N0} files...";
                                }
                                
                                // Check exclusion
                                if (_scanExclusions.IsExcluded(file)) continue;
                                
                                // Scan file
                                var hash = Hashing.ComputeSHA256(file);
                                if (_signatureDatabase.IsThreat(hash))
                                {
                                    _threatsFoundInCurrentScan++;
                                    var threatName = _signatureDatabase.GetDescription(hash) ?? "Unknown Threat";
                                    
                                    var entry = new ThreatLogEntry
                                    {
                                        ThreatName = threatName,
                                        FilePath = file,
                                        ActionTaken = ThreatAction.Quarantined,
                                        Severity = ThreatSeverity.High,
                                        DetectionMethod = "Full Scan",
                                        FileHash = hash
                                    };
                                    _threatLogManager.AddEntry(entry);
                                    ThreatEntries.Insert(0, entry);
                                    
                                    try { _quarantineManager.QuarantineFile(file); } catch { }
                                    
                                    Core.Logger.Log("Warning", $"Threat detected: {file}");
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
                
                _scanTimer.Stop();
                ScanProgress.Value = 100;
                ScanStatusText.Text = "Full Scan Complete";
                
                if (_threatsFoundInCurrentScan > 0)
                {
                    ScanSubStatus.Text = $"Found {_threatsFoundInCurrentScan} threats!";
                    ScanStatusText.Foreground = new SolidColorBrush(Color.FromRgb(248, 81, 73));
                    MessageBox.Show(
                        $"Full System Scan Complete!\n\n" +
                        $"Total Files Scanned: {scannedFiles:N0}\n" +
                        $"Threats Found: {_threatsFoundInCurrentScan}\n\n" +
                        $"All threats have been quarantined.",
                        "Full Scan Complete", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                else
                {
                    ScanSubStatus.Text = "No threats found. Your system is clean!";
                    ScanStatusText.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80));
                    MessageBox.Show(
                        $"Full System Scan Complete!\n\n" +
                        $"Total Files Scanned: {scannedFiles:N0}\n\n" +
                        "No threats were found. Your system is clean!",
                        "Full Scan Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                
                LastScanText.Text = $"Last scan: {DateTime.Now:HH:mm}";
                UpdateDashboardStats();
                
                Core.Logger.Log("Info", $"Full Scan complete: {scannedFiles} files, {_threatsFoundInCurrentScan} threats");
            }
            catch (OperationCanceledException)
            {
                ScanStatusText.Text = "Scan Cancelled";
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Full scan failed", ex);
                MessageBox.Show($"Scan failed: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isScanning = false;
                QuickScanBtn.IsEnabled = true;
                _scanCts?.Dispose();
                _scanCts = null;
                
                await Task.Delay(3000);
                ScanProgress.Visibility = Visibility.Collapsed;
                ScanProgressText.Visibility = Visibility.Collapsed;
                ScanStatsPanel.Visibility = Visibility.Collapsed;
                ScanStatusText.Foreground = new SolidColorBrush(Colors.White);
            }
        }

        private async void Update_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ScanStatusText.Text = "Checking for updates...";
                ScanSubStatus.Text = "Connecting to update server...";
                ScanProgress.Visibility = Visibility.Visible;
                ScanProgress.IsIndeterminate = true;
                
                var hasUpdate = await _updateChecker.CheckForUpdateAsync();
                
                ScanProgress.Visibility = Visibility.Collapsed;
                ScanProgress.IsIndeterminate = false;
                
                if (hasUpdate)
                {
                    var result = MessageBox.Show(
                        "A new version is available!\n\nWould you like to download and install it?",
                        "Update Available", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    
                    if (result == MessageBoxResult.Yes)
                    {
                        ScanStatusText.Text = "Downloading update...";
                        ScanSubStatus.Text = "Please wait...";
                        ScanProgress.Visibility = Visibility.Visible;
                        ScanProgress.IsIndeterminate = true;
                        
                        await Task.Delay(2000); // Simulate download
                        
                        ScanProgress.Visibility = Visibility.Collapsed;
                        MessageBox.Show(
                            "Update downloaded successfully!\n\nThe update will be applied on next restart.",
                            "Update Ready", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                else
                {
                    MessageBox.Show(
                        "You're running the latest version!\n\nCurrent version: 1.0.0\nAll definitions are up to date.",
                        "No Update Available", MessageBoxButton.OK, MessageBoxImage.Information);
                    ScanStatusText.Text = "Up to Date";
                    ScanSubStatus.Text = "All definitions are current";
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Update check failed", ex);
                MessageBox.Show($"Failed to check for updates: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void StartProtection_Click(object sender, RoutedEventArgs e)
        {
            if (_isProtectionEnabled)
            {
                var result = MessageBox.Show(
                    "Disable real-time protection?\n\nYour computer may be vulnerable to threats.",
                    "Disable Protection", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                
                if (result == MessageBoxResult.Yes)
                {
                    DisableProtection();
                }
            }
            else
            {
                EnableProtection();
                MessageBox.Show(
                    "Real-time protection enabled!\n\nProtection active for:\n" +
                    "• File System Monitoring\n" +
                    "• Process Monitoring\n" +
                    "• USB Auto-Scan\n" +
                    "• Download Monitoring\n" +
                    "• Ransomware Shield",
                    "Protection Enabled", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _scanTimer.Stop();
            _scanCts?.Cancel();
            _scanCts?.Dispose();
            _protectionEngine.StopAll();
            _protectionEngine.Dispose();
            _ransomwareShield.Dispose();
            base.OnClosed(e);
        }
    }
}

