using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace SecureGuard.Core
{
    public enum LicensePlan
    {
        Free,
        Pro,
        Premium,
        Ultimate,
        Startup,
        Business,
        Enterprise
    }

    public class LicenseInfo
    {
        public string LicenseKey { get; set; } = string.Empty;
        public LicensePlan Plan { get; set; } = LicensePlan.Free;
        public DateTime ActivationDate { get; set; } = DateTime.Now;
        public DateTime ExpiryDate { get; set; } = DateTime.Now.AddDays(30);
        public string DeviceId { get; set; } = string.Empty;
        public string UserEmail { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
        public int MaxDevices { get; set; } = 1;
    }

    public class LicenseManager
    {
        private readonly string _licenseFilePath;
        private LicenseInfo? _currentLicense;

        public LicenseManager()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard");
            Directory.CreateDirectory(appDataPath);
_licenseFilePath = Path.Combine(appDataPath, "license");
            LoadLicense();
        }

        private void LoadLicense()
        {
            try
            {
                if (File.Exists(_licenseFilePath))
                {
                    var encrypted = File.ReadAllBytes(_licenseFilePath);
                    var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
                    var json = Encoding.UTF8.GetString(decrypted);
                    _currentLicense = JsonConvert.DeserializeObject<LicenseInfo>(json);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load license", ex);
                _currentLicense = null;
            }
        }

        public void SaveLicense(LicenseInfo license)
        {
            try
            {
                var json = JsonConvert.SerializeObject(license);
                var data = Encoding.UTF8.GetBytes(json);
                var encrypted = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(_licenseFilePath, encrypted);
                _currentLicense = license;
                Logger.Log("Info", "License saved successfully");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save license", ex);
            }
        }

        public bool ActivateLicense(string licenseKey, string email)
        {
            // In production, this would validate against a server
            // For demo, we accept any key format
            if (string.IsNullOrWhiteSpace(licenseKey) || licenseKey.Length < 10)
            {
                return false;
            }

            var plan = DeterminePlan(licenseKey);
            var license = new LicenseInfo
            {
                LicenseKey = licenseKey,
                Plan = plan,
                ActivationDate = DateTime.Now,
                ExpiryDate = GetExpiryDate(plan),
                DeviceId = GetDeviceId(),
                UserEmail = email,
                IsActive = true,
                MaxDevices = GetMaxDevices(plan)
            };

            SaveLicense(license);
            Logger.Log("Info", $"License activated: {plan}");
            return true;
        }

        public bool ValidateLicense()
        {
            if (_currentLicense == null)
                return false;

            // Check if expired
            if (_currentLicense.ExpiryDate < DateTime.Now)
            {
                // Check grace period (7 days)
                if (_currentLicense.ExpiryDate.AddDays(7) < DateTime.Now)
                {
                    _currentLicense.IsActive = false;
                    return false;
                }
            }

            // Check device binding
            if (_currentLicense.DeviceId != GetDeviceId())
            {
                return false;
            }

            return _currentLicense.IsActive;
        }

        public LicenseInfo? GetCurrentLicense()
        {
            if (ValidateLicense())
                return _currentLicense;
            return null;
        }

        public void DeactivateLicense()
        {
            if (_currentLicense != null)
            {
                _currentLicense.IsActive = false;
                SaveLicense(_currentLicense);
                Logger.Log("Info", "License deactivated");
            }
        }

        public bool RenewLicense(string licenseKey)
        {
            if (ActivateLicense(licenseKey, _currentLicense?.UserEmail ?? ""))
            {
                Logger.Log("Info", "License renewed");
                return true;
            }
            return false;
        }

        private LicensePlan DeterminePlan(string licenseKey)
        {
            // In production, this would query a server
            // For demo, determine by key length/prefix
            if (licenseKey.StartsWith("ENT-"))
                return LicensePlan.Enterprise;
            if (licenseKey.StartsWith("BUS-"))
                return LicensePlan.Business;
            if (licenseKey.StartsWith("ST-"))
                return LicensePlan.Startup;
            if (licenseKey.StartsWith("ULT-"))
                return LicensePlan.Ultimate;
            if (licenseKey.StartsWith("PRM-"))
                return LicensePlan.Premium;
            if (licenseKey.StartsWith("PRO-"))
                return LicensePlan.Pro;
            return LicensePlan.Free;
        }

        private DateTime GetExpiryDate(LicensePlan plan)
        {
            return plan switch
            {
                LicensePlan.Free => DateTime.Now.AddYears(1),
                LicensePlan.Pro => DateTime.Now.AddYears(1),
                LicensePlan.Premium => DateTime.Now.AddYears(1),
                LicensePlan.Ultimate => DateTime.Now.AddYears(1),
                LicensePlan.Startup => DateTime.Now.AddYears(1),
                LicensePlan.Business => DateTime.Now.AddYears(1),
                LicensePlan.Enterprise => DateTime.Now.AddYears(10),
                _ => DateTime.Now.AddDays(30)
            };
        }

        private int GetMaxDevices(LicensePlan plan)
        {
            return plan switch
            {
                LicensePlan.Free => 1,
                LicensePlan.Pro => 1,
                LicensePlan.Premium => 3,
                LicensePlan.Ultimate => 5,
                LicensePlan.Startup => 10,
                LicensePlan.Business => 50,
                LicensePlan.Enterprise => 999,
                _ => 1
            };
        }

        private string GetDeviceId()
        {
            // Generate a unique device ID based on hardware
            var cpuId = GetCpuId();
            var mbId = GetMotherboardId();
            return Convert.ToBase64String(SHA256.Create().ComputeHash(
                Encoding.UTF8.GetBytes(cpuId + mbId)))[..16];
        }

        private string GetCpuId()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT ProcessorId FROM Win32_Processor");
                foreach (var obj in searcher.Get())
                {
                    return obj["ProcessorId"]?.ToString() ?? "";
                }
            }
            catch { }
            return "CPU-DEFAULT";
        }

        private string GetMotherboardId()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT SerialNumber FROM Win32_BaseBoard");
                foreach (var obj in searcher.Get())
                {
                    return obj["SerialNumber"]?.ToString() ?? "";
                }
            }
            catch { }
            return "MB-DEFAULT";
        }
    }
}
