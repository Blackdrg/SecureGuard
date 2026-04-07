using System.Security.Cryptography;
using System.Text;
using System;

namespace SecureGuard.Core
{
    public static class Hashing
    {
        /// <summary>
        /// Compute SHA256 hash of a file
        /// </summary>
        public static string ComputeSHA256(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = System.IO.File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", string.Empty).ToLower();
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Failed to compute SHA256 for {filePath}", ex);
                return string.Empty;
            }
        }

        /// <summary>
        /// Compute MD5 hash of a file
        /// </summary>
        public static string ComputeMD5(string filePath)
        {
            try
            {
                using var md5 = MD5.Create();
                using var stream = System.IO.File.OpenRead(filePath);
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", string.Empty).ToLower();
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Failed to compute MD5 for {filePath}", ex);
                return string.Empty;
            }
        }

        /// <summary>
        /// Compute both SHA256 and MD5 hashes
        /// </summary>
        public static (string sha256, string md5) ComputeBoth(string filePath)
        {
            return (ComputeSHA256(filePath), ComputeMD5(filePath));
        }
    }
}
