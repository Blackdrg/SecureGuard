using System;
using System.IO;
using System.Security.Cryptography;

namespace SecureGuard.Core
{
    public static class EncryptedStorage
    {
        public static void Save(string filePath, byte[] data)
        {
            var encrypted = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(filePath, encrypted);
        }

        public static byte[]? Load(string filePath)
        {
            if (!File.Exists(filePath)) return null;
            var encrypted = File.ReadAllBytes(filePath);
            return ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        }
    }
}
