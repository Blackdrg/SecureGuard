using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace SecureGuard.Core
{
    [ComImport, Guid("272784AF-3E70-48D4-B827-5FF35F2C2DF3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IWSCSecurityProvider
    {
        void Initialize([In] IntPtr pCtrl, [In] IntPtr pCallback);
        void Cleanup();
        void ProductId([Out] IntPtr productId);
        void ProductName([Out] IntPtr productName);
        void UpdatePath([Out] IntPtr updatePath);
        void QuarantinePath([Out] IntPtr quarantinePath);
        void EngineVersion([Out] IntPtr engineVersion);
        void DefinitionVersion([Out] IntPtr definitionVersion);
        void DisplayName([Out] IntPtr displayName);
        void Path([Out] IntPtr path);
        void ProviderState([Out] IntPtr providerState);
        void ProductState([Out] IntPtr productState);
        void ProductStateTimestamp([Out] IntPtr productStateTimestamp);
    }

    [ComImport, Guid("A61CEFC1-1A02-4B58-9385-9AF5E14B289C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IWSCRegistration
    {
        void RegisterSecurityProvider([In] IWSCSecurityProvider pSecurityProvider);
        void UnregisterSecurityProvider([In] IWSCSecurityProvider pSecurityProvider);
    }

    public class WindowsSecurityCenter
    {
        private const string CLSID_WSCRegistration = "{A61CEFC1-1A02-4B58-9385-9AF5E14B289C}";
        private const string IID_IWSCRegistration = CLSID_WSCRegistration;
        private IWSCSecurityProvider? _provider;
        private bool _registered;

        public bool IsRegistered => _registered;

        public bool Register()
        {
            try
            {
                var type = Type.GetTypeFromCLSID(new Guid(CLSID_WSCRegistration));
                if (type == null) return false;

                dynamic wscReg = Activator.CreateInstance(type);
                if (wscReg == null) return false;

                _provider = new SecureGuardSecurityProvider();
                wscReg.RegisterSecurityProvider(_provider);
                _registered = true;

                Logger.Log("Info", "Registered as Windows Security Center AV provider");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Warning", $"Failed to register WSC provider: {ex.Message}");
                return false;
            }
        }

        public bool Unregister()
        {
            try
            {
                if (!_registered || _provider == null) return false;

                var type = Type.GetTypeFromCLSID(new Guid(CLSID_WSCRegistration));
                if (type == null) return false;

                dynamic wscReg = Activator.CreateInstance(type);
                if (wscReg == null) return false;

                wscReg.UnregisterSecurityProvider(_provider);
                _registered = false;

                Logger.Log("Info", "Unregistered from Windows Security Center");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Warning", $"Failed to unregister WSC provider: {ex.Message}");
                return false;
            }
        }
    }

    [ClassInterface(ClassInterfaceType.None)]
    public class SecureGuardSecurityProvider : IWSCSecurityProvider
    {
        public void Initialize(IntPtr pCtrl, IntPtr pCallback)
        {
            Logger.Log("Debug", "WSC Security Provider initialized");
        }

        public void Cleanup()
        {
            Logger.Log("Debug", "WSC Security Provider cleanup");
        }

        public void ProductId(IntPtr productId)
        {
            Marshal.WriteIntPtr(productId, Marshal.StringToCoTaskMemUni("SecureGuardAV-001"));
        }

        public void ProductName(IntPtr productName)
        {
            Marshal.WriteIntPtr(productName, Marshal.StringToCoTaskMemUni("SecureGuard Enterprise"));
        }

        public void UpdatePath(IntPtr updatePath)
        {
            Marshal.WriteIntPtr(updatePath, Marshal.StringToCoTaskMemUni(""));
        }

        public void QuarantinePath(IntPtr quarantinePath)
        {
            var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureGuard", "quarantine");
            Marshal.WriteIntPtr(quarantinePath, Marshal.StringToCoTaskMemUni(appData));
        }

        public void EngineVersion(IntPtr engineVersion)
        {
            Marshal.WriteIntPtr(engineVersion, Marshal.StringToCoTaskMemUni("2.0.0"));
        }

        public void DefinitionVersion(IntPtr definitionVersion)
        {
            Marshal.WriteIntPtr(definitionVersion, Marshal.StringToCoTaskMemUni("2024.01.15.001"));
        }

        public void DisplayName(IntPtr displayName)
        {
            Marshal.WriteIntPtr(displayName, Marshal.StringToCoTaskMemUni("SecureGuard Enterprise Antivirus"));
        }

        public void Path(IntPtr path)
        {
            Marshal.WriteIntPtr(path, Marshal.StringToCoTaskMemUni(System.Diagnostics.Process.GetCurrentProcess().MainModule!.FileName));
        }

        public void ProviderState(IntPtr providerState)
        {
            Marshal.WriteIntPtr(providerState, (IntPtr)1); // WSC_SECURITY_PROVIDER_STATE_ON
        }

        public void ProductState(IntPtr productState)
        {
            Marshal.WriteIntPtr(productState, (IntPtr)1); // WSC_SECURITY_PRODUCT_STATE_ON
        }

        public void ProductStateTimestamp(IntPtr productStateTimestamp)
        {
            Marshal.WriteIntPtr(productStateTimestamp, Marshal.StringToCoTaskMemUni(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")));
        }
    }
}

