using System;
using System.Windows;
using SecureGuard.Core;

namespace SecureGuard.UI
{
    public partial class PrivacyConsentDialog : Window
    {
        private readonly ConsentManager _consentManager;
        
        public PrivacyConsentDialog(ConsentManager consentManager)
        {
            InitializeComponent();
            _consentManager = consentManager;
            
            // Default selections for protection
            WebcamChk.IsChecked = true;
            MicChk.IsChecked = true;
            KeyloggerChk.IsChecked = true;
        }
        
        private void AcceptBtn_Click(object sender, RoutedEventArgs e)
        {
            var types = ConsentType.None;
            
            if (TelemetryChk.IsChecked == true) types |= ConsentType.Telemetry;
            if (WebcamChk.IsChecked == true) types |= ConsentType.Webcam;
            if (MicChk.IsChecked == true) types |= ConsentType.Microphone;
            if (KeyloggerChk.IsChecked == true) types |= ConsentType.KeyloggerProtection;
            if (DarkWebChk.IsChecked == true) types |= ConsentType.DarkWebMonitoring;
            if (CloudSyncChk.IsChecked == true) types |= ConsentType.CloudSync;
            
            bool isEU = true; // Detect from region/IP in production
            
            _consentManager.GrantConsent(types, isEU);
            
            DialogResult = true;
            Close();
        }
        
        private void DeclineBtn_Click(object sender, RoutedEventArgs e)
        {
            // Minimal consent for basic protection
            var basicTypes = ConsentType.KeyloggerProtection | ConsentType.Webcam | ConsentType.Microphone;
            _consentManager.GrantConsent(basicTypes, isEU: true);
            
            DialogResult = false;
            Close();
        }
    }
}

