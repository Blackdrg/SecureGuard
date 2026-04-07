# SecureGuard Critical Risks TODO - False Positives, Defender, Privacy (Pre-Shipping)

## Status
- [x] Plan created & approved
- [x] TODO.md created ✅ (2024)

## 1. False Positives - Exclusion Tuning [Priority 1]
- [x] Enhance src/Core/ScanExclusions.cs: Add SHA256 hash exclusions, regex patterns, recursive dirs, common apps list
- [x] Pre-populate exclusions.json with VSCode/Office/browsers/Node
- [ ] Create src/UI/ExclusionTunerWindow.xaml + .cs: WPF tuning dashboard
- [x] Integrate with src/Core/RealTimeProtectionEngine.cs: Check IsExcluded before scan/quarantine
- [ ] Add false-positive feedback: New FalsePositiveReporter.cs -> CloudThreatIntelligence.cs API

## 2. Windows Defender Coexistence [Priority 2]
- [ ] New src/Core/WindowsSecurityCenter.cs: IWSCSecurityProvider COM impl, Register/Unregister
- [ ] Update src/Core/KernelDriverInterface.cs: Call Register on Connect()
- [ ] Update installer/SecureGuardSetup.iss + Install-SecureGuard.ps1: COM reg, WSC notify on install/uninstall
- [ ] Test: `Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct | Select DisplayName`

## 3. Privacy/Legal Consent [Priority 3]
- [ ] New src/Core/ConsentManager.cs: JSON storage (LocalAppData), consent types (mic/webcam/keystroke/telemetry)
- [ ] Enhance src/Privacy/PrivacyFeatures.cs: Real blocks (P/Invoke), consent checks before hook
- [ ] New src/UI/PrivacyConsentDialog.xaml + .cs: Startup modal with checkboxes, GDPR notice
- [ ] Update website/privacy.html/terms.html/eula.html: Add GDPR banner, data policy, consent checkboxes
- [ ] backend-python: New app/routers/consent.py + models.Consent: API/DB for cloud sync
- [ ] src/UI/MainWindow.xaml.cs: Show consent dialog on first run

## Integration & Test
- [ ] Update tests/DetectionTestSuite.cs: Exclusion tests, consent scenarios
- [ ] run_build.bat → check compile, WSC reg, consent flow
- [ ] Manual: Install, verify no Defender conflict, test exclusions, consents block features if denied

## Dependent Edits
RealTimeProtectionEngine.cs, MainWindow.xaml.cs, SecureConfigManager.cs (load consents/exclusions)

**Notes**: Edit files with exact diff matches. Update this TODO after each major step.
