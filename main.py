import sys
import os
sys.path.append(os.path.dirname(__file__))

from engine.core_engine import CoreEngine
from engine.detection_engine import DetectionEngine
from engine.quarantine_system import QuarantineSystem
from engine.realtime_protection import RealTimeProtection
from engine.auto_update import AutoUpdateSystem
from engine.process_monitor import ProcessMonitor
from engine.network_shield import NetworkShield
from engine.ransomware_shield import RansomwareShield
from engine.self_defense import SelfDefense
from engine.registry_protector import RegistryProtector
from engine.scan_modes import ScanModes
from engine.behavior_monitor import BehaviorMonitor
from engine.ransomware_protection import RansomwareProtection, FileIntegrityMonitor
from engine.network_protection import NetworkProtectionShield, ExploitProtection, WebProtection
from engine.system_stats import SystemStats
from engine.account_system import AccountSystem, get_account_system, RolePermissions
from engine.subscription_system import (
    SubscriptionSystem, get_subscription_system, SubscriptionPlan, 
    JWTAuth, PaymentSystem, SecurityFeatures
)
from ai.ml_detector import MLDetector
from ai.behavior_analyzer import BehaviorAnalyzer
from updates.update_manager import UpdateManager
from updates.rollback_manager import RollbackManager
from network.threat_feed import ThreatFeed
from logs.crash_reporter import install_crash_handler
from logs.threat_logger import ThreatLogger, get_threat_logger
from logs.industry_logger import IndustryLogger, get_logger as get_industry_logger, install_exception_handler


class AntivirusService:
    def __init__(self):
        # Install crash handler first
        install_crash_handler()
        
        # Industry-standard logger
        self.logger = get_industry_logger()
        install_exception_handler(self.logger)
        
        # Core components
        self.core_engine = CoreEngine()
        self.detection_engine = DetectionEngine()
        self.quarantine_system = QuarantineSystem()
        self.threat_logger = get_threat_logger()
        self.system_stats = SystemStats()
        
        # Protection modules
        self.process_monitor = ProcessMonitor()
        self.network_shield = NetworkShield()
        self.ransomware_shield = RansomwareShield()
        self.self_defense = SelfDefense()
        self.registry_protector = RegistryProtector()
        
        # AI/ML
        self.ml_detector = MLDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        
        # Updates & Cloud
        self.update_manager = UpdateManager()
        self.rollback_manager = RollbackManager()
        self.threat_feed = ThreatFeed()
        
        # Real-Time Protection & Scan Modes
        self.realtime_protection = RealTimeProtection(self.detection_engine, self.quarantine_system)
        self.scan_modes = ScanModes(self.detection_engine, self.quarantine_system, self.threat_logger)
        
        # Advanced Security Modules
        self.behavior_monitor = BehaviorMonitor(self.threat_logger)
        self.ransomware_protection = RansomwareProtection(self.threat_logger)
        self.file_integrity = FileIntegrityMonitor()
        self.network_protection = NetworkProtectionShield(self.threat_logger)
        self.exploit_protection = ExploitProtection(self.threat_logger)
        self.web_protection = WebProtection(self.threat_logger)
        
        # Account System
        self.account_system = get_account_system()
        self.current_session = None
        
        # Subscription System (JWT Auth, Payments, Plans)
        self.subscription_system = get_subscription_system()
        self.access_token = None
        self.refresh_token = None
        
    def start_all_services(self):
        self.logger.log_service_start("AntivirusService")
        print("[+] Starting SecureGuard Antivirus...")
        self.core_engine.start_realtime_protection()
        self.realtime_protection.start()
        self.process_monitor.start_monitoring()
        self.network_shield.start_monitoring()
        self.ransomware_shield.start_monitoring()
        self.self_defense.protect_process()
        self.registry_protector.protect_registry_keys()
        self.update_manager.start_auto_update()
        self.threat_feed.start_feed_updates()
        self.behavior_monitor.start_monitoring()
        self.ransomware_protection.start_protection()
        self.network_protection.start_monitoring()
        self.exploit_protection.start_protection()
        self.logger.log_service_start("AllProtectionLayers")
        print("[+] All protection layers active")
        
    def stop_all_services(self):
        self.logger.log_service_stop("AntivirusService")
        print("[-] Stopping SecureGuard Antivirus...")
        self.realtime_protection.stop()
        self.core_engine.stop()
        self.process_monitor.stop()
        self.network_shield.stop()
        self.ransomware_shield.stop()
        self.self_defense.stop()
        self.registry_protector.stop()
        if hasattr(self.behavior_monitor, 'stop'): self.behavior_monitor.stop()
        if hasattr(self.ransomware_protection, 'stop'): self.ransomware_protection.stop()
        if hasattr(self.network_protection, 'stop'): self.network_protection.stop()
        if hasattr(self.exploit_protection, 'stop'): self.exploit_protection.stop()
        self.update_manager.stop()
        self.threat_feed.stop()
        self.logger.log_service_stop("AllProtectionLayers")
        print("[-] All services stopped")
    
    # Scan Mode Methods
    def quick_scan(self, callback=None):
        self.logger.log_scan_start("quick", self.scan_modes.quick_scan_paths)
        result = self.scan_modes.quick_scan(callback)
        self.logger.log_scan_complete("quick", result.files_scanned, result.threats_found, result.duration)
        return result
    
    def full_scan(self, callback=None):
        self.logger.log_scan_start("full", ["C:\\"])
        result = self.scan_modes.full_scan(callback)
        self.logger.log_scan_complete("full", result.files_scanned, result.threats_found, result.duration)
        return result
    
    def custom_scan(self, paths, callback=None):
        self.logger.log_scan_start("custom", paths)
        result = self.scan_modes.custom_scan(paths, callback)
        self.logger.log_scan_complete("custom", result.files_scanned, result.threats_found, result.duration)
        return result
    
    def boot_scan(self, callback=None):
        self.logger.log_scan_start("boot", ["System32"])
        result = self.scan_modes.boot_scan(callback)
        self.logger.log_scan_complete("boot", result.files_scanned, result.threats_found, result.duration)
        return result
    
    # Threat Management
    def get_threat_history(self):
        return self.threat_logger.get_all_threats()
    
    def get_threat_stats(self):
        return self.threat_logger.get_threat_statistics()
    
    def filter_threats(self, **kwargs):
        return self.threat_logger.filter_threats(**kwargs)
    
    # Quarantine Management
    def get_quarantine(self):
        return self.quarantine_system.list_quarantined()
    
    def restore_quarantine(self, file_id):
        return self.quarantine_system.restore(file_id)
    
    def delete_quarantine(self, file_id):
        return self.quarantine_system.delete_permanent(file_id)
    
    # Updates & Logs
    def check_updates(self):
        self.logger.log_update_check("checking")
        if hasattr(self.update_manager, 'check_updates'):
            self.update_manager.check_updates()
    
    def get_logs(self, log_type="app", lines=100):
        return self.logger.get_recent_logs(log_type, lines)
    
    # Individual Account Methods
    def register(self, email, password, confirm_password, full_name, country, device_type, accept_terms=True, captcha_token="demo"):
        return self.account_system.register(email, password, confirm_password, full_name, country, device_type, accept_terms, captcha_token)
    
    def login(self, email, password):
        result = self.account_system.login(email, password)
        if result.get('success'):
            self.current_session = result.get('session_token')
        return result
    
    def logout(self):
        if self.current_session:
            result = self.account_system.logout(self.current_session)
            self.current_session = None
            return result
        return {'success': False, 'error': 'Not logged in'}
    
    def verify_email(self, email, code):
        return self.account_system.verify_email(email, code)
    
    def activate_license(self, license_key):
        if not self.current_session:
            return {'success': False, 'error': 'Not logged in'}
        return self.account_system.activate_license(self.current_session, license_key)
    
    def get_license_status(self):
        if not self.current_session:
            return {'success': False, 'error': 'Not logged in'}
        return self.account_system.get_license_status(self.current_session)
    
    def is_logged_in(self):
        return self.current_session is not None
    
    def get_current_user(self):
        if self.current_session:
            return self.account_system.validate_session(self.current_session)
        return None
    
    # Business Account Methods
    def register_business(self, company_name, company_email, admin_name, num_devices, country, industry, phone, password, confirm_password, accept_terms=True, captcha_token="demo"):
        return self.account_system.register_business(company_name, company_email, admin_name, num_devices, country, industry, phone, password, confirm_password, accept_terms, captcha_token)
    
    # Role-Based Permissions
    def check_permission(self, permission):
        if not self.current_session:
            return False
        return self.account_system.check_permission(self.current_session, permission)
    
    def get_permissions(self):
        if not self.current_session:
            return {'success': False, 'error': 'Not logged in'}
        return self.account_system.get_user_permissions(self.current_session)
    
    # User Management (Business)
    def add_user(self, new_email, new_password, new_full_name, role="user"):
        if not self.current_session:
            return {'success': False, 'error': 'Not logged in'}
        return self.account_system.add_user_to_company(self.current_session, new_email, new_password, new_full_name, role)
    
    def remove_user(self, user_email):
        if not self.current_session:
            return {'success': False, 'error': 'Not logged in'}
        return self.account_system.remove_user_from_company(self.current_session, user_email)
    
    def change_user_role(self, user_email, new_role):
        if not self.current_session:
            return {'success': False, 'error': 'Not logged in'}
        return self.account_system.change_user_role(self.current_session, user_email, new_role)
    
    # ===== Subscription System Methods (JWT Auth, Payments, Plans) =====
    
    def subscribe_register(self, email, password, plan="free"):
        return self.subscription_system.register_user(email, password, plan)
    
    def subscribe_login(self, email, password, ip="0.0.0.0"):
        result = self.subscription_system.login(email, password, ip)
        if result.get('success') and not result.get('requires_2fa'):
            self.access_token = result.get('access_token')
            self.refresh_token = result.get('refresh_token')
        return result
    
    def subscribe_logout(self):
        if self.access_token:
            result = self.subscription_system.logout(self.access_token)
            self.access_token = None
            self.refresh_token = None
            return result
        return {'success': False, 'error': 'Not logged in'}
    
    def refresh_session(self):
        if self.refresh_token:
            return self.subscription_system.refresh_token(self.refresh_token)
        return {'success': False, 'error': 'No refresh token'}
    
    def get_plans(self):
        return SubscriptionPlan.get_all_plans()
    
    def get_individual_plans(self):
        return SubscriptionPlan.get_individual_plans()
    
    def get_business_plans(self):
        return SubscriptionPlan.get_business_plans()
    
    def change_plan(self, user_id, plan):
        return self.subscription_system.change_plan(user_id, plan)
    
    def process_payment(self, user_id, plan, method, details):
        return self.subscription_system.process_payment(user_id, plan, method, details)
    
    def get_subscription(self, user_id):
        return self.subscription_system.get_subscription(user_id)
    
    def register_device(self, user_id, device_name, os_type="Windows"):
        return self.subscription_system.register_device(user_id, device_name, os_type)
    
    def get_user_devices(self, user_id):
        return self.subscription_system.get_devices(user_id)
    
    def block_device(self, user_id, device_id):
        return self.subscription_system.block_device(user_id, device_id)
    
    def create_company(self, user_id, company_name, plan="startup"):
        return self.subscription_system.create_company(user_id, company_name, plan)
    
    def get_user_dashboard(self, user_id):
        return self.subscription_system.get_user_dashboard(user_id)
    
    def get_business_dashboard(self, company_id):
        return self.subscription_system.get_business_dashboard(company_id)
    
    def enable_2fa(self, user_id):
        return self.subscription_system.enable_2fa(user_id)
    
    def verify_2fa(self, user_id, code):
        return self.subscription_system.verify_2fa(user_id, code)
    
    def get_login_history(self, user_id):
        return self.subscription_system.get_login_history(user_id)
    
    def force_logout_all(self, user_id):
        return self.subscription_system.force_logout(user_id)


if __name__ == "__main__":
    # Run console demo instead of GUI (avoids Tkinter/Tcl issues on some systems)
    print("=" * 70)
    print("SecureGuard Antivirus - Professional Security Suite")
    print("=" * 70)
    
    # Initialize service
    service = AntivirusService()
    
    # Start all protection services
    try:
        service.start_all_services()
        print("\n[✓] All security services started successfully!\n")
        
        # Run demonstration
        import demo
        
        # Show system status
        stats = service.system_stats.get_all_stats() if hasattr(service, 'system_stats') else {}
        
        print("\n" + "=" * 70)
        print("Demo Complete! SecureGuard is running with full protection.")
        print("=" * 70)
        
    except KeyboardInterrupt:
        pass

    service.stop_all_services()

    print("\n[✓] SecureGuard Antivirus closed.")
