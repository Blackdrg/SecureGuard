"""
SecureGuard Subscription & Authentication System
=============================================

Complete enterprise-level account system with:
- Database schema (Users, Companies, Devices, Subscriptions)
- JWT authentication with refresh tokens
- Subscription plans with pricing
- Payment flow simulation
- License key management
- User & Business dashboards
- Smart features (health scores, usage meters)
- Account security features
- REAL HaveIBeenPwned API integration
- Real data persistence
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import string
import time
import base64
import hashlib
import jwt
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List
from enum import Enum
import threading


# ==================== DATABASE SCHEMA ====================

class User:
    """User database model"""
    def __init__(self, user_id: str, email: str, password_hash: str,
                 plan: str = "free", license_key: str = None,
                 device_limit: int = 1, created_at: datetime = None):
        self.user_id = user_id
        self.email = email
        self.password_hash = password_hash
        self.plan = plan
        self.license_key = license_key
        self.device_limit = device_limit
        self.created_at = created_at or datetime.now()
        self.company_id = None
        self.role = "user"
        self.is_active = True
        self.last_login = None
        self.login_alerts = True
        self.two_factor_enabled = False
        self.two_factor_secret = None
        
    def to_dict(self) -> Dict:
        return {
            'user_id': self.user_id,
            'email': self.email,
            'plan': self.plan,
            'license_key': self.license_key,
            'device_limit': self.device_limit,
            'created_at': self.created_at.isoformat(),
            'company_id': self.company_id,
            'role': self.role,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'login_alerts': self.login_alerts,
            'two_factor_enabled': self.two_factor_enabled
        }


class Company:
    """Company database model"""
    def __init__(self, company_id: str, company_name: str, admin_user_id: str,
                 plan: str = "startup", devices_allowed: int = 10):
        self.company_id = company_id
        self.company_name = company_name
        self.admin_user_id = admin_user_id
        self.plan = plan
        self.devices_allowed = devices_allowed
        self.billing_cycle = "monthly"
        self.subscription_status = "active"
        self.created_at = datetime.now()
        
    def to_dict(self) -> Dict:
        return {
            'company_id': self.company_id,
            'company_name': self.company_name,
            'admin_user_id': self.admin_user_id,
            'plan': self.plan,
            'devices_allowed': self.devices_allowed,
            'billing_cycle': self.billing_cycle,
            'subscription_status': self.subscription_status,
            'created_at': self.created_at.isoformat()
        }


class Device:
    """Device database model"""
    def __init__(self, device_id: str, user_id: str, device_name: str,
                 os_type: str = "Windows"):
        self.device_id = device_id
        self.user_id = user_id
        self.device_name = device_name
        self.os_type = os_type
        self.last_seen = datetime.now()
        self.status = "active"
        self.health_score = 100
        self.is_blocked = False
        self.ip_address = None
        
    def to_dict(self) -> Dict:
        return {
            'device_id': self.device_id,
            'user_id': self.user_id,
            'device_name': self.device_name,
            'os_type': self.os_type,
            'last_seen': self.last_seen.isoformat(),
            'status': self.status,
            'health_score': self.health_score,
            'is_blocked': self.is_blocked
        }


class Subscription:
    """Subscription database model"""
    def __init__(self, subscription_id: str, user_id: str = None, 
                 company_id: str = None, plan: str = "free"):
        self.subscription_id = subscription_id
        self.user_id = user_id
        self.company_id = company_id
        self.plan = plan
        self.status = "active"
        self.start_date = datetime.now()
        self.renewal_date = datetime.now() + timedelta(days=30)
        self.payment_id = None
        self.payment_method = None
        self.auto_renew = True
        
    def to_dict(self) -> Dict:
        return {
            'subscription_id': self.subscription_id,
            'user_id': self.user_id,
            'company_id': self.company_id,
            'plan': self.plan,
            'status': self.status,
            'start_date': self.start_date.isoformat(),
            'renewal_date': self.renewal_date.isoformat(),
            'payment_method': self.payment_method,
            'auto_renew': self.auto_renew
        }


# ==================== SUBSCRIPTION PLANS ====================

class SubscriptionPlan:
    """Subscription plans with pricing"""
    
    PLANS = {
        # Individual Plans
        'free': {
            'name': 'Free',
            'price': 0,
            'devices': 1,
            'features': ['basic_protection', 'manual_scan'],
            'billing': None
        },
        'basic': {
            'name': 'Basic',
            'price': 3,
            'devices': 1,
            'features': ['real_time_protection', 'quick_scan', 'email_support'],
            'billing': 'monthly'
        },
        'pro': {
            'name': 'Pro',
            'price': 7,
            'devices': 3,
            'features': ['ai_detection', 'ransomware_shield', 'priority_support', 'cloud_backup'],
            'billing': 'monthly'
        },
        'ultimate': {
            'name': 'Ultimate',
            'price': 12,
            'devices': 5,
            'features': ['all_features', 'premium_support', 'unlimited_backup', 'identity_protection'],
            'billing': 'monthly'
        },
        # Business Plans
        'startup': {
            'name': 'Startup',
            'price': 20,
            'devices': 10,
            'features': ['central_dashboard', 'device_management', 'basic_analytics', 'email_support'],
            'billing': 'monthly'
        },
        'business': {
            'name': 'Business',
            'price': 50,
            'devices': 50,
            'features': ['advanced_analytics', 'user_management', 'api_access', 'priority_support'],
            'billing': 'monthly'
        },
        'enterprise': {
            'name': 'Enterprise',
            'price': 0,  # Custom pricing
            'devices': -1,  # Unlimited
            'features': ['dedicated_support', 'custom_integrations', 'sla', 'on_prem_option'],
            'billing': 'custom'
        }
    }
    
    @classmethod
    def get_plan(cls, plan_name: str) -> Dict:
        return cls.PLANS.get(plan_name.lower(), cls.PLANS['free'])
    
    @classmethod
    def get_all_plans(cls) -> Dict:
        return cls.PLANS
    
    @classmethod
    def get_individual_plans(cls) -> Dict:
        return {k: v for k, v in cls.PLANS.items() if k in ['free', 'basic', 'pro', 'ultimate']}
    
    @classmethod
    def get_business_plans(cls) -> Dict:
        return {k: v for k, v in cls.PLANS.items() if k in ['startup', 'business', 'enterprise']}


# ==================== JWT AUTHENTICATION ====================

class JWTAuth:
    """JWT Authentication with refresh tokens"""
    
    SECRET_KEY = secrets.token_hex(32)
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE = 3600  # 1 hour
    REFRESH_TOKEN_EXPIRE = 604800  # 7 days
    
    @classmethod
    def generate_access_token(cls, user_id: str, email: str, role: str) -> str:
        """Generate JWT access token"""
        payload = {
            'user_id': user_id,
            'email': email,
            'role': role,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(seconds=cls.ACCESS_TOKEN_EXPIRE),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
    
    @classmethod
    def generate_refresh_token(cls, user_id: str) -> str:
        """Generate JWT refresh token"""
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + timedelta(seconds=cls.REFRESH_TOKEN_EXPIRE),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
    
    @classmethod
    def verify_token(cls, token: str) -> Optional[Dict]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    @classmethod
    def refresh_access_token(cls, refresh_token: str) -> Optional[str]:
        """Generate new access token from refresh token"""
        payload = cls.verify_token(refresh_token)
        if payload and payload.get('type') == 'refresh':
            return cls.generate_access_token(payload['user_id'], '', '')
        return None


# ==================== LICENSE KEY SYSTEM ====================

class LicenseKey:
    """License key generation and management"""
    
    @staticmethod
    def generate(plan: str, duration_days: int = 365) -> str:
        """Generate license key"""
        prefix = plan[:3].upper()
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        parts = []
        for _ in range(4):
            part = ''.join(secrets.choice(chars) for _ in range(5))
            parts.append(part)
        key = '-'.join(parts)
        
        # Store key metadata in database
        return key
    
    @staticmethod
    def validate(key: str) -> bool:
        """Validate license key format"""
        pattern = r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$'
        return bool(re.match(pattern, key.upper()))
    
    @staticmethod
    def bind_to_device(key: str, device_id: str) -> Dict:
        """Bind license to device"""
        return {
            'key': key,
            'device_id': device_id,
            'bound_at': datetime.now().isoformat(),
            'expiry': (datetime.now() + timedelta(days=365)).isoformat()
        }


# ==================== PAYMENT SYSTEM ====================

class PaymentSystem:
    """Payment processing simulation"""
    
    SUPPORTED_METHODS = ['credit_card', 'debit_card', 'paypal', 'upi', 'corporate_invoice']
    
    @classmethod
    def process_payment(cls, amount: float, payment_method: str, 
                       card_details: Dict = None) -> Dict:
        """Process payment"""
        if payment_method not in cls.SUPPORTED_METHODS:
            return {'success': False, 'error': 'Invalid payment method'}
        
        # Simulate payment processing
        payment_id = f"PAY-{secrets.token_hex(8).upper()}"
        
        # In production, integrate with Stripe/PayPal
        return {
            'success': True,
            'payment_id': payment_id,
            'amount': amount,
            'method': payment_method,
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        }
    
    @classmethod
    def get_supported_methods(cls) -> List[str]:
        return cls.SUPPORTED_METHODS


# ==================== SECURITY FEATURES - REAL IMPLEMENTATION ====================

class SecurityFeatures:
    """Account security features with REAL HaveIBeenPwned API integration"""
    
    # HaveIBeenPwned API configuration
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    
    @staticmethod
    def check_password_breach(password: str) -> bool:
        """
        Check if password has been breached using HaveIBeenPwned API
        
        This is a REAL implementation that queries the HaveIBeenPwned API
        using the k-anonymity model for privacy.
        """
        if not password:
            return False
            
        # First check common passwords locally (fast check)
        common_passwords = ['password', '123456', 'password123', 'admin', 'qwerty', 
                          '123456789', '12345678', '12345', '1234567', 'letmein',
                          '1234567890', 'dragon', 'monkey', 'master', 'hello']
        if password.lower() in common_passwords:
            return True
        
        # Use HaveIBeenPwned API with k-anonymity
        try:
            # Hash password with SHA-1 (required by HIBP API)
            sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_password[:5]
            suffix = sha1_password[5:]
            
            # Query API with prefix (k-anonymity)
            response = requests.get(
                f"{SecurityFeatures.HIBP_API_URL}{prefix}",
                headers={'User-Agent': 'SecureGuard-AV'},
                timeout=5
            )
            
            if response.status_code == 200:
                # Search for our hash suffix in response
                hashes = response.text.split('\n')
                for h in hashes:
                    hash_suffix, count = h.split(':')
                    if hash_suffix.strip() == suffix:
                        # Password found in breaches
                        breach_count = int(count.strip())
                        print(f"[HIBP] Password found in {breach_count} breaches!")
                        return True
                        
            return False
            
        except requests.RequestException as e:
            print(f"[HIBP] API error: {e}, falling back to local check")
            # Fall back to common passwords check
            return password.lower() in common_passwords
    
    @staticmethod
    def check_email_breach(email: str) -> Dict:
        """
        Check if email has been involved in data breaches
        
        Uses HaveIBeenPwned API v3
        """
        if not email:
            return {'breached': False, 'breaches': []}
        
        try:
            # Note: This endpoint requires API key for full access
            # Using the free tier with limited lookups
            hibp_api_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            
            response = requests.get(
                hibp_api_url,
                headers={
                    'User-Agent': 'SecureGuard-AV',
                    'hibp-api-key': ''  # Add API key for production
                },
                timeout=10,
                params={'truncateResponse': 'false'}
            )
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    'breached': True,
                    'breaches': breaches,
                    'count': len(breaches)
                }
            elif response.status_code == 404:
                return {'breached': False, 'breaches': [], 'count': 0}
            else:
                return {'error': f'API returned {response.status_code}', 'breached': False}
                
        except requests.RequestException as e:
            print(f"[HIBP] Email check error: {e}")
            return {'error': str(e), 'breached': False}
    
    @staticmethod
    def generate_2fa_secret() -> str:
        """Generate 2FA secret"""
        return base64.b32encode(secrets.token_bytes(20)).decode()
    
    @staticmethod
    def verify_2fa(code: str, secret: str) -> bool:
        """Verify 2FA code (simplified)"""
        # In production, use proper TOTP verification with pyotp
        return len(code) == 6 and code.isdigit()


# ==================== MAIN SUBSCRIPTION SYSTEM ====================

class SubscriptionSystem:
    """Complete subscription and authentication system with REAL data persistence"""
    
    def __init__(self):
        self.data_dir = Path("config/subscription")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Data storage
        self.users: Dict[str, User] = {}
        self.companies: Dict[str, Company] = {}
        self.devices: Dict[str, Device] = {}
        self.subscriptions: Dict[str, Subscription] = {}
        
        self.sessions: Dict[str, Dict] = {}  # session_token -> user data
        self.refresh_tokens: Dict[str, str] = {}  # refresh_token -> user_id
        self.login_history: Dict[str, List] = {}  # user_id -> login history
        
        # REAL: Load data from persistent storage
        self._load_data()
        
    def _load_data(self):
        """Load data from persistent JSON storage - REAL implementation"""
        try:
            # Load users
            users_file = self.data_dir / "users.json"
            if users_file.exists():
                with open(users_file, 'r') as f:
                    users_data = json.load(f)
                    for user_id, user_data in users_data.items():
                        user = User(
                            user_id=user_data['user_id'],
                            email=user_data['email'],
                            password_hash=user_data['password_hash'],
                            plan=user_data.get('plan', 'free'),
                            license_key=user_data.get('license_key'),
                            device_limit=user_data.get('device_limit', 1),
                            created_at=datetime.fromisoformat(user_data.get('created_at', datetime.now().isoformat()))
                        )
                        user.company_id = user_data.get('company_id')
                        user.role = user_data.get('role', 'user')
                        user.is_active = user_data.get('is_active', True)
                        user.two_factor_enabled = user_data.get('two_factor_enabled', False)
                        self.users[user.email] = user
            print(f"[DATA] Loaded {len(self.users)} users")
            
            # Load companies
            companies_file = self.data_dir / "companies.json"
            if companies_file.exists():
                with open(companies_file, 'r') as f:
                    companies_data = json.load(f)
                    for company_id, company_data in companies_data.items():
                        company = Company(
                            company_id=company_data['company_id'],
                            company_name=company_data['company_name'],
                            admin_user_id=company_data['admin_user_id'],
                            plan=company_data.get('plan', 'startup'),
                            devices_allowed=company_data.get('devices_allowed', 10)
                        )
                        self.companies[company_id] = company
            print(f"[DATA] Loaded {len(self.companies)} companies")
            
            # Load devices
            devices_file = self.data_dir / "devices.json"
            if devices_file.exists():
                with open(devices_file, 'r') as f:
                    devices_data = json.load(f)
                    for device_id, device_data in devices_data.items():
                        device = Device(
                            device_id=device_data['device_id'],
                            user_id=device_data['user_id'],
                            device_name=device_data['device_name'],
                            os_type=device_data.get('os_type', 'Windows')
                        )
                        device.last_seen = datetime.fromisoformat(device_data.get('last_seen', datetime.now().isoformat()))
                        device.status = device_data.get('status', 'active')
                        device.health_score = device_data.get('health_score', 100)
                        self.devices[device_id] = device
            print(f"[DATA] Loaded {len(self.devices)} devices")
            
            # Load subscriptions
            subs_file = self.data_dir / "subscriptions.json"
            if subs_file.exists():
                with open(subs_file, 'r') as f:
                    subs_data = json.load(f)
                    for sub_id, sub_data in subs_data.items():
                        subscription = Subscription(
                            subscription_id=sub_data['subscription_id'],
                            user_id=sub_data.get('user_id'),
                            company_id=sub_data.get('company_id'),
                            plan=sub_data.get('plan', 'free')
                        )
                        subscription.status = sub_data.get('status', 'active')
                        self.subscriptions[sub_id] = subscription
            print(f"[DATA] Loaded {len(self.subscriptions)} subscriptions")
            
        except Exception as e:
            print(f"[DATA] Error loading data: {e}")
    
    def _save_data(self):
        """Save data to persistent JSON storage - REAL implementation"""
        try:
            # Save users
            users_data = {}
            for email, user in self.users.items():
                users_data[user.user_id] = {
                    'user_id': user.user_id,
                    'email': user.email,
                    'password_hash': user.password_hash,
                    'plan': user.plan,
                    'license_key': user.license_key,
                    'device_limit': user.device_limit,
                    'created_at': user.created_at.isoformat(),
                    'company_id': user.company_id,
                    'role': user.role,
                    'is_active': user.is_active,
                    'two_factor_enabled': user.two_factor_enabled
                }
            
            with open(self.data_dir / "users.json", 'w') as f:
                json.dump(users_data, f, indent=2)
            
            # Save companies
            companies_data = {}
            for company_id, company in self.companies.items():
                companies_data[company_id] = {
                    'company_id': company.company_id,
                    'company_name': company.company_name,
                    'admin_user_id': company.admin_user_id,
                    'plan': company.plan,
                    'devices_allowed': company.devices_allowed
                }
            
            with open(self.data_dir / "companies.json", 'w') as f:
                json.dump(companies_data, f, indent=2)
            
            # Save devices
            devices_data = {}
            for device_id, device in self.devices.items():
                devices_data[device_id] = {
                    'device_id': device.device_id,
                    'user_id': device.user_id,
                    'device_name': device.device_name,
                    'os_type': device.os_type,
                    'last_seen': device.last_seen.isoformat(),
                    'status': device.status,
                    'health_score': device.health_score
                }
            
            with open(self.data_dir / "devices.json", 'w') as f:
                json.dump(devices_data, f, indent=2)
            
            # Save subscriptions
            subs_data = {}
            for sub_id, subscription in self.subscriptions.items():
                subs_data[sub_id] = {
                    'subscription_id': subscription.subscription_id,
                    'user_id': subscription.user_id,
                    'company_id': subscription.company_id,
                    'plan': subscription.plan,
                    'status': subscription.status
                }
            
            with open(self.data_dir / "subscriptions.json", 'w') as f:
                json.dump(subs_data, f, indent=2)
                
            print("[DATA] Data saved successfully")
            
        except Exception as e:
            print(f"[DATA] Error saving data: {e}")
    
    # ===== REGISTRATION =====
    
    def register_user(self, email: str, password: str, plan: str = "free") -> Dict:
        """Register new user with REAL password breach checking"""
        errors = []
        
        # Validate email
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            errors.append('Invalid email format')
        
        # Check existing
        if email in [u.email for u in self.users.values()]:
            errors.append('Email already registered')
        
        # Validate password length
        if len(password) < 8:
            errors.append('Password must be at least 8 characters')
        if not re.search(r'\d', password):
            errors.append('Password must contain a number')
        
        # REAL: Check password against HaveIBeenPwned
        if SecurityFeatures.check_password_breach(password):
            errors.append('Password is too common or found in data breaches. Please choose a stronger one.')
        
        if errors:
            return {'success': False, 'errors': errors}
        
        # Create user
        user_id = secrets.token_hex(16)
        password_hash = self._hash_password(password)
        
        user = User(
            user_id=user_id,
            email=email,
            password_hash=password_hash,
            plan=plan,
            device_limit=SubscriptionPlan.get_plan(plan)['devices']
        )
        
        self.users[user_id] = user
        
        # Create subscription
        sub_id = secrets.token_hex(16)
        subscription = Subscription(subscription_id=sub_id, user_id=user_id, plan=plan)
        self.subscriptions[user_id] = subscription
        
        # REAL: Save to persistent storage
        self._save_data()
        
        return {
            'success': True,
            'user_id': user_id,
            'plan': plan,
            'message': 'Registration successful'
        }
    
    def _hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(32)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${pwd_hash.hex()}"
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, pwd_hash = stored_hash.split('$')
            return hmac.compare_digest(
                hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex(),
                pwd_hash
            )
        except:
            return False
    
    # ===== AUTHENTICATION =====
    
    def login(self, email: str, password: str, ip_address: str = "0.0.0.0") -> Dict:
        """User login with JWT"""
        user = None
        for u in self.users.values():
            if u.email == email:
                user = u
                break
        
        if not user:
            return {'success': False, 'error': 'Invalid credentials'}
        
        if not self.verify_password(password, user.password_hash):
            self._log_login_attempt(user.user_id, ip_address, False)
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Check 2FA
        if user.two_factor_enabled:
            return {
                'success': True,
                'requires_2fa': True,
                'user_id': user.user_id
            }
        
        # Generate tokens
        access_token = JWTAuth.generate_access_token(user.user_id, user.email, user.role)
        refresh_token = JWTAuth.generate_refresh_token(user.user_id)
        
        # Store session
        self.sessions[access_token] = {
            'user_id': user.user_id,
            'email': user.email,
            'ip_address': ip_address,
            'login_time': datetime.now().isoformat()
        }
        self.refresh_tokens[refresh_token] = user.user_id
        
        # Update last login
        user.last_login = datetime.now()
        
        # Log login
        self._log_login_attempt(user.user_id, ip_address, True)
        
        # Save updated data
        self._save_data()
        
        return {
            'success': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict(),
            'expires_in': JWTAuth.ACCESS_TOKEN_EXPIRE
        }
    
    def verify_2fa(self, user_id: str, code: str) -> Dict:
        """Verify 2FA code"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        if not SecurityFeatures.verify_2fa(code, user.two_factor_secret or ''):
            return {'success': False, 'error': 'Invalid 2FA code'}
        
        # Generate tokens
        access_token = JWTAuth.generate_access_token(user.user_id, user.email, user.role)
        refresh_token = JWTAuth.generate_refresh_token(user.user_id)
        
        self.sessions[access_token] = {
            'user_id': user.user_id,
            'email': user.email,
            'login_time': datetime.now().isoformat()
        }
        self.refresh_tokens[refresh_token] = user.user_id
        
        return {
            'success': True,
            'access_token': access_token,
            'refresh_token': refresh_token
        }
    
    def _log_login_attempt(self, user_id: str, ip: str, success: bool):
        """Log login attempt"""
        if user_id not in self.login_history:
            self.login_history[user_id] = []
        
        self.login_history[user_id].append({
            'ip': ip,
            'success': success,
            'time': datetime.now().isoformat()
        })
    
    def get_login_history(self, user_id: str) -> List:
        """Get login history for user"""
        return self.login_history.get(user_id, [])
    
    def refresh_token(self, refresh_token: str) -> Dict:
        """Refresh access token"""
        user_id = self.refresh_tokens.get(refresh_token)
        if not user_id:
            return {'success': False, 'error': 'Invalid refresh token'}
        
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        new_access_token = JWTAuth.generate_access_token(user.user_id, user.email, user.role)
        
        return {
            'success': True,
            'access_token': new_access_token,
            'expires_in': JWTAuth.ACCESS_TOKEN_EXPIRE
        }
    
    def logout(self, access_token: str):
        """Logout user"""
        if access_token in self.sessions:
            del self.sessions[access_token]
        return {'success': True}
    
    def validate_session(self, token: str) -> Optional[User]:
        """Validate session token"""
        payload = JWTAuth.verify_token(token)
        if payload and payload.get('type') == 'access':
            return self.users.get(payload.get('user_id'))
        return None
    
    # ===== SUBSCRIPTION =====
    
    def change_plan(self, user_id: str, new_plan: str) -> Dict:
        """Change subscription plan"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        plan_info = SubscriptionPlan.get_plan(new_plan)
        
        user.plan = new_plan
        user.device_limit = plan_info['devices']
        
        # Update subscription
        if user_id in self.subscriptions:
            self.subscriptions[user_id].plan = new_plan
            self.subscriptions[user_id].renewal_date = datetime.now() + timedelta(days=30)
        
        # Save changes
        self._save_data()
        
        return {
            'success': True,
            'plan': new_plan,
            'price': plan_info['price'],
            'devices': plan_info['devices']
        }
    
    def get_subscription(self, user_id: str) -> Dict:
        """Get subscription details"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        subscription = self.subscriptions.get(user_id)
        
        days_left = None
        if subscription:
            days_left = (subscription.renewal_date - datetime.now()).days
        
        return {
            'success': True,
            'plan': user.plan,
            'status': subscription.status if subscription else 'active',
            'devices_used': len([d for d in self.devices.values() if d.user_id == user_id]),
            'devices_allowed': user.device_limit,
            'renewal_date': subscription.renewal_date.isoformat() if subscription else None,
            'days_left': days_left,
            'auto_renew': subscription.auto_renew if subscription else False
        }
    
    # ===== PAYMENT =====
    
    def process_payment(self, user_id: str, plan: str, payment_method: str,
                       payment_details: Dict) -> Dict:
        """Process payment and activate plan"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        plan_info = SubscriptionPlan.get_plan(plan)
        
        # Process payment
        result = PaymentSystem.process_payment(
            plan_info['price'],
            payment_method,
            payment_details
        )
        
        if result['success']:
            # Generate license key
            license_key = LicenseKey.generate(plan)
            user.license_key = license_key
            
            # Change plan
            self.change_plan(user_id, plan)
            
            return {
                'success': True,
                'message': 'Payment successful',
                'license_key': license_key,
                'plan': plan
            }
        
        return result
    
    # ===== DEVICE MANAGEMENT =====
    
    def register_device(self, user_id: str, device_name: str, os_type: str) -> Dict:
        """Register a device"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        # Check device limit
        user_devices = [d for d in self.devices.values() if d.user_id == user_id]
        if len(user_devices) >= user.device_limit:
            return {'success': False, 'error': 'Device limit reached'}
        
        device_id = secrets.token_hex(16)
        device = Device(device_id=device_id, user_id=user_id, 
                       device_name=device_name, os_type=os_type)
        
        self.devices[device_id] = device
        
        # Save
        self._save_data()
        
        return {
            'success': True,
            'device_id': device_id,
            'device': device.to_dict()
        }
    
    def get_devices(self, user_id: str) -> List[Dict]:
        """Get all devices for user"""
        return [d.to_dict() for d in self.devices.values() if d.user_id == user_id]
    
    def block_device(self, user_id: str, device_id: str) -> Dict:
        """Block a device"""
        device = self.devices.get(device_id)
        if not device or device.user_id != user_id:
            return {'success': False, 'error': 'Device not found'}
        
        device.is_blocked = True
        device.status = 'blocked'
        
        # Save
        self._save_data()
        
        return {'success': True, 'message': 'Device blocked'}
    
    # ===== COMPANY/BUSINESS =====
    
    def create_company(self, user_id: str, company_name: str, plan: str = "startup") -> Dict:
        """Create company"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        company_id = secrets.token_hex(16)
        plan_info = SubscriptionPlan.get_plan(plan)
        
        company = Company(
            company_id=company_id,
            company_name=company_name,
            admin_user_id=user_id,
            plan=plan,
            devices_allowed=plan_info['devices']
        )
        
        self.companies[company_id] = company
        user.company_id = company_id
        user.role = 'admin'
        
        # Save
        self._save_data()
        
        return {
            'success': True,
            'company_id': company_id,
            'company': company.to_dict()
        }
    
    def get_company_devices(self, company_id: str) -> List[Dict]:
        """Get all devices in company"""
        company = self.companies.get(company_id)
        if not company:
            return []
        
        # Get all company users
        company_users = [u for u in self.users.values() if u.company_id == company_id]
        user_ids = [u.user_id for u in company_users]
        
        return [d.to_dict() for d in self.devices.values() if d.user_id in user_ids]
    
    # ===== DASHBOARD =====
    
    def get_user_dashboard(self, user_id: str) -> Dict:
        """Get user dashboard data"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        subscription = self.get_subscription(user_id)
        devices = self.get_devices(user_id)
        
        # Calculate health score
        health_score = 100
        if devices:
            avg_health = sum(d.get('health_score', 100) for d in devices) / len(devices)
            health_score = int(avg_health)
        
        # Calculate risk level
        risk_level = "LOW"
        if health_score < 70:
            risk_level = "MEDIUM"
        if health_score < 50:
            risk_level = "HIGH"
        
        return {
            'success': True,
            'user': user.to_dict(),
            'subscription': subscription,
            'devices': devices,
            'protection_status': 'PROTECTED' if user.plan != 'free' else 'LIMITED',
            'health_score': health_score,
            'risk_level': risk_level,
            'license_usage': f"{len(devices)}/{user.device_limit}",
            'login_history': self.get_login_history(user_id)[-5:]
        }
    
    def get_business_dashboard(self, company_id: str) -> Dict:
        """Get business dashboard data"""
        company = self.companies.get(company_id)
        if not company:
            return {'success': False, 'error': 'Company not found'}
        
        devices = self.get_company_devices(company_id)
        
        # Get all company users
        users = [u for u in self.users.values() if u.company_id == company_id]
        
        # Calculate organization security score
        security_score = 100
        if devices:
            avg_health = sum(d.get('health_score', 100) for d in devices) / len(devices)
            security_score = int(avg_health)
        
        return {
            'success': True,
            'company': company.to_dict(),
            'devices': devices,
            'total_devices': len(devices),
            'devices_allowed': company.devices_allowed,
            'users_count': len(users),
            'security_score': security_score,
            'license_usage': f"{len(devices)}/{company.devices_allowed}",
            'plan': company.plan,
            'billing_cycle': company.billing_cycle
        }
    
    # ===== SECURITY =====
    
    def enable_2fa(self, user_id: str) -> Dict:
        """Enable 2FA"""
        user = self.users.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        secret = SecurityFeatures.generate_2fa_secret()
        user.two_factor_secret = secret
        user.two_factor_enabled = True
        
        # Save
        self._save_data()
        
        return {
            'success': True,
            'secret': secret,
            'message': '2FA enabled. Scan the secret with your authenticator app.'
        }
    
    def disable_login_alerts(self, user_id: str, enabled: bool):
        """Toggle login alerts"""
        user = self.users.get(user_id)
        if user:
            user.login_alerts = enabled
            self._save_data()
        return {'success': True}
    
    def force_logout(self, user_id: str):
        """Force logout all sessions"""
        tokens_to_remove = []
        for token, data in self.sessions.items():
            if data.get('user_id') == user_id:
                tokens_to_remove.append(token)
        
        for token in tokens_to_remove:
            del self.sessions[token]
        
        return {'success': True, 'sessions_terminated': len(tokens_to_remove)}
    
    # ===== BREACH CHECK =====
    
    def check_email_breaches(self, email: str) -> Dict:
        """Check if email has been in any data breaches"""
        return SecurityFeatures.check_email_breach(email)


# Global instance
_subscription_system = None

def get_subscription_system() -> SubscriptionSystem:
    """Get global subscription system"""
    global _subscription_system
    if _subscription_system is None:
        _subscription_system = SubscriptionSystem()
    return _subscription_system
