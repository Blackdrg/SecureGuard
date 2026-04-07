using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;
using SecureGuard.Core;

namespace SecureGuard.Backend.API
{
    /// <summary>
    /// Authentication Controller with secure password hashing
    /// </summary>
    public class AuthController
    {
        private readonly Dictionary<string, User> _users = new();
        
        // In production, store this securely - never in code!
        // For demo purposes only - in production use environment variables or secure key vault
        private static readonly string SecretKey = Convert.ToBase64String(
            SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(
                Environment.MachineName + "SecureGuard2024SecureKey!")));
        
        // Rate limiting
        private readonly Dictionary<string, (int attempts, DateTime lockoutUntil)> _loginAttempts = new();
        private const int MaxLoginAttempts = 5;
        private const int LockoutMinutes = 15;
        
        public AuthController()
        {
            // Add demo user
            var demoUser = new User
            {
                Email = "demo@secureguard.com",
                PasswordHash = HashPassword("demo123"),
                Name = "Demo User",
                CreatedAt = DateTime.UtcNow,
                Plan = "Free",
                Devices = new List<Device>()
            };
            _users[demoUser.Email] = demoUser;
        }

        public AuthResponse Register(RegisterRequest request)
        {
            // Input validation
            if (string.IsNullOrWhiteSpace(request.Email))
                return new AuthResponse { Success = false, Message = "Email is required" };
            
            if (!IsValidEmail(request.Email))
                return new AuthResponse { Success = false, Message = "Invalid email format" };
            
            if (string.IsNullOrWhiteSpace(request.Password))
                return new AuthResponse { Success = false, Message = "Password is required" };
            
            if (request.Password.Length < 8)
                return new AuthResponse { Success = false, Message = "Password must be at least 8 characters" };
            
            if (!IsStrongPassword(request.Password))
                return new AuthResponse { Success = false, Message = "Password must contain uppercase, lowercase, and numbers" };

            if (_users.ContainsKey(request.Email.ToLower()))
                return new AuthResponse { Success = false, Message = "Email already registered" };
            
            var user = new User
            {
                Email = request.Email.ToLower(),
                PasswordHash = HashPassword(request.Password),
                Name = request.Name ?? "User",
                CreatedAt = DateTime.UtcNow,
                Plan = "Free",
                Devices = new List<Device>()
            };
            
            _users[user.Email] = user;
            var token = GenerateToken(user);
            
            Core.Logger.Log("Info", $"User registered: {user.Email}");
            
            return new AuthResponse 
            { 
                Success = true, 
                Token = token,
                User = new UserInfo { Email = user.Email, Name = user.Name, Plan = user.Plan }
            };
        }
        
        public AuthResponse Login(LoginRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                return new AuthResponse { Success = false, Message = "Email and password are required" };
            
            // Check rate limiting
            var ip = request.Email; // In production, use actual IP
            if (IsRateLimited(ip))
            {
                Core.Logger.Log("Warning", $"Login attempt blocked due to too many attempts: {request.Email}");
                return new AuthResponse { Success = false, Message = $"Too many login attempts. Please try again in {LockoutMinutes} minutes." };
            }
            
            var email = request.Email.ToLower();
            if (!_users.TryGetValue(email, out var user))
            {
                RecordFailedAttempt(ip);
                return new AuthResponse { Success = false, Message = "Invalid credentials" };
            }
            
            if (!VerifyPassword(request.Password, user.PasswordHash))
            {
                RecordFailedAttempt(ip);
                Core.Logger.Log("Warning", $"Failed login attempt for: {email}");
                return new AuthResponse { Success = false, Message = "Invalid credentials" };
            }
            
            // Clear failed attempts on success
            _loginAttempts.Remove(ip);
            
            var token = GenerateToken(user);
            Core.Logger.Log("Info", $"User logged in: {email}");
            
            return new AuthResponse 
            { 
                Success = true, 
                Token = token,
                User = new UserInfo { Email = user.Email, Name = user.Name, Plan = user.Plan }
            };
        }
        
        public bool ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(SecretKey);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero,
                    ValidateLifetime = true
                }, out _);
                return true;
            }
            catch { return false; }
        }
        
        public string? GetUserFromToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadJwtToken(token);
                return jwtToken?.Claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            }
            catch { return null; }
        }
        
        private string GenerateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(SecretKey);
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.Name),
                    new Claim(ClaimTypes.Role, user.Plan),
                    new Claim("user_id", user.Email) // Add identifier
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature
                )
            };
            
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        
        /// <summary>
        /// Hashes password using PBKDF2 with salt
        /// </summary>
        private string HashPassword(string password)
        {
            // Generate salt
            var salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            
            // Hash password with PBKDF2
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                var hash = pbkdf2.GetBytes(32);
                
                // Combine salt + hash
                var result = new byte[salt.Length + hash.Length];
                Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                Buffer.BlockCopy(hash, 0, result, salt.Length, hash.Length);
                
                return Convert.ToBase64String(result);
            }
        }
        
        /// <summary>
        /// Verifies password against stored hash
        /// </summary>
        private bool VerifyPassword(string password, string storedHash)
        {
            try
            {
                var hashBytes = Convert.FromBase64String(storedHash);
                
                // Extract salt (first 16 bytes)
                var salt = new byte[16];
                Buffer.BlockCopy(hashBytes, 0, salt, 0, 16);
                
                // Extract stored hash
                var storedHashValue = new byte[32];
                Buffer.BlockCopy(hashBytes, 16, storedHashValue, 0, 32);
                
                // Hash input password with same salt
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
                {
                    var computedHash = pbkdf2.GetBytes(32);
                    
                    // Compare hashes
                    return CryptographicOperations.FixedTimeEquals(computedHash, storedHashValue);
                }
            }
            catch
            {
                return false;
            }
        }
        
        private bool IsValidEmail(string email)
        {
            try
            {
                var regex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
                return regex.IsMatch(email);
            }
            catch { return false; }
        }
        
        private bool IsStrongPassword(string password)
        {
            // At least 8 chars, 1 uppercase, 1 lowercase, 1 number
            var hasUpper = password.Any(char.IsUpper);
            var hasLower = password.Any(char.IsLower);
            var hasDigit = password.Any(char.IsDigit);
            
            return hasUpper && hasLower && hasDigit;
        }
        
        private bool IsRateLimited(string identifier)
        {
            if (_loginAttempts.TryGetValue(identifier, out var attemptInfo))
            {
                if (attemptInfo.lockoutUntil > DateTime.UtcNow)
                    return true;
                
                if (attemptInfo.attempts >= MaxLoginAttempts)
                {
                    _loginAttempts[identifier] = (attemptInfo.attempts, DateTime.UtcNow.AddMinutes(LockoutMinutes));
                    return true;
                }
            }
            return false;
        }
        
        private void RecordFailedAttempt(string identifier)
        {
            if (_loginAttempts.TryGetValue(identifier, out var attemptInfo))
            {
                _loginAttempts[identifier] = (attemptInfo.attempts + 1, attemptInfo.lockoutUntil);
            }
            else
            {
                _loginAttempts[identifier] = (1, DateTime.MinValue);
            }
        }
    }
    
    public class RegisterRequest 
    { 
        public string Email { get; set; } = ""; 
        public string Password { get; set; } = ""; 
        public string Name { get; set; } = ""; 
    }
    
    public class LoginRequest 
    { 
        public string Email { get; set; } = ""; 
        public string Password { get; set; } = ""; 
    }
    
    public class AuthResponse 
    { 
        public bool Success { get; set; } 
        public string? Token { get; set; } 
        public string? Message { get; set; } 
        public UserInfo? User { get; set; } 
    }
    
    public class UserInfo 
    { 
        public string Email { get; set; } = ""; 
        public string Name { get; set; } = ""; 
        public string Plan { get; set; } = ""; 
    }
    
    public class User
    {
        public string Email { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string Name { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public string Plan { get; set; } = "";
        public List<Device> Devices { get; set; } = new();
        public DateTime? PlanExpiry { get; set; }
    }
    
    public class Device
    {
        public string DeviceId { get; set; } = "";
        public string DeviceName { get; set; } = "";
        public string OS { get; set; } = "";
        public DateTime LastSeen { get; set; }
        public string Status { get; set; } = "Protected";
    }
}
</parameter>
</create_file>
