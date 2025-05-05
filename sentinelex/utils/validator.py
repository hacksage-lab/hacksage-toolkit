import re
import ipaddress
import dns.resolver
from urllib.parse import urlparse
import socket
import html
from typing import Union, Optional, Tuple, List
import logging

class InputValidator:
    """
    Comprehensive input validation and sanitization for security applications.
    Includes both validation checks and sanitization methods.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        
        # Common regex patterns
        self._patterns = {
            'domain': r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'md5_hash': r'^[a-f0-9]{32}$',
            'sha256_hash': r'^[a-f0-9]{64}$',
            'credit_card': r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$',
            'ssn': r'^\d{3}-\d{2}-\d{4}$',
            'phone': r'^\+?[\d\s\-\(\)]{7,}$'
        }
        
        # Dangerous patterns to detect injection attempts
        self._injection_patterns = {
            'sql_injection': r'(\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|EXEC|XP_)\b|\-\-|\/\*|\*\/|\b(OR\s+\d+\s*=\s*\d+)\b)',
            'xss': r'(<script|javascript:|on\w+\s*=|&#|\b(alert|prompt|confirm)\()',
            'command_injection': r'[;&|\`]\s*\b(rm|sh|bash|cmd|powershell|wget|curl)\b'
        }
        
        # Maximum lengths for various input types
        self._max_lengths = {
            'domain': 253,
            'email': 254,
            'ip_address': 45,  # IPv6 max length
            'url': 2048,
            'username': 32,
            'password': 128
        }

    def validate_domain(self, domain: str, resolve_dns: bool = False) -> Tuple[bool, str]:
        """
        Validate a domain name with optional DNS resolution check.
        
        Args:
            domain: Domain name to validate
            resolve_dns: Whether to perform DNS resolution check
            
        Returns:
            Tuple of (is_valid, message)
        """
        domain = domain.lower().strip()
        
        # Check length
        if len(domain) > self._max_lengths['domain']:
            return False, f"Domain exceeds maximum length of {self._max_lengths['domain']} characters"
            
        # Check basic format
        if not re.match(self._patterns['domain'], domain):
            return False, "Invalid domain format"
            
        # Check for injection attempts
        if self._check_injection(domain):
            return False, "Domain contains potentially dangerous characters"
            
        # Optional DNS resolution
        if resolve_dns:
            try:
                dns.resolver.resolve(domain, 'A')
            except dns.resolver.NXDOMAIN:
                return False, "Domain does not exist (NXDOMAIN)"
            except dns.resolver.NoAnswer:
                return False, "Domain has no A records"
            except Exception as e:
                return False, f"DNS resolution failed: {str(e)}"
                
        return True, "Valid domain"

    def validate_ip(self, ip: str, check_public: bool = False) -> Tuple[bool, str]:
        """
        Validate an IP address (v4 or v6).
        
        Args:
            ip: IP address to validate
            check_public: Whether to verify the IP is public
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            
            if check_public:
                if ip_obj.is_private:
                    return False, "Private IP addresses are not allowed"
                if ip_obj.is_loopback:
                    return False, "Loopback addresses are not allowed"
                if ip_obj.is_multicast:
                    return False, "Multicast addresses are not allowed"
                if ip_obj.is_reserved:
                    return False, "Reserved IP addresses are not allowed"
                if ip_obj.is_unspecified:
                    return False, "Unspecified IP addresses are not allowed"
                    
            return True, "Valid IP address"
        except ValueError:
            return False, "Invalid IP address format"

    def validate_url(self, url: str, allowed_schemes: List[str] = ['http', 'https']) -> Tuple[bool, str]:
        """
        Validate a URL with configurable allowed schemes.
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed URL schemes
            
        Returns:
            Tuple of (is_valid, message)
        """
        if len(url) > self._max_lengths['url']:
            return False, f"URL exceeds maximum length of {self._max_lengths['url']} characters"
            
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in allowed_schemes:
                return False, f"URL scheme must be one of: {', '.join(allowed_schemes)}"
                
            # Validate domain or IP
            if parsed.hostname:
                if self._is_ip(parsed.hostname):
                    valid, msg = self.validate_ip(parsed.hostname)
                else:
                    valid, msg = self.validate_domain(parsed.hostname)
                    
                if not valid:
                    return False, f"Invalid host in URL: {msg}"
            else:
                return False, "URL must contain a host"
                
            # Check for injection patterns
            if self._check_injection(url):
                return False, "URL contains potentially dangerous characters"
                
            return True, "Valid URL"
        except ValueError:
            return False, "Invalid URL format"

    def sanitize_input(self, input_str: str, input_type: str = 'text') -> str:
        """
        Sanitize input based on its type.
        
        Args:
            input_str: Input string to sanitize
            input_type: Type of input ('text', 'html', 'sql', 'command')
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_str, str):
            return ''
            
        input_str = input_str.strip()
        
        if input_type == 'html':
            # Escape HTML special characters
            return html.escape(input_str)
        elif input_type == 'sql':
            # Basic SQL injection protection (parameterized queries should still be used)
            return re.sub(r'[\'\";]', '', input_str)
        elif input_type == 'command':
            # Remove command injection characters
            return re.sub(r'[;&|`$]', '', input_str)
        else:
            # Default: remove control characters except basic whitespace
            return re.sub(r'[\x00-\x1F\x7F]', '', input_str)

    def validate_credentials(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Validate username and password according to security best practices.
        
        Args:
            username: Username to validate
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Validate username
        if len(username) < 4:
            return False, "Username must be at least 4 characters"
        if len(username) > self._max_lengths['username']:
            return False, f"Username exceeds maximum length of {self._max_lengths['username']} characters"
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
            return False, "Username contains invalid characters"
            
        # Validate password
        if len(password) < 12:
            return False, "Password must be at least 12 characters"
        if len(password) > self._max_lengths['password']:
            return False, f"Password exceeds maximum length of {self._max_lengths['password']} characters"
            
        # Password complexity checks
        complexity_errors = []
        if not re.search(r'[A-Z]', password):
            complexity_errors.append("uppercase letter")
        if not re.search(r'[a-z]', password):
            complexity_errors.append("lowercase letter")
        if not re.search(r'[0-9]', password):
            complexity_errors.append("digit")
        if not re.search(r'[^A-Za-z0-9]', password):
            complexity_errors.append("special character")
            
        if complexity_errors:
            return False, f"Password must contain at least one {', '.join(complexity_errors)}"
            
        return True, "Valid credentials"

    def validate_port(self, port: Union[str, int]) -> Tuple[bool, str]:
        """
        Validate a network port number.
        
        Args:
            port: Port number to validate (as string or int)
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            port_num = int(port)
            if 1 <= port_num <= 65535:
                return True, "Valid port number"
            return False, "Port number must be between 1 and 65535"
        except ValueError:
            return False, "Port must be a numeric value"

    def detect_injection(self, input_str: str) -> dict:
        """
        Detect potential injection attempts in input.
        
        Args:
            input_str: Input string to analyze
            
        Returns:
            Dictionary of detected injection types with details
        """
        results = {}
        
        for injection_type, pattern in self._injection_patterns.items():
            matches = re.finditer(pattern, input_str, re.IGNORECASE)
            if matches:
                results[injection_type] = [m.group() for m in matches]
                
        return results

    def _check_injection(self, input_str: str) -> bool:
        """Internal method to check for injection patterns."""
        return any(re.search(pattern, input_str, re.IGNORECASE) 
                  for pattern in self._injection_patterns.values())

    def _is_ip(self, host: str) -> bool:
        """Check if a host string is an IP address."""
        try:
            ipaddress.ip_address(host.strip())
            return True
        except ValueError:
            return False

    def validate_file_path(self, path: str, allowed_dirs: List[str] = None) -> Tuple[bool, str]:
        """
        Validate a file path to prevent directory traversal.
        
        Args:
            path: File path to validate
            allowed_dirs: List of allowed base directories (None for any)
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            # Normalize path and resolve any '..'
            clean_path = path(path).resolve().as_posix()
            
            # Check for directory traversal
            if '..' in path or path.startswith('/') or (os.name == 'nt' and path.startswith('\\')):
                return False, "Path contains directory traversal attempts"
                
            # Check against allowed directories if specified
            if allowed_dirs:
                allowed = False
                for allowed_dir in allowed_dirs:
                    allowed_dir = path(allowed_dir).resolve().as_posix()
                    if clean_path.startswith(allowed_dir):
                        allowed = True
                        break
                if not allowed:
                    return False, "Path is not in an allowed directory"
                    
            return True, "Valid file path"
        except Exception as e:
            return False, f"Invalid path: {str(e)}"

    def validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Validate an email address format.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        email = email.strip()
        
        if len(email) > self._max_lengths['email']:
            return False, f"Email exceeds maximum length of {self._max_lengths['email']} characters"
            
        if not re.match(self._patterns['email'], email):
            return False, "Invalid email format"
            
        if self._check_injection(email):
            return False, "Email contains potentially dangerous characters"
            
        return True, "Valid email"

    def validate_hash(self, hash_str: str, hash_type: str = 'sha256') -> Tuple[bool, str]:
        """
        Validate a cryptographic hash string.
        
        Args:
            hash_str: Hash string to validate
            hash_type: Type of hash ('md5' or 'sha256')
            
        Returns:
            Tuple of (is_valid, message)
        """
        hash_str = hash_str.lower().strip()
        
        if hash_type == 'md5':
            pattern = self._patterns['md5_hash']
            expected_length = 32
        elif hash_type == 'sha256':
            pattern = self._patterns['sha256_hash']
            expected_length = 64
        else:
            return False, f"Unsupported hash type: {hash_type}"
            
        if len(hash_str) != expected_length:
            return False, f"Invalid {hash_type} hash length"
            
        if not re.match(pattern, hash_str):
            return False, f"Invalid {hash_type} hash format"
            
        return True, f"Valid {hash_type} hash"