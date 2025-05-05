import logging
import logging.handlers
from datetime import datetime
import os
import json
from pathlib import Path
import hashlib
from utils.crypto import encrypt_data, generate_hmac
from typing import Dict, Any

class SecureLogger:
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the secure logging system.
        
        Args:
            config (dict): Configuration dictionary containing:
                - log_dir: Directory to store logs
                - max_log_size: Max size in MB before rotation
                - backup_count: Number of backups to keep
                - log_level: Minimum log level to record
                - redact_fields: List of fields to redact
                - enable_remote: Whether to enable remote logging
                - remote_endpoint: Remote logging endpoint (if enabled)
                - crypto_key: Encryption key for sensitive logs
        """
        self.config = config
        self._validate_config()
        self._setup_log_directory()
        self.logger = logging.getLogger('SentinelX')
        self._configure_logger()
        
        # Add sensitive field redaction filter
        self.logger.addFilter(SensitiveDataFilter(self.config.get('redact_fields', [])))
        
    def _validate_config(self):
        """Validate the logging configuration."""
        required_fields = ['log_dir', 'max_log_size', 'backup_count', 'log_level']
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"Missing required logging config field: {field}")
                
        if not isinstance(self.config['max_log_size'], int) or self.config['max_log_size'] <= 0:
            raise ValueError("max_log_size must be a positive integer")
            
    def _setup_log_directory(self):
        """Create and secure the log directory."""
        log_path = Path(self.config['log_dir'])
        log_path.mkdir(exist_ok=True, mode=0o750)
        
        # Set restrictive permissions (owner read/write, group read only)
        log_path.chmod(0o640)
        
    def _configure_logger(self):
        """Configure the logger with handlers and formatters."""
        self.logger.setLevel(self.config['log_level'])
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Create rotating file handler
        log_file = Path(self.config['log_dir']) / 'sentinelx.log'
        max_bytes = self.config['max_log_size'] * 1024 * 1024  # Convert MB to bytes
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=self.config['backup_count'],
            encoding='utf-8'
        )
        
        # Create secure formatter
        formatter = SecureFormatter(
            fmt='%(asctime)s | %(levelname)-8s | %(module)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S %Z'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Add console handler for critical errors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.CRITICAL)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Add remote logging if enabled
        if self.config.get('enable_remote', False):
            self._add_remote_logging()
            
    def _add_remote_logging(self):
        """Configure remote logging if enabled in config."""
        try:
            from utils.network import secure_post  # Import your secure HTTP client
            
            class RemoteLogHandler(logging.Handler):
                def emit(self, record):
                    try:
                        log_entry = self.format(record)
                        # Add integrity check
                        hmac = generate_hmac(log_entry, self.config['crypto_key'])
                        payload = {
                            'log': encrypt_data(log_entry, self.config['crypto_key']),
                            'hmac': hmac,
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        secure_post(self.config['remote_endpoint'], json=payload)
                    except Exception as e:
                        # Fail silently to not disrupt main operations
                        pass
                        
            remote_handler = RemoteLogHandler()
            remote_handler.setLevel(logging.WARNING)  # Only send important logs remotely
            self.logger.addHandler(remote_handler)
        except ImportError:
            self.logger.warning("Remote logging dependencies not available", exc_info=True)
            
    def log_operation(self, operation: str, status: str, metadata: dict = None):
        """
        Standardized method for logging security operations.
        
        Args:
            operation (str): The operation being performed (e.g., "port_scan")
            status (str): Operation status ("started", "completed", "failed")
            metadata (dict): Additional context about the operation
        """
        log_data = {
            'operation': operation,
            'status': status,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if metadata:
            log_data['metadata'] = metadata
            
        self.logger.info(json.dumps(log_data, default=str))
        
    def get_log_hashes(self) -> Dict[str, str]:
        """
        Generate integrity hashes for all log files.
        
        Returns:
            dict: Mapping of log filenames to their SHA-256 hashes
        """
        log_dir = Path(self.config['log_dir'])
        hashes = {}
        
        for log_file in log_dir.glob('*.log*'):
            file_hash = hashlib.sha256()
            with open(log_file, 'rb') as f:
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            hashes[log_file.name] = file_hash.hexdigest()
            
        return hashes


class SensitiveDataFilter(logging.Filter):
    """Filter to redact sensitive information from logs."""
    def __init__(self, redact_fields: list):
        super().__init__()
        self.redact_fields = redact_fields
        
    def filter(self, record):
        if isinstance(record.msg, dict):
            record.msg = self._redact_dict(record.msg)
        elif isinstance(record.msg, str):
            try:
                msg_dict = json.loads(record.msg)
                record.msg = json.dumps(self._redact_dict(msg_dict))
            except json.JSONDecodeError:
                pass  # Not JSON, leave as-is
        return True
        
    def _redact_dict(self, data: dict) -> dict:
        """Recursively redact sensitive fields in a dictionary."""
        redacted = data.copy()
        for key, value in redacted.items():
            if key in self.redact_fields:
                redacted[key] = '[REDACTED]'
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            elif isinstance(value, list):
                redacted[key] = [self._redact_dict(item) if isinstance(item, dict) else 
                               '[REDACTED]' if key in self.redact_fields else item 
                               for item in value]
        return redacted


class SecureFormatter(logging.Formatter):
    """Custom formatter with additional security features."""
    def format(self, record):
        """Format the log record with security enhancements."""
        # Get the standard formatted message
        message = super().format(record)
        
        # Add process/thread information for debugging
        if record.process:
            message = f"[PID:{record.process}] {message}"
        if record.thread:
            message = f"[TID:{record.thread}] {message}"
            
        return message
        
    def formatException(self, exc_info):
        """Format exceptions to limit sensitive information exposure."""
        exc_text = super().formatException(exc_info)
        # Remove potential file system paths
        exc_text = '\n'.join(line for line in exc_text.split('\n') 
                   if not line.strip().startswith('File'))
        return exc_text