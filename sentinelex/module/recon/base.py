from typing import Dict, List, Optional
import logging
from core.config import ConfigManager
from utils.validator import InputValidator
from utils.network import NetworkUtils

class BaseRecon:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.validator = InputValidator()
        self.network = NetworkUtils()
        self.logger = logging.getLogger('sentinelx.recon')
        
        # Rate limiting controls
        self.rate_limit = config.get('recon.rate_limit', 2)  # reqs/second
        self.max_threads = config.get('recon.max_threads', 5)
        
    def validate_target(self, target: str) -> bool:
        """Validate target before reconnaissance"""
        if self.validator.is_ip(target):
            valid, _ = self.validator.validate_ip(target)
        else:
            valid, _ = self.validator.validate_domain(target)
        
        if not valid:
            self.logger.error(f"Invalid target: {target}")
        return valid

    def safe_request(self, url: str, headers: Optional[Dict] = None) -> Optional[str]:
        """Make requests with safety checks"""
        if not self.validator.validate_url(url)[0]:
            return None
            
        try:
            response = self.network.get(
                url,
                headers=headers,
                timeout=self.config.get('recon.timeout', 10),
                rate_limit=self.rate_limit
            )
            return response.text if response.status_code == 200 else None
        except Exception as e:
            self.logger.warning(f"Request failed to {url}: {str(e)}")
            return None