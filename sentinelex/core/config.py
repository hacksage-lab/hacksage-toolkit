import json
from pathlib import Path
from utils.crypto import decrypt_config, encrypt_config

class ConfigManager:
    def __init__(self, config_path="config.json.enc"):
        self.config_path = Path(config_path)
        self._config = None
        
    def load_config(self, key):
        if not self.config_path.exists():
            raise FileNotFoundError("Configuration file missing")
        
        encrypted = self.config_path.read_bytes()
        self._config = json.loads(decrypt_config(encrypted, key))
        return self._config
    
    def save_config(self, key, config_data):
        encrypted = encrypt_config(json.dumps(config_data).encode(), key)
        self.config_path.write_bytes(encrypted)
        self._config = config_data