import socket
import concurrent.futures
from typing import List, Dict
from ..base import BaseRecon

class PortScanner(BaseRecon):
    COMMON_PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH',
        23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 443: 'HTTPS', 445: 'SMB',
        3306: 'MySQL', 3389: 'RDP'
    }

    def __init__(self, config):
        super().__init__(config)
        self.scan_timeout = config.get('scan.timeout', 1.5)

    def scan_port(self, target: str, port: int) -> Optional[Dict]:
        """Scan single port with service detection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.scan_timeout)
                result = s.connect_ex((target, port))
                
                if result == 0:
                    service = self.COMMON_PORTS.get(port, 'unknown')
                    return {'port': port, 'state': 'open', 'service': service}
        except Exception as e:
            self.logger.debug(f"Port {port} scan error: {str(e)}")
        return None

    def scan_range(self, target: str, ports: List[int]) -> Dict[int, Dict]:
        """Scan multiple ports with threading"""
        if not self.validate_target(target):
            return {}
            
        open_ports = {}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_threads
        ) as executor:
            futures = {
                executor.submit(self.scan_port, target, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports[result['port']] = result
                    
        return open_ports

    def smart_scan(self, target: str) -> Dict[int, Dict]:
        """Automated scan strategy based on target"""
        # Start with top 1000 ports for IPs
        ports = list(range(1, 1001)) if self.validator.is_ip(target) else [
            80, 443, 8080, 8443  # Common web ports for domains
        ]
        return self.scan_range(target, ports)