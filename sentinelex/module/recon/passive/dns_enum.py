import dns.resolver
from typing import Dict, List
from ..base import BaseRecon

class DNSEnumerator(BaseRecon):
    RECORD_TYPES = [
        'A', 'AAAA', 'MX', 
        'NS', 'SOA', 'TXT',
        'CNAME', 'SRV', 'PTR'
    ]

    def __init__(self, config):
        super().__init__(config)
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = config.get('dns.servers', ['1.1.1.1', '8.8.8.8'])

    def query(self, domain: str, record_type: str = 'A') -> List[str]:
        """Query specific DNS record type"""
        if not self.validate_target(domain):
            return []
            
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except Exception as e:
            self.logger.debug(f"DNS {record_type} query failed: {str(e)}")
            return []

    def full_enumeration(self, domain: str) -> Dict[str, List[str]]:
        """Perform complete DNS enumeration"""
        results = {}
        for record_type in self.RECORD_TYPES:
            records = self.query(domain, record_type)
            if records:
                results[record_type] = records
        return results

    def reverse_lookup(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup"""
        if not self.validator.validate_ip(ip)[0]:
            return []
            
        try:
            ptr_record = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
            answers = self.resolver.resolve(ptr_record, 'PTR')
            return [str(r) for r in answers]
        except Exception as e:
            self.logger.debug(f"Reverse lookup failed: {str(e)}")
            return []