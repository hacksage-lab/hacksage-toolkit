import re
from typing import Dict, List
from bs4 import BeautifulSoup
from ..base import BaseRecon

class SocialMediaFinder(BaseRecon):
    PLATFORMS = {
        'twitter': r'https?://(www\.)?twitter\.com/[a-zA-Z0-9_]{1,15}',
        'linkedin': r'https?://(www\.)?linkedin\.com/(in|company)/[a-zA-Z0-9-]+',
        'github': r'https?://(www\.)?github\.com/[a-zA-Z0-9-]+'
    }

    def find_profiles(self, query: str) -> Dict[str, List[str]]:
        """Find social media profiles using search engines"""
        if not query or len(query) < 4:
            return {}
            
        results = {}
        search_url = (
            f"https://www.google.com/search?q={query}"
            "&num=20&hl=en&filter=0"
        )
        
        html = self.safe_request(search_url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })
        
        if not html:
            return results
            
        soup = BeautifulSoup(html, 'html.parser')
        for platform, pattern in self.PLATFORMS.items():
            matches = re.finditer(pattern, str(soup))
            results[platform] = list({m.group() for m in matches})
            
        return results