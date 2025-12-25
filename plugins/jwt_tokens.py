"""
JWT Tokens Plugin - Detect JWT tokens
"""

from typing import List, Dict
from plugins.base_plugin import BasePlugin


class JWTTokensPlugin(BasePlugin):
    """Detect JWT tokens"""
    
    def get_patterns(self) -> List[Dict]:
        """Get JWT token patterns"""
        return [
            {
                'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                'severity': 'High',
                'type': 'JWT Token',
                'description': 'JWT token detected - potential authentication token exposure'
            },
            {
                'pattern': r'(?i)bearer\s+eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                'severity': 'High',
                'type': 'Bearer JWT Token',
                'description': 'Bearer JWT token detected - active authentication token'
            },
            {
                'pattern': r'(?i)authorization["\s]*[:=]["\s]*bearer\s+[A-Za-z0-9_-]+',
                'severity': 'High',
                'type': 'Authorization Bearer Token',
                'description': 'Authorization bearer token detected'
            }
        ]
