"""
AWS Keys Plugin - Detect AWS credentials
"""

from typing import List, Dict
from plugins.base_plugin import BasePlugin


class AWSKeysPlugin(BasePlugin):
    """Detect AWS access keys and secrets"""
    
    def get_patterns(self) -> List[Dict]:
        """Get AWS credential patterns"""
        return [
            {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'Critical',
                'type': 'AWS Access Key ID',
                'description': 'AWS Access Key ID detected - potential credential exposure'
            },
            {
                'pattern': r'(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key["\s]*[:=]["\s]*[A-Za-z0-9/+=]{40}',
                'severity': 'Critical',
                'type': 'AWS Secret Access Key',
                'description': 'AWS Secret Access Key detected - critical credential exposure'
            },
            {
                'pattern': r'(?i)aws[_\-\s]?session[_\-\s]?token["\s]*[:=]["\s]*[A-Za-z0-9/+=]{100,}',
                'severity': 'High',
                'type': 'AWS Session Token',
                'description': 'AWS Session Token detected - temporary credential exposure'
            },
            {
                'pattern': r'(?i)aws[_\-\s]?account[_\-\s]?id["\s]*[:=]["\s]*\d{12}',
                'severity': 'Medium',
                'type': 'AWS Account ID',
                'description': 'AWS Account ID detected - potential information disclosure'
            }
        ]
