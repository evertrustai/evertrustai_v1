"""
Firebase Plugin - Detect Firebase configuration and keys
"""

from typing import List, Dict
from plugins.base_plugin import BasePlugin


class FirebasePlugin(BasePlugin):
    """Detect Firebase credentials and configuration"""
    
    def get_patterns(self) -> List[Dict]:
        """Get Firebase patterns"""
        return [
            {
                'pattern': r'AIza[0-9A-Za-z_-]{35}',
                'severity': 'High',
                'type': 'Firebase API Key',
                'description': 'Firebase API key detected - potential database access'
            },
            {
                'pattern': r'(?i)firebase[_\-\s]?api[_\-\s]?key["\s]*[:=]["\s]*[A-Za-z0-9_-]{39}',
                'severity': 'High',
                'type': 'Firebase API Key',
                'description': 'Firebase API key detected in configuration'
            },
            {
                'pattern': r'https://[a-z0-9-]+\.firebaseio\.com',
                'severity': 'Medium',
                'type': 'Firebase Database URL',
                'description': 'Firebase database URL detected - potential data exposure'
            },
            {
                'pattern': r'(?i)firebase[_\-\s]?database[_\-\s]?url["\s]*[:=]["\s]*https://[a-z0-9-]+\.firebaseio\.com',
                'severity': 'Medium',
                'type': 'Firebase Database URL',
                'description': 'Firebase database URL in configuration'
            },
            {
                'pattern': r'[a-z0-9-]+\.firebaseapp\.com',
                'severity': 'Low',
                'type': 'Firebase App Domain',
                'description': 'Firebase app domain detected'
            },
            {
                'pattern': r'(?i)firebase[_\-\s]?storage[_\-\s]?bucket["\s]*[:=]["\s]*[a-z0-9-]+\.appspot\.com',
                'severity': 'Medium',
                'type': 'Firebase Storage Bucket',
                'description': 'Firebase storage bucket detected'
            }
        ]
