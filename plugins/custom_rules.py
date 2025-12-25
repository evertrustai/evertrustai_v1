"""
Custom Rules Plugin - Generic API keys, OAuth tokens, passwords, URLs, GraphQL
"""

from typing import List, Dict
from plugins.base_plugin import BasePlugin


class CustomRulesPlugin(BasePlugin):
    """Detect various sensitive data patterns"""
    
    def get_patterns(self) -> List[Dict]:
        """Get custom detection patterns"""
        return [
            # API Keys
            {
                'pattern': r'(?i)api[_\-\s]?key["\s]*[:=]["\s]*["\'][A-Za-z0-9_\-]{20,}["\']',
                'severity': 'High',
                'type': 'Generic API Key',
                'description': 'Generic API key detected'
            },
            {
                'pattern': r'(?i)api[_\-\s]?secret["\s]*[:=]["\s]*["\'][A-Za-z0-9_\-]{20,}["\']',
                'severity': 'High',
                'type': 'API Secret',
                'description': 'API secret detected'
            },
            
            # OAuth Tokens
            {
                'pattern': r'(?i)oauth[_\-\s]?token["\s]*[:=]["\s]*["\'][A-Za-z0-9_\-]{20,}["\']',
                'severity': 'High',
                'type': 'OAuth Token',
                'description': 'OAuth token detected'
            },
            {
                'pattern': r'(?i)access[_\-\s]?token["\s]*[:=]["\s]*["\'][A-Za-z0-9_\-\.]{20,}["\']',
                'severity': 'High',
                'type': 'Access Token',
                'description': 'Access token detected'
            },
            {
                'pattern': r'(?i)refresh[_\-\s]?token["\s]*[:=]["\s]*["\'][A-Za-z0-9_\-\.]{20,}["\']',
                'severity': 'High',
                'type': 'Refresh Token',
                'description': 'Refresh token detected'
            },
            
            # Passwords
            {
                'pattern': r'(?i)password["\s]*[:=]["\s]*["\'][^"\']{8,}["\']',
                'severity': 'Critical',
                'type': 'Hardcoded Password',
                'description': 'Hardcoded password detected'
            },
            {
                'pattern': r'(?i)passwd["\s]*[:=]["\s]*["\'][^"\']{8,}["\']',
                'severity': 'Critical',
                'type': 'Hardcoded Password',
                'description': 'Hardcoded password detected'
            },
            {
                'pattern': r'(?i)pwd["\s]*[:=]["\s]*["\'][^"\']{8,}["\']',
                'severity': 'Critical',
                'type': 'Hardcoded Password',
                'description': 'Hardcoded password detected'
            },
            
            # Database Credentials
            {
                'pattern': r'(?i)db[_\-\s]?password["\s]*[:=]["\s]*["\'][^"\']{4,}["\']',
                'severity': 'Critical',
                'type': 'Database Password',
                'description': 'Database password detected'
            },
            {
                'pattern': r'(?i)database[_\-\s]?url["\s]*[:=]["\s]*["\'](?:mysql|postgres|mongodb|redis)://[^"\']+["\']',
                'severity': 'High',
                'type': 'Database Connection String',
                'description': 'Database connection string with credentials detected'
            },
            
            # Private Keys
            {
                'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
                'severity': 'Critical',
                'type': 'Private Key',
                'description': 'Private key detected'
            },
            
            # Internal URLs
            {
                'pattern': r'(?i)https?://(?:localhost|127\.0\.0\.1|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::[0-9]{1,5})?(?:/[^\s"\']*)?',
                'severity': 'Medium',
                'type': 'Internal URL',
                'description': 'Internal/localhost URL detected'
            },
            {
                'pattern': r'(?i)https?://[a-z0-9-]+\.(?:local|internal|corp|dev|staging)(?:/[^\s"\']*)?',
                'severity': 'Medium',
                'type': 'Internal Domain',
                'description': 'Internal domain URL detected'
            },
            
            # GraphQL Endpoints
            {
                'pattern': r'(?i)(?:https?://[^\s"\']+)?/graphql',
                'severity': 'Low',
                'type': 'GraphQL Endpoint',
                'description': 'GraphQL endpoint detected'
            },
            {
                'pattern': r'(?i)(?:https?://[^\s"\']+)?/graphiql',
                'severity': 'Medium',
                'type': 'GraphiQL Interface',
                'description': 'GraphiQL interface endpoint detected'
            },
            
            # Admin Endpoints
            {
                'pattern': r'(?i)(?:https?://[^\s"\']+)?/admin(?:/[^\s"\']*)?',
                'severity': 'Medium',
                'type': 'Admin Endpoint',
                'description': 'Admin endpoint detected'
            },
            {
                'pattern': r'(?i)(?:https?://[^\s"\']+)?/api/v[0-9]+/admin',
                'severity': 'Medium',
                'type': 'Admin API Endpoint',
                'description': 'Admin API endpoint detected'
            },
            
            # Slack Tokens
            {
                'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
                'severity': 'High',
                'type': 'Slack Token',
                'description': 'Slack API token detected'
            },
            
            # GitHub Tokens
            {
                'pattern': r'ghp_[A-Za-z0-9]{36}',
                'severity': 'Critical',
                'type': 'GitHub Personal Access Token',
                'description': 'GitHub personal access token detected'
            },
            {
                'pattern': r'gho_[A-Za-z0-9]{36}',
                'severity': 'Critical',
                'type': 'GitHub OAuth Token',
                'description': 'GitHub OAuth token detected'
            },
            
            # Google API Keys
            {
                'pattern': r'(?i)google[_\-\s]?api[_\-\s]?key["\s]*[:=]["\s]*[A-Za-z0-9_-]{39}',
                'severity': 'High',
                'type': 'Google API Key',
                'description': 'Google API key detected'
            },
            
            # Stripe Keys
            {
                'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
                'severity': 'Critical',
                'type': 'Stripe Live Secret Key',
                'description': 'Stripe live secret key detected'
            },
            {
                'pattern': r'pk_live_[0-9a-zA-Z]{24,}',
                'severity': 'High',
                'type': 'Stripe Live Publishable Key',
                'description': 'Stripe live publishable key detected'
            },
            
            # Twilio
            {
                'pattern': r'SK[a-z0-9]{32}',
                'severity': 'High',
                'type': 'Twilio API Key',
                'description': 'Twilio API key detected'
            },
            
            # SendGrid
            {
                'pattern': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
                'severity': 'High',
                'type': 'SendGrid API Key',
                'description': 'SendGrid API key detected'
            },
            
            # MailChimp
            {
                'pattern': r'[a-f0-9]{32}-us[0-9]{1,2}',
                'severity': 'High',
                'type': 'MailChimp API Key',
                'description': 'MailChimp API key detected'
            }
        ]
