"""
Base Plugin Class - Abstract interface for all scanner plugins
"""

from abc import ABC, abstractmethod
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class Finding:
    """Represents a security finding"""
    plugin_name: str
    severity: str  # Critical, High, Medium, Low
    finding_type: str
    description: str
    file_path: str
    line_number: int
    matched_value: str
    masked_value: str
    context: str = ""
    
    def to_dict(self) -> Dict:
        """Convert finding to dictionary"""
        return {
            'plugin': self.plugin_name,
            'severity': self.severity,
            'type': self.finding_type,
            'description': self.description,
            'file': self.file_path,
            'line': self.line_number,
            'value': self.masked_value,
            'context': self.context
        }


class BasePlugin(ABC):
    """Abstract base class for scanner plugins"""
    
    def __init__(self):
        """Initialize plugin"""
        self.name = self.__class__.__name__
        self.enabled = True
    
    @abstractmethod
    def get_patterns(self) -> List[Dict]:
        """
        Get regex patterns to scan for
        
        Returns:
            List of pattern dictionaries with keys:
            - pattern: regex pattern
            - severity: Critical/High/Medium/Low
            - type: Finding type
            - description: Finding description
        """
        pass
    
    def scan(self, content: str, filepath: str) -> List[Finding]:
        """
        Scan content for security issues
        
        Args:
            content: File content to scan
            filepath: Path to the file being scanned
            
        Returns:
            List of findings
        """
        import re
        from utils.helpers import mask_sensitive_value
        
        findings = []
        patterns = self.get_patterns()
        
        lines = content.split('\n')
        
        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            severity = pattern_info['severity']
            finding_type = pattern_info['type']
            description = pattern_info['description']
            
            for line_num, line in enumerate(lines, start=1):
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    matched_value = match.group(0)
                    masked_value = mask_sensitive_value(matched_value)
                    
                    # Get context (surrounding text)
                    context_start = max(0, match.start() - 30)
                    context_end = min(len(line), match.end() + 30)
                    context = line[context_start:context_end].strip()
                    
                    finding = Finding(
                        plugin_name=self.name,
                        severity=severity,
                        finding_type=finding_type,
                        description=description,
                        file_path=filepath,
                        line_number=line_num,
                        matched_value=matched_value,
                        masked_value=masked_value,
                        context=context
                    )
                    
                    findings.append(finding)
        
        return findings
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.enabled
    
    def enable(self):
        """Enable plugin"""
        self.enabled = True
    
    def disable(self):
        """Disable plugin"""
        self.enabled = False
