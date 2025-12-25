"""
Scanner Module - Plugin-based vulnerability scanner
"""

import os
import importlib
import inspect
from pathlib import Path
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn

from plugins.base_plugin import BasePlugin, Finding

console = Console()


class VulnerabilityScanner:
    """Scan JavaScript files for vulnerabilities using plugins"""
    
    def __init__(self, plugins_dir: str = "plugins"):
        """
        Initialize scanner
        
        Args:
            plugins_dir: Directory containing plugin modules
        """
        self.plugins_dir = plugins_dir
        self.plugins: List[BasePlugin] = []
        self.findings: List[Finding] = []
    
    def load_plugins(self):
        """Dynamically load all plugins from plugins directory"""
        console.print("[cyan]→[/cyan] Loading scanner plugins...")
        
        # Get all Python files in plugins directory
        plugins_path = Path(self.plugins_dir)
        
        if not plugins_path.exists():
            console.print(f"[yellow]⚠[/yellow] Plugins directory not found: {self.plugins_dir}")
            return
        
        plugin_files = [f for f in plugins_path.glob("*.py") 
                       if f.name not in ['__init__.py', 'base_plugin.py']]
        
        for plugin_file in plugin_files:
            try:
                # Import module
                module_name = f"plugins.{plugin_file.stem}"
                module = importlib.import_module(module_name)
                
                # Find all classes that inherit from BasePlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BasePlugin) and obj != BasePlugin:
                        plugin_instance = obj()
                        self.plugins.append(plugin_instance)
                        console.print(f"  [green]✓[/green] Loaded: {name}")
            
            except Exception as e:
                console.print(f"  [red]✗[/red] Failed to load {plugin_file.name}: {str(e)}")
        
        console.print(f"\n[bold green]✓ Loaded {len(self.plugins)} plugins[/bold green]\n")
    
    def scan_file(self, filepath: str) -> List[Finding]:
        """
        Scan a single file with all plugins
        
        Args:
            filepath: Path to file to scan
            
        Returns:
            List of findings from all plugins
        """
        file_findings = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Run all enabled plugins
            for plugin in self.plugins:
                if plugin.is_enabled():
                    findings = plugin.scan(content, filepath)
                    file_findings.extend(findings)
        
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error scanning {filepath}: {str(e)}")
        
        return file_findings
    
    def scan_files(self, file_paths: List[str]) -> List[Finding]:
        """
        Scan multiple files
        
        Args:
            file_paths: List of file paths to scan
            
        Returns:
            List of all findings
        """
        console.print(f"\n[bold cyan]🔍 Scanning {len(file_paths)} JavaScript files for vulnerabilities...[/bold cyan]\n")
        
        self.findings = []
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
        ) as progress:
            task = progress.add_task(
                "[cyan]Scanning files...",
                total=len(file_paths)
            )
            
            for filepath in file_paths:
                findings = self.scan_file(filepath)
                self.findings.extend(findings)
                progress.update(task, advance=1)
        
        # Print summary
        severity_counts = self._count_by_severity()
        
        console.print(f"\n[bold green]✓ Scan complete![/bold green]")
        console.print(f"  Total findings: {len(self.findings)}")
        
        if severity_counts:
            console.print(f"  [bold red]Critical:[/bold red] {severity_counts.get('Critical', 0)}")
            console.print(f"  [bold orange1]High:[/bold orange1] {severity_counts.get('High', 0)}")
            console.print(f"  [bold yellow]Medium:[/bold yellow] {severity_counts.get('Medium', 0)}")
            console.print(f"  [bold cyan]Low:[/bold cyan] {severity_counts.get('Low', 0)}")
        
        console.print()
        
        return self.findings
    
    def scan_directory(self, directory: str) -> List[Finding]:
        """
        Recursively scan all JS files in a directory
        
        Args:
            directory: Directory to scan
            
        Returns:
            List of all findings
        """
        js_files = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.js'):
                    js_files.append(os.path.join(root, file))
        
        return self.scan_files(js_files)
    
    def get_findings(self) -> List[Finding]:
        """Get all findings"""
        return self.findings
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
    
    def get_summary(self) -> Dict:
        """Get scan summary statistics"""
        return {
            'total_findings': len(self.findings),
            'by_severity': self._count_by_severity(),
            'by_plugin': self._count_by_plugin(),
            'by_type': self._count_by_type()
        }
    
    def _count_by_plugin(self) -> Dict[str, int]:
        """Count findings by plugin"""
        counts = {}
        for finding in self.findings:
            counts[finding.plugin_name] = counts.get(finding.plugin_name, 0) + 1
        return counts
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count findings by type"""
        counts = {}
        for finding in self.findings:
            counts[finding.finding_type] = counts.get(finding.finding_type, 0) + 1
        return counts


def scan_javascript_files(file_paths: List[str], plugins_dir: str = "plugins") -> List[Finding]:
    """
    Convenience function to scan JavaScript files
    
    Args:
        file_paths: List of file paths to scan
        plugins_dir: Directory containing plugins
        
    Returns:
        List of findings
    """
    scanner = VulnerabilityScanner(plugins_dir)
    scanner.load_plugins()
    return scanner.scan_files(file_paths)
