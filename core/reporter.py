"""
Reporter Module - Generate console and JSON reports
"""

import json
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from plugins.base_plugin import Finding

console = Console()


class Reporter:
    """Generate professional reports from scan findings"""
    
    def __init__(self, findings: List[Finding], target_domain: str):
        """
        Initialize reporter
        
        Args:
            findings: List of findings to report
            target_domain: Target domain that was scanned
        """
        self.findings = findings
        self.target_domain = target_domain
        self.scan_time = datetime.now()
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'Critical': 'bold red',
            'High': 'bold orange1',
            'Medium': 'bold yellow',
            'Low': 'bold cyan'
        }
        return colors.get(severity, 'white')
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🔵'
        }
        return emojis.get(severity, '⚪')
    
    def print_summary(self):
        """Print summary statistics"""
        total = len(self.findings)
        
        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        # Create summary text
        summary_text = Text()
        summary_text.append(f"Target: ", style="bold cyan")
        summary_text.append(f"{self.target_domain}\n", style="white")
        summary_text.append(f"Scan Time: ", style="bold cyan")
        summary_text.append(f"{self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}\n", style="white")
        summary_text.append(f"Total Findings: ", style="bold cyan")
        summary_text.append(f"{total}\n\n", style="white")
        
        summary_text.append("Severity Breakdown:\n", style="bold cyan")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = severity_counts.get(severity, 0)
            emoji = self._get_severity_emoji(severity)
            color = self._get_severity_color(severity)
            summary_text.append(f"  {emoji} {severity}: ", style=color)
            summary_text.append(f"{count}\n", style="white")
        
        panel = Panel(
            summary_text,
            title="[bold cyan]📊 Scan Summary[/bold cyan]",
            border_style="cyan"
        )
        
        console.print()
        console.print(panel)
        console.print()
    
    def print_findings_table(self, max_findings: int = 50):
        """
        Print findings in a table format
        
        Args:
            max_findings: Maximum number of findings to display
        """
        if not self.findings:
            console.print("[yellow]No findings to display[/yellow]")
            return
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_findings = sorted(
            self.findings,
            key=lambda x: (severity_order.get(x.severity, 4), x.file_path)
        )
        
        # Limit findings
        display_findings = sorted_findings[:max_findings]
        
        # Create table
        table = Table(
            title=f"[bold cyan]🔍 Security Findings (Showing {len(display_findings)} of {len(self.findings)})[/bold cyan]",
            show_header=True,
            header_style="bold magenta"
        )
        
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type", style="cyan", width=25)
        table.add_column("File", style="blue", width=40)
        table.add_column("Line", justify="right", width=6)
        table.add_column("Value", style="yellow", width=30)
        
        for finding in display_findings:
            severity_color = self._get_severity_color(finding.severity)
            emoji = self._get_severity_emoji(finding.severity)
            
            # Truncate file path
            file_display = finding.file_path
            if len(file_display) > 40:
                file_display = "..." + file_display[-37:]
            
            # Truncate value
            value_display = finding.masked_value
            if len(value_display) > 30:
                value_display = value_display[:27] + "..."
            
            table.add_row(
                f"{emoji} {finding.severity}",
                finding.finding_type,
                file_display,
                str(finding.line_number),
                value_display
            )
        
        console.print(table)
        console.print()
        
        if len(self.findings) > max_findings:
            console.print(f"[yellow]⚠ Showing first {max_findings} findings. See JSON report for complete results.[/yellow]\n")
    
    def print_detailed_findings(self, severity_filter: str = None, max_findings: int = 10):
        """
        Print detailed findings with context
        
        Args:
            severity_filter: Filter by severity (Critical/High/Medium/Low)
            max_findings: Maximum number of findings to display
        """
        findings = self.findings
        
        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]
        
        if not findings:
            console.print(f"[yellow]No {severity_filter or ''} findings to display[/yellow]")
            return
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_findings = sorted(
            findings,
            key=lambda x: (severity_order.get(x.severity, 4), x.file_path)
        )
        
        display_findings = sorted_findings[:max_findings]
        
        console.print(f"\n[bold cyan]📋 Detailed Findings ({len(display_findings)} of {len(findings)})[/bold cyan]\n")
        
        for i, finding in enumerate(display_findings, 1):
            emoji = self._get_severity_emoji(finding.severity)
            color = self._get_severity_color(finding.severity)
            
            console.print(f"[bold]{i}. {emoji} {finding.finding_type}[/bold]", style=color)
            console.print(f"   Severity: [{color}]{finding.severity}[/{color}]")
            console.print(f"   File: [blue]{finding.file_path}[/blue]:[cyan]{finding.line_number}[/cyan]")
            console.print(f"   Description: {finding.description}")
            console.print(f"   Value: [yellow]{finding.masked_value}[/yellow]")
            if finding.context:
                console.print(f"   Context: [dim]{finding.context}[/dim]")
            console.print()
    
    def generate_json_report(self, output_path: str = "reports/report.json") -> str:
        """
        Generate JSON report
        
        Args:
            output_path: Path to save JSON report
            
        Returns:
            Path to saved report
        """
        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        # Count by type
        type_counts = {}
        for finding in self.findings:
            type_counts[finding.finding_type] = type_counts.get(finding.finding_type, 0) + 1
        
        # Build report
        report = {
            'scan_metadata': {
                'target': self.target_domain,
                'scan_time': self.scan_time.isoformat(),
                'total_findings': len(self.findings)
            },
            'summary': {
                'by_severity': severity_counts,
                'by_type': type_counts
            },
            'findings': [finding.to_dict() for finding in self.findings]
        }
        
        # Save to file
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓[/green] JSON report saved: {output_path}")
        
        return output_path
    
    def generate_console_report(self, detailed: bool = False):
        """
        Generate complete console report
        
        Args:
            detailed: Include detailed findings
        """
        self.print_summary()
        self.print_findings_table()
        
        if detailed:
            # Show detailed critical and high findings
            self.print_detailed_findings(severity_filter='Critical', max_findings=5)
            self.print_detailed_findings(severity_filter='High', max_findings=5)


def generate_report(findings: List[Finding], target_domain: str, output_dir: str = "reports", detailed: bool = False):
    """
    Convenience function to generate reports
    
    Args:
        findings: List of findings
        target_domain: Target domain
        output_dir: Output directory for reports
        detailed: Include detailed console output
    """
    reporter = Reporter(findings, target_domain)
    reporter.generate_console_report(detailed=detailed)
    
    json_path = f"{output_dir}/report.json"
    reporter.generate_json_report(json_path)
