"""
Subdomain Enumerator - Multiple sources (crt.sh, SecurityTrails, external tools)
"""

import asyncio
import json
import re
import subprocess
from typing import List, Set, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from utils.http_client import AsyncHTTPClient
from utils.helpers import extract_domain, deduplicate_list, save_to_file, save_to_json

console = Console()


class SubdomainEnumerator:
    """Enumerate subdomains using multiple techniques"""
    
    def __init__(self, domain: str, output_dir: str = "output"):
        """
        Initialize subdomain enumerator
        
        Args:
            domain: Target domain
            output_dir: Output directory for results
        """
        self.domain = domain.lower().strip()
        self.output_dir = output_dir
        self.subdomains: Set[str] = set()
    
    async def enumerate_crtsh(self) -> List[str]:
        """
        Enumerate subdomains using crt.sh (Certificate Transparency)
        
        Returns:
            List of discovered subdomains
        """
        console.print(f"[cyan]→[/cyan] Querying crt.sh for {self.domain}...")
        
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()
        
        try:
            async with AsyncHTTPClient(timeout=30) as client:
                response = await client.get(url)
                
                if response:
                    try:
                        data = json.loads(response)
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # Split by newlines (crt.sh returns multiple domains per entry sometimes)
                            for subdomain in name_value.split('\n'):
                                subdomain = subdomain.strip().lower()
                                # Remove wildcards
                                subdomain = subdomain.replace('*.', '')
                                # Validate it's a subdomain of target
                                if subdomain.endswith(self.domain) and subdomain:
                                    subdomains.add(subdomain)
                        
                        console.print(f"[green]✓[/green] crt.sh: Found {len(subdomains)} subdomains")
                    except json.JSONDecodeError:
                        console.print("[yellow]⚠[/yellow] crt.sh: Invalid JSON response")
                else:
                    console.print("[yellow]⚠[/yellow] crt.sh: No response")
        except Exception as e:
            console.print(f"[red]✗[/red] crt.sh error: {str(e)}")
        
        return list(subdomains)
    
    async def enumerate_securitytrails(self, api_key: Optional[str] = None) -> List[str]:
        """
        Enumerate subdomains using SecurityTrails API (requires API key)
        
        Args:
            api_key: SecurityTrails API key
            
        Returns:
            List of discovered subdomains
        """
        if not api_key:
            console.print("[yellow]⚠[/yellow] SecurityTrails: No API key provided, skipping")
            return []
        
        console.print(f"[cyan]→[/cyan] Querying SecurityTrails for {self.domain}...")
        
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {
            'APIKEY': api_key,
            'Accept': 'application/json'
        }
        
        subdomains = set()
        
        try:
            async with AsyncHTTPClient(timeout=30) as client:
                # Note: Need to modify client to support custom headers
                # For now, using basic implementation
                console.print("[yellow]⚠[/yellow] SecurityTrails: API integration requires custom headers (future enhancement)")
        except Exception as e:
            console.print(f"[red]✗[/red] SecurityTrails error: {str(e)}")
        
        return list(subdomains)
    
    def enumerate_assetfinder(self) -> List[str]:
        """
        Enumerate subdomains using assetfinder (if installed)
        
        Returns:
            List of discovered subdomains
        """
        console.print(f"[cyan]→[/cyan] Running assetfinder for {self.domain}...")
        
        try:
            result = subprocess.run(
                ['assetfinder', '--subs-only', self.domain],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                console.print(f"[green]✓[/green] assetfinder: Found {len(subdomains)} subdomains")
                return subdomains
            else:
                console.print("[yellow]⚠[/yellow] assetfinder: Command failed")
                return []
        except FileNotFoundError:
            console.print("[yellow]⚠[/yellow] assetfinder: Not installed (optional)")
            return []
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠[/yellow] assetfinder: Timeout")
            return []
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] assetfinder error: {str(e)}")
            return []
    
    def enumerate_subfinder(self) -> List[str]:
        """
        Enumerate subdomains using subfinder (if installed)
        
        Returns:
            List of discovered subdomains
        """
        console.print(f"[cyan]→[/cyan] Running subfinder for {self.domain}...")
        
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.domain, '-silent'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                console.print(f"[green]✓[/green] subfinder: Found {len(subdomains)} subdomains")
                return subdomains
            else:
                console.print("[yellow]⚠[/yellow] subfinder: Command failed")
                return []
        except FileNotFoundError:
            console.print("[yellow]⚠[/yellow] subfinder: Not installed (optional)")
            return []
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠[/yellow] subfinder: Timeout")
            return []
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] subfinder error: {str(e)}")
            return []
    
    async def enumerate_all(self, api_key: Optional[str] = None) -> List[str]:
        """
        Enumerate subdomains using all available methods
        
        Args:
            api_key: Optional SecurityTrails API key
            
        Returns:
            Deduplicated list of all discovered subdomains
        """
        console.print(f"\n[bold cyan]🔍 Starting subdomain enumeration for: {self.domain}[/bold cyan]\n")
        
        all_subdomains = []
        
        # Async methods
        async_results = await asyncio.gather(
            self.enumerate_crtsh(),
            self.enumerate_securitytrails(api_key)
        )
        
        for result in async_results:
            all_subdomains.extend(result)
        
        # Sync methods (external tools)
        all_subdomains.extend(self.enumerate_assetfinder())
        all_subdomains.extend(self.enumerate_subfinder())
        
        # Add main domain
        all_subdomains.append(self.domain)
        
        # Deduplicate
        self.subdomains = set(deduplicate_list(all_subdomains))
        
        console.print(f"\n[bold green]✓ Total unique subdomains found: {len(self.subdomains)}[/bold green]\n")
        
        return sorted(list(self.subdomains))
    
    def save_results(self) -> tuple:
        """
        Save enumeration results to files
        
        Returns:
            Tuple of (text_file_path, json_file_path)
        """
        # Save to text file
        txt_path = f"{self.output_dir}/subdomains.txt"
        txt_content = '\n'.join(sorted(self.subdomains))
        save_to_file(txt_path, txt_content)
        
        # Save to JSON
        json_path = f"{self.output_dir}/subdomains.json"
        json_data = {
            'domain': self.domain,
            'total_count': len(self.subdomains),
            'subdomains': sorted(list(self.subdomains))
        }
        save_to_json(json_path, json_data)
        
        console.print(f"[green]✓[/green] Results saved:")
        console.print(f"  • {txt_path}")
        console.print(f"  • {json_path}")
        
        return txt_path, json_path


async def enumerate_subdomains(domain: str, output_dir: str = "output", api_key: Optional[str] = None) -> List[str]:
    """
    Convenience function to enumerate subdomains
    
    Args:
        domain: Target domain
        output_dir: Output directory
        api_key: Optional SecurityTrails API key
        
    Returns:
        List of discovered subdomains
    """
    enumerator = SubdomainEnumerator(domain, output_dir)
    subdomains = await enumerator.enumerate_all(api_key)
    enumerator.save_results()
    return subdomains
