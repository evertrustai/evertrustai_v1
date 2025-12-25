"""
JavaScript Finder - Discover JS files from live subdomains
"""

import asyncio
from typing import List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, TaskID

from utils.http_client import AsyncHTTPClient
from utils.helpers import is_javascript_file, normalize_url, extract_js_urls_from_html

console = Console()


class JavaScriptFinder:
    """Discover JavaScript files from web pages"""
    
    def __init__(self, subdomains: List[str], max_concurrent: int = 10):
        """
        Initialize JS finder
        
        Args:
            subdomains: List of subdomains to crawl
            max_concurrent: Maximum concurrent requests
        """
        self.subdomains = subdomains
        self.max_concurrent = max_concurrent
        self.js_files: Set[str] = set()
    
    async def _fetch_page(self, url: str, client: AsyncHTTPClient) -> str:
        """Fetch a single page"""
        try:
            return await client.get(url)
        except Exception:
            return None
    
    def _extract_js_from_html(self, html: str, base_url: str) -> Set[str]:
        """
        Extract JavaScript URLs from HTML content
        
        Args:
            html: HTML content
            base_url: Base URL for resolving relative paths
            
        Returns:
            Set of JavaScript URLs
        """
        if not html:
            return set()
        
        js_urls = set()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find all script tags with src attribute
            for script in soup.find_all('script', src=True):
                src = script.get('src', '').strip()
                if src:
                    # Normalize URL
                    full_url = normalize_url(src, base_url)
                    if full_url and is_javascript_file(full_url):
                        js_urls.add(full_url)
            
            # Also check for inline script tags that might reference external JS
            for script in soup.find_all('script'):
                script_content = script.string
                if script_content:
                    # Look for URLs in script content (e.g., dynamic script loading)
                    import re
                    url_pattern = r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'
                    matches = re.findall(url_pattern, script_content)
                    for match in matches:
                        full_url = normalize_url(match, base_url)
                        if full_url and is_javascript_file(full_url):
                            js_urls.add(full_url)
        
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error parsing HTML: {str(e)}")
        
        return js_urls
    
    async def discover_from_subdomain(self, subdomain: str, client: AsyncHTTPClient) -> Set[str]:
        """
        Discover JS files from a single subdomain
        
        Args:
            subdomain: Subdomain to crawl
            client: HTTP client
            
        Returns:
            Set of discovered JS URLs
        """
        js_urls = set()
        
        # Try both HTTP and HTTPS
        protocols = ['https', 'http']
        
        for protocol in protocols:
            base_url = f"{protocol}://{subdomain}"
            
            # Fetch the main page
            html = await self._fetch_page(base_url, client)
            
            if html:
                # Extract JS files
                found_js = self._extract_js_from_html(html, base_url)
                js_urls.update(found_js)
                
                # If we found content, no need to try other protocol
                break
        
        return js_urls
    
    async def discover_all(self) -> List[str]:
        """
        Discover JavaScript files from all subdomains
        
        Returns:
            List of unique JavaScript URLs
        """
        console.print(f"\n[bold cyan]🔍 Discovering JavaScript files from {len(self.subdomains)} subdomains...[/bold cyan]\n")
        
        async with AsyncHTTPClient(timeout=20, max_concurrent=self.max_concurrent) as client:
            with Progress() as progress:
                task = progress.add_task(
                    "[cyan]Crawling subdomains...",
                    total=len(self.subdomains)
                )
                
                # Create tasks for all subdomains
                tasks = []
                for subdomain in self.subdomains:
                    tasks.append(self.discover_from_subdomain(subdomain, client))
                
                # Process in batches
                batch_size = self.max_concurrent
                for i in range(0, len(tasks), batch_size):
                    batch = tasks[i:i + batch_size]
                    results = await asyncio.gather(*batch)
                    
                    for result in results:
                        self.js_files.update(result)
                    
                    progress.update(task, advance=len(batch))
        
        console.print(f"\n[bold green]✓ Total JavaScript files discovered: {len(self.js_files)}[/bold green]\n")
        
        return sorted(list(self.js_files))
    
    def get_js_files(self) -> List[str]:
        """Get discovered JavaScript files"""
        return sorted(list(self.js_files))


async def discover_javascript_files(subdomains: List[str], max_concurrent: int = 10) -> List[str]:
    """
    Convenience function to discover JavaScript files
    
    Args:
        subdomains: List of subdomains to crawl
        max_concurrent: Maximum concurrent requests
        
    Returns:
        List of discovered JavaScript URLs
    """
    finder = JavaScriptFinder(subdomains, max_concurrent)
    return await finder.discover_all()
