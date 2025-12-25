"""
JavaScript Downloader - Bulk download of discovered JS files
"""

import asyncio
import os
from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from utils.http_client import AsyncHTTPClient
from utils.helpers import sanitize_filename, extract_domain

console = Console()


class JavaScriptDownloader:
    """Download JavaScript files and organize by domain"""
    
    def __init__(self, js_urls: List[str], output_dir: str = "js_files", max_concurrent: int = 10):
        """
        Initialize JS downloader
        
        Args:
            js_urls: List of JavaScript URLs to download
            output_dir: Base output directory
            max_concurrent: Maximum concurrent downloads
        """
        self.js_urls = js_urls
        self.output_dir = output_dir
        self.max_concurrent = max_concurrent
        self.downloaded_files: Dict[str, str] = {}  # URL -> local path
    
    def _get_local_path(self, url: str) -> str:
        """
        Get local file path for a JS URL
        
        Args:
            url: JavaScript URL
            
        Returns:
            Local file path
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Create domain directory
        domain_dir = os.path.join(self.output_dir, domain)
        
        # Get filename from path
        if path.endswith('/'):
            filename = 'index.js'
        else:
            filename = os.path.basename(path)
            if not filename:
                filename = 'script.js'
        
        # Sanitize filename
        filename = sanitize_filename(filename)
        
        # Ensure .js extension
        if not filename.endswith('.js'):
            filename += '.js'
        
        # Handle duplicates by adding counter
        local_path = os.path.join(domain_dir, filename)
        counter = 1
        while os.path.exists(local_path):
            name, ext = os.path.splitext(filename)
            local_path = os.path.join(domain_dir, f"{name}_{counter}{ext}")
            counter += 1
        
        return local_path
    
    async def _download_file(self, url: str, client: AsyncHTTPClient) -> tuple:
        """
        Download a single JavaScript file
        
        Args:
            url: JavaScript URL
            client: HTTP client
            
        Returns:
            Tuple of (url, local_path) or (url, None) on failure
        """
        try:
            content = await client.get(url)
            
            if content:
                local_path = self._get_local_path(url)
                
                # Create directory
                Path(local_path).parent.mkdir(parents=True, exist_ok=True)
                
                # Save file
                with open(local_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(content)
                
                return url, local_path
            else:
                return url, None
        except Exception as e:
            return url, None
    
    async def download_all(self) -> Dict[str, str]:
        """
        Download all JavaScript files
        
        Returns:
            Dictionary mapping URLs to local file paths
        """
        console.print(f"\n[bold cyan]📥 Downloading {len(self.js_urls)} JavaScript files...[/bold cyan]\n")
        
        async with AsyncHTTPClient(timeout=30, max_concurrent=self.max_concurrent) as client:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task(
                    "[cyan]Downloading...",
                    total=len(self.js_urls)
                )
                
                # Create download tasks
                tasks = []
                for url in self.js_urls:
                    tasks.append(self._download_file(url, client))
                
                # Process in batches
                batch_size = self.max_concurrent
                for i in range(0, len(tasks), batch_size):
                    batch = tasks[i:i + batch_size]
                    results = await asyncio.gather(*batch)
                    
                    for url, local_path in results:
                        if local_path:
                            self.downloaded_files[url] = local_path
                    
                    progress.update(task, advance=len(batch))
        
        success_count = len(self.downloaded_files)
        failed_count = len(self.js_urls) - success_count
        
        console.print(f"\n[bold green]✓ Successfully downloaded: {success_count} files[/bold green]")
        if failed_count > 0:
            console.print(f"[yellow]⚠ Failed downloads: {failed_count} files[/yellow]\n")
        else:
            console.print()
        
        return self.downloaded_files
    
    def get_downloaded_files(self) -> List[str]:
        """Get list of downloaded file paths"""
        return list(self.downloaded_files.values())


async def download_javascript_files(js_urls: List[str], output_dir: str = "js_files", max_concurrent: int = 10) -> Dict[str, str]:
    """
    Convenience function to download JavaScript files
    
    Args:
        js_urls: List of JavaScript URLs
        output_dir: Output directory
        max_concurrent: Maximum concurrent downloads
        
    Returns:
        Dictionary mapping URLs to local file paths
    """
    downloader = JavaScriptDownloader(js_urls, output_dir, max_concurrent)
    return await downloader.download_all()
