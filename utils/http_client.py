"""
Async HTTP Client - Rate limiting, timeout handling, user-agent rotation
"""

import asyncio
import aiohttp
import random
from typing import Optional, Dict
from aiohttp import ClientTimeout


class AsyncHTTPClient:
    """Async HTTP client with rate limiting and error handling"""
    
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
    ]
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        """
        Initialize HTTP client
        
        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        self.timeout = ClientTimeout(total=timeout)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get randomized headers"""
        return {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    async def get(self, url: str, allow_redirects: bool = True) -> Optional[str]:
        """
        Perform GET request
        
        Args:
            url: Target URL
            allow_redirects: Follow redirects
            
        Returns:
            Response text or None on error
        """
        async with self.semaphore:
            try:
                if not self.session:
                    self.session = aiohttp.ClientSession(timeout=self.timeout)
                
                async with self.session.get(
                    url,
                    headers=self._get_headers(),
                    allow_redirects=allow_redirects,
                    ssl=False  # For bug bounty testing, may need to handle self-signed certs
                ) as response:
                    if response.status == 200:
                        return await response.text()
                    return None
            except asyncio.TimeoutError:
                return None
            except aiohttp.ClientError:
                return None
            except Exception:
                return None
    
    async def get_binary(self, url: str) -> Optional[bytes]:
        """
        Perform GET request for binary content
        
        Args:
            url: Target URL
            
        Returns:
            Response bytes or None on error
        """
        async with self.semaphore:
            try:
                if not self.session:
                    self.session = aiohttp.ClientSession(timeout=self.timeout)
                
                async with self.session.get(
                    url,
                    headers=self._get_headers(),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        return await response.read()
                    return None
            except Exception:
                return None
    
    async def head(self, url: str) -> bool:
        """
        Perform HEAD request to check if URL is alive
        
        Args:
            url: Target URL
            
        Returns:
            True if URL is accessible, False otherwise
        """
        async with self.semaphore:
            try:
                if not self.session:
                    self.session = aiohttp.ClientSession(timeout=self.timeout)
                
                async with self.session.head(
                    url,
                    headers=self._get_headers(),
                    allow_redirects=True,
                    ssl=False
                ) as response:
                    return response.status < 400
            except Exception:
                return False


async def fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    """
    Convenience function to fetch a single URL
    
    Args:
        url: Target URL
        timeout: Request timeout
        
    Returns:
        Response text or None
    """
    async with AsyncHTTPClient(timeout=timeout, max_concurrent=1) as client:
        return await client.get(url)


async def fetch_urls(urls: list, timeout: int = 30, max_concurrent: int = 10) -> Dict[str, Optional[str]]:
    """
    Fetch multiple URLs concurrently
    
    Args:
        urls: List of URLs to fetch
        timeout: Request timeout
        max_concurrent: Maximum concurrent requests
        
    Returns:
        Dictionary mapping URLs to their responses
    """
    async with AsyncHTTPClient(timeout=timeout, max_concurrent=max_concurrent) as client:
        tasks = [client.get(url) for url in urls]
        results = await asyncio.gather(*tasks)
        return dict(zip(urls, results))
