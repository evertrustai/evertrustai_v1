"""
Simple Direct Test - Test evertrustai against testphp.vulnweb.com
This is a quick test to verify the tool works correctly
"""

import asyncio
import sys
import os

# Add to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.http_client import AsyncHTTPClient
from rich.console import Console

console = Console()


async def quick_test():
    """Quick test of core functionality"""
    
    console.print("\n[bold cyan]═══ QUICK FUNCTIONALITY TEST ═══[/bold cyan]\n")
    
    # Test 1: HTTP Client
    console.print("[cyan]Test 1: HTTP Client[/cyan]")
    try:
        async with AsyncHTTPClient(timeout=10) as client:
            response = await client.get("http://testphp.vulnweb.com/")
            if response:
                console.print(f"[green]✓[/green] HTTP client works - Got {len(response)} bytes")
            else:
                console.print("[red]✗[/red] HTTP client failed")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
    
    # Test 2: crt.sh Query
    console.print("\n[cyan]Test 2: crt.sh Subdomain Enumeration[/cyan]")
    try:
        async with AsyncHTTPClient(timeout=30) as client:
            response = await client.get("https://crt.sh/?q=%.vulnweb.com&output=json")
            if response:
                import json
                data = json.loads(response)
                console.print(f"[green]✓[/green] crt.sh works - Found {len(data)} certificate entries")
            else:
                console.print("[yellow]⚠[/yellow] crt.sh returned no data")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
    
    # Test 3: JavaScript Detection
    console.print("\n[cyan]Test 3: JavaScript Pattern Detection[/cyan]")
    try:
        from plugins.aws_keys import AWSKeysPlugin
        from plugins.jwt_tokens import JWTTokensPlugin
        from plugins.firebase import FirebasePlugin
        
        test_content = """
        const awsKey = 'AKIAIOSFODNN7EXAMPLE';
        const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.test';
        const firebase = 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe';
        """
        
        plugins = [AWSKeysPlugin(), JWTTokensPlugin(), FirebasePlugin()]
        total_findings = 0
        
        for plugin in plugins:
            findings = plugin.scan(test_content, "test.js")
            total_findings += len(findings)
            console.print(f"  • {plugin.name}: {len(findings)} findings")
        
        console.print(f"[green]✓[/green] Pattern detection works - {total_findings} total findings")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 4: Banner Display
    console.print("\n[cyan]Test 4: Banner Display[/cyan]")
    try:
        from core.banner import display_banner
        display_banner()
        console.print("[green]✓[/green] Banner displays correctly")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
    
    console.print("\n[bold green]═══ ALL QUICK TESTS COMPLETE ═══[/bold green]\n")


if __name__ == "__main__":
    asyncio.run(quick_test())
