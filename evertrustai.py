"""
evertrustai - AI-Assisted Bug Bounty Reconnaissance & Scanner
Professional tool for subdomain enumeration, JavaScript analysis, and secret detection

Author: Ananthan
Email: evertrustai@gmail.com
GitHub: https://github.com/evertrustai
"""

import asyncio
import argparse
import sys
from pathlib import Path

from core.banner import display_banner, display_warning
from core.enumerator import enumerate_subdomains
from core.js_finder import discover_javascript_files
from core.js_downloader import download_javascript_files
from core.scanner import VulnerabilityScanner
from core.reporter import Reporter
from rich.console import Console

console = Console()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='evertrustai - Bug Bounty Reconnaissance & Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with all features
  python evertrustai.py -d example.com --js-scan --report
  
  # Subdomain enumeration only
  python evertrustai.py -d example.com --enum-only
  
  # JavaScript discovery only
  python evertrustai.py -d example.com --js-only
  
  # Scan existing JS files
  python evertrustai.py -d example.com --scan-dir js_files/example.com
  
  # Detailed report
  python evertrustai.py -d example.com --js-scan --report --detailed
        """
    )
    
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Target domain (e.g., example.com)'
    )
    
    parser.add_argument(
        '--enum-only',
        action='store_true',
        help='Only perform subdomain enumeration'
    )
    
    parser.add_argument(
        '--js-only',
        action='store_true',
        help='Only discover JavaScript files (requires existing subdomains)'
    )
    
    parser.add_argument(
        '--js-scan',
        action='store_true',
        help='Download and scan JavaScript files for secrets'
    )
    
    parser.add_argument(
        '--scan-dir',
        help='Scan existing directory of JS files'
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate detailed reports'
    )
    
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed findings in console'
    )
    
    parser.add_argument(
        '--max-concurrent',
        type=int,
        default=10,
        help='Maximum concurrent HTTP requests (default: 10)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='output',
        help='Output directory for results (default: output)'
    )
    
    parser.add_argument(
        '--js-dir',
        default='js_files',
        help='Directory for downloaded JS files (default: js_files)'
    )
    
    parser.add_argument(
        '--reports-dir',
        default='reports',
        help='Directory for reports (default: reports)'
    )
    
    parser.add_argument(
        '--api-key',
        help='SecurityTrails API key (optional)'
    )
    
    return parser.parse_args()


async def main():
    """Main execution flow"""
    # Parse arguments
    args = parse_arguments()
    
    # Display banner and warning
    display_banner()
    display_warning()
    
    # Ensure output directories exist
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    Path(args.js_dir).mkdir(parents=True, exist_ok=True)
    Path(args.reports_dir).mkdir(parents=True, exist_ok=True)
    
    subdomains = []
    js_files = []
    downloaded_files = {}
    findings = []
    
    try:
        # Step 1: Subdomain Enumeration
        if not args.js_only and not args.scan_dir:
            console.print("[bold cyan]═══ PHASE 1: SUBDOMAIN ENUMERATION ═══[/bold cyan]\n")
            subdomains = await enumerate_subdomains(
                domain=args.domain,
                output_dir=args.output_dir,
                api_key=args.api_key
            )
            
            if args.enum_only:
                console.print("[bold green]✓ Enumeration complete![/bold green]")
                return
        
        # Step 2: JavaScript Discovery
        if args.js_scan and not args.scan_dir:
            if not subdomains:
                # Try to load from previous enumeration
                subdomain_file = Path(args.output_dir) / "subdomains.txt"
                if subdomain_file.exists():
                    with open(subdomain_file, 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                    console.print(f"[cyan]→[/cyan] Loaded {len(subdomains)} subdomains from {subdomain_file}")
                else:
                    console.print("[red]✗[/red] No subdomains found. Run enumeration first or provide subdomains file.")
                    return
            
            console.print("\n[bold cyan]═══ PHASE 2: JAVASCRIPT DISCOVERY ═══[/bold cyan]\n")
            js_files = await discover_javascript_files(
                subdomains=subdomains,
                max_concurrent=args.max_concurrent
            )
            
            if args.js_only:
                console.print("[bold green]✓ JavaScript discovery complete![/bold green]")
                console.print(f"Found {len(js_files)} JavaScript files")
                return
        
        # Step 3: JavaScript Download
        if args.js_scan and js_files:
            console.print("\n[bold cyan]═══ PHASE 3: JAVASCRIPT DOWNLOAD ═══[/bold cyan]\n")
            downloaded_files = await download_javascript_files(
                js_urls=js_files,
                output_dir=args.js_dir,
                max_concurrent=args.max_concurrent
            )
        
        # Step 4: Vulnerability Scanning
        if args.js_scan or args.scan_dir:
            console.print("\n[bold cyan]═══ PHASE 4: VULNERABILITY SCANNING ═══[/bold cyan]\n")
            
            scanner = VulnerabilityScanner(plugins_dir="plugins")
            scanner.load_plugins()
            
            if args.scan_dir:
                # Scan existing directory
                findings = scanner.scan_directory(args.scan_dir)
            elif downloaded_files:
                # Scan downloaded files
                file_paths = list(downloaded_files.values())
                findings = scanner.scan_files(file_paths)
            else:
                console.print("[yellow]⚠[/yellow] No files to scan")
                return
        
        # Step 5: Reporting
        if args.report and findings:
            console.print("\n[bold cyan]═══ PHASE 5: REPORT GENERATION ═══[/bold cyan]\n")
            
            reporter = Reporter(findings, args.domain)
            reporter.generate_console_report(detailed=args.detailed)
            
            json_path = f"{args.reports_dir}/report.json"
            reporter.generate_json_report(json_path)
        
        elif findings:
            # Quick summary even without --report flag
            console.print("\n[bold green]✓ Scan complete![/bold green]")
            console.print(f"Total findings: {len(findings)}")
            console.print("Use --report flag for detailed output")
        
        console.print("\n[bold green]═══════════════════════════════════════[/bold green]")
        console.print("[bold green]✓ evertrustai scan completed successfully![/bold green]")
        console.print("[bold green]═══════════════════════════════════════[/bold green]\n")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]✗ Error: {str(e)}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Run async main
    asyncio.run(main())
