"""
Banner Module - Professional ASCII Art Display
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def display_banner():
    """Display the evertrustai banner with metadata"""
    
    # ASCII Art Logo - Styled similar to reference image
    logo = r"""
    ███████╗██╗   ██╗███████╗██████╗ ████████╗██████╗ ██╗   ██╗███████╗████████╗ █████╗ ██╗
    ██╔════╝██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔══██╗██║
    █████╗  ██║   ██║█████╗  ██████╔╝   ██║   ██████╔╝██║   ██║███████╗   ██║   ███████║██║
    ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██╔══██║██║
    ███████╗ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║  ██║██║
    ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝
    """
    
    # Create styled text
    banner_text = Text()
    banner_text.append(logo, style="bold cyan")
    banner_text.append("\n")
    banner_text.append("    🔐 ", style="bold yellow")
    banner_text.append("evertrustai – AI-Assisted Bug Bounty Recon & Scanner\n", style="bold white")
    banner_text.append("    ⚡ ", style="bold yellow")
    banner_text.append("Reconnaissance | JavaScript Analysis | Secret Detection | Reporting\n", style="bold white")
    banner_text.append("    ⚠️  ", style="bold red")
    banner_text.append("AUTHORIZED TESTING ONLY\n", style="bold red")
    banner_text.append("\n")
    banner_text.append("    Version : ", style="bold green")
    banner_text.append("v1.0.0\n", style="white")
    banner_text.append("    Creator : ", style="bold green")
    banner_text.append("evertrustai\n", style="white")
    banner_text.append("    Author  : ", style="bold green")
    banner_text.append("Ananthan\n", style="white")
    banner_text.append("    Email   : ", style="bold green")
    banner_text.append("evertrustai@gmail.com\n", style="white")
    banner_text.append("    GitHub  : ", style="bold green")
    banner_text.append("https://github.com/evertrustai\n", style="cyan underline")
    
    # Display in a panel
    panel = Panel(
        banner_text,
        box=box.DOUBLE,
        border_style="bold cyan",
        padding=(1, 2)
    )
    
    console.print(panel)
    console.print()


def display_warning():
    """Display ethical usage warning"""
    warning_text = Text()
    warning_text.append("⚠️  WARNING: ", style="bold red blink")
    warning_text.append("Use only on assets you own or have explicit written permission to test.\n", style="bold yellow")
    warning_text.append("Unauthorized access to computer systems is illegal. The authors are not responsible\n", style="yellow")
    warning_text.append("for any misuse or damage caused by this tool. Always follow responsible disclosure.", style="yellow")
    
    panel = Panel(
        warning_text,
        title="[bold red]⚠️  ETHICAL USE POLICY ⚠️[/bold red]",
        border_style="bold red",
        box=box.HEAVY
    )
    
    console.print(panel)
    console.print()


if __name__ == "__main__":
    display_banner()
    display_warning()
