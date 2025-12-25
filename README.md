# evertrustai

<div align="center">

```
███████╗██╗   ██╗███████╗██████╗ ████████╗██████╗ ██╗   ██╗███████╗████████╗ █████╗ ██╗
██╔════╝██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔══██╗██║
█████╗  ██║   ██║█████╗  ██████╔╝   ██║   ██████╔╝██║   ██║███████╗   ██║   ███████║██║
██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██╔══██║██║
███████╗ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║  ██║██║
╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝
```

**🔐 AI-Assisted Bug Bounty Reconnaissance & Scanner**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/evertrustai/evertrustai)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

*Reconnaissance | JavaScript Analysis | Secret Detection | Reporting*

</div>

---

## ⚠️ ETHICAL USE WARNING

**This tool is designed for authorized security testing only.**

- ✅ Use only on assets you own or have explicit written permission to test
- ❌ Unauthorized access to computer systems is illegal
- 📋 Always follow responsible disclosure practices
- ⚖️ The authors are not responsible for any misuse or damage

**By using this tool, you agree to use it ethically and legally.**

---

## 🚀 Features

### 🔍 Subdomain Enumeration
- **Multiple Sources**: crt.sh, SecurityTrails API, assetfinder, subfinder
- **Automatic Deduplication**: Clean, unique subdomain lists
- **Export Formats**: Text and JSON output

### 📜 JavaScript Discovery
- **Intelligent Crawling**: Discovers JS files from live subdomains
- **Comprehensive Extraction**: Inline and external JavaScript
- **Async Performance**: Fast concurrent crawling

### 📥 Bulk JavaScript Download
- **Organized Storage**: Files organized by domain
- **Progress Tracking**: Real-time download progress
- **Error Handling**: Robust retry logic

### 🔐 Secret Detection
Detects 30+ types of sensitive data:
- ✅ AWS Access Keys & Secrets
- ✅ JWT Tokens
- ✅ Firebase API Keys & Config
- ✅ GitHub Tokens
- ✅ Stripe Keys
- ✅ Google API Keys
- ✅ Slack Tokens
- ✅ OAuth Tokens
- ✅ Hardcoded Passwords
- ✅ Database Credentials
- ✅ Private Keys
- ✅ Internal URLs
- ✅ GraphQL Endpoints
- ✅ Admin Endpoints
- And many more...

### 🔌 Plugin System
- **Extensible Architecture**: Easy to add custom detection rules
- **Auto-Loading**: Plugins automatically discovered and loaded
- **Modular Design**: Each plugin focuses on specific patterns

### 📊 Professional Reporting
- **Console Reports**: Beautiful, color-coded terminal output
- **JSON Reports**: Machine-readable structured data
- **Severity Classification**: Critical, High, Medium, Low
- **Detailed Context**: Line numbers, masked values, descriptions

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/evertrustai/evertrustai.git
cd evertrustai

# Install dependencies
pip install -r requirements.txt

# Optional: Install external tools for enhanced enumeration
# assetfinder (Go required)
go install github.com/tomnomnom/assetfinder@latest

# subfinder (Go required)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## 🎯 Usage

### Basic Usage

```bash
# Full scan with all features
python evertrustai.py -d example.com --js-scan --report

# Subdomain enumeration only
python evertrustai.py -d example.com --enum-only

# JavaScript discovery only
python evertrustai.py -d example.com --js-only

# Scan existing JS files
python evertrustai.py -d example.com --scan-dir js_files/example.com

# Detailed report with findings
python evertrustai.py -d example.com --js-scan --report --detailed
```

### Command Line Options

```
Required:
  -d, --domain DOMAIN          Target domain (e.g., example.com)

Scan Modes:
  --enum-only                  Only perform subdomain enumeration
  --js-only                    Only discover JavaScript files
  --js-scan                    Download and scan JavaScript files
  --scan-dir DIR               Scan existing directory of JS files

Reporting:
  --report                     Generate detailed reports
  --detailed                   Show detailed findings in console

Configuration:
  --max-concurrent N           Max concurrent requests (default: 10)
  --output-dir DIR             Output directory (default: output)
  --js-dir DIR                 JS files directory (default: js_files)
  --reports-dir DIR            Reports directory (default: reports)
  --api-key KEY                SecurityTrails API key (optional)
```

### Example Workflows

#### 1. Quick Reconnaissance
```bash
python evertrustai.py -d target.com --enum-only
```

#### 2. Full Bug Bounty Scan
```bash
python evertrustai.py -d target.com --js-scan --report --detailed
```

#### 3. Scan Specific Subdomains
```bash
# First, create a custom subdomain list
echo "api.target.com" > output/subdomains.txt
echo "app.target.com" >> output/subdomains.txt

# Then run JS scan
python evertrustai.py -d target.com --js-scan --report
```

---

## 📁 Project Structure

```
evertrustai/
├── core/
│   ├── __init__.py
│   ├── banner.py           # ASCII banner and metadata
│   ├── enumerator.py       # Subdomain enumeration
│   ├── js_finder.py        # JavaScript discovery
│   ├── js_downloader.py    # Bulk JS download
│   ├── scanner.py          # Vulnerability scanner
│   └── reporter.py         # Report generation
├── plugins/
│   ├── __init__.py
│   ├── base_plugin.py      # Plugin base class
│   ├── aws_keys.py         # AWS credential detection
│   ├── jwt_tokens.py       # JWT token detection
│   ├── firebase.py         # Firebase key detection
│   └── custom_rules.py     # Generic patterns
├── utils/
│   ├── __init__.py
│   ├── helpers.py          # Utility functions
│   └── http_client.py      # Async HTTP client
├── output/                 # Subdomain lists
├── js_files/               # Downloaded JS files
├── reports/                # JSON reports
├── evertrustai.py          # Main entry point
├── requirements.txt        # Dependencies
└── README.md               # This file
```

---

## 🔌 Creating Custom Plugins

Extend evertrustai with custom detection rules:

```python
# plugins/my_custom_plugin.py

from typing import List, Dict
from plugins.base_plugin import BasePlugin


class MyCustomPlugin(BasePlugin):
    """Detect custom patterns"""
    
    def get_patterns(self) -> List[Dict]:
        """Define your detection patterns"""
        return [
            {
                'pattern': r'your-regex-pattern-here',
                'severity': 'High',  # Critical, High, Medium, Low
                'type': 'Custom Finding Type',
                'description': 'Description of what was found'
            }
        ]
```

The plugin will be automatically loaded on next run!

---

## 📊 Output Examples

### Console Output
```
═══ PHASE 1: SUBDOMAIN ENUMERATION ═══

→ Querying crt.sh for example.com...
✓ crt.sh: Found 45 subdomains
→ Running subfinder for example.com...
✓ subfinder: Found 32 subdomains

✓ Total unique subdomains found: 67

═══ PHASE 4: VULNERABILITY SCANNING ═══

→ Loading scanner plugins...
  ✓ Loaded: AWSKeysPlugin
  ✓ Loaded: JWTTokensPlugin
  ✓ Loaded: FirebasePlugin
  ✓ Loaded: CustomRulesPlugin

✓ Loaded 4 plugins

🔍 Scanning 156 JavaScript files for vulnerabilities...
[████████████████████████] 100% (156/156)

✓ Scan complete!
  Total findings: 23
  🔴 Critical: 3
  🟠 High: 8
  🟡 Medium: 9
  🔵 Low: 3
```

### JSON Report Structure
```json
{
  "scan_metadata": {
    "target": "example.com",
    "scan_time": "2025-12-25T16:42:00",
    "total_findings": 23
  },
  "summary": {
    "by_severity": {
      "Critical": 3,
      "High": 8,
      "Medium": 9,
      "Low": 3
    }
  },
  "findings": [
    {
      "plugin": "AWSKeysPlugin",
      "severity": "Critical",
      "type": "AWS Access Key ID",
      "file": "js_files/example.com/config.js",
      "line": 42,
      "value": "AKIA****EXAMPLE****",
      "context": "const awsKey = 'AKIA...';"
    }
  ]
}
```

---

## 🛡️ Bug Bounty Best Practices

1. **Always Get Permission**: Only test on in-scope assets
2. **Read the Policy**: Understand the bug bounty program rules
3. **Rate Limiting**: Use `--max-concurrent` to avoid overwhelming targets
4. **Responsible Disclosure**: Report findings through proper channels
5. **Document Everything**: Keep detailed notes of your testing
6. **Respect Privacy**: Don't access or exfiltrate user data
7. **Follow the Law**: Comply with all applicable laws and regulations

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs**: Open an issue with details
2. **Suggest Features**: Share your ideas
3. **Submit Plugins**: Create new detection plugins
4. **Improve Documentation**: Help others understand the tool
5. **Code Contributions**: Submit pull requests

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ananthan**
- Email: evertrustai@gmail.com
- GitHub: [@evertrustai](https://github.com/evertrustai)

---

## 🙏 Acknowledgments

- Thanks to the bug bounty community for inspiration
- Built with ❤️ for ethical hackers and security researchers
- Powered by Python and open-source libraries

---

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Bug Bounty Platforms](https://www.bugcrowd.com/)
- [HackerOne](https://www.hackerone.com/)
- [Responsible Disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure)

---

<div align="center">

**⚡ Happy Hunting! ⚡**

*Remember: With great power comes great responsibility.*

</div>
