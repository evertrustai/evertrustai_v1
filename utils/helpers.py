"""
Helper Utilities - URL validation, domain extraction, file I/O
"""

import re
import json
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import List, Set


def is_valid_url(url: str) -> bool:
    """Validate if a string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except Exception:
        return ""


def normalize_url(url: str, base_url: str = "") -> str:
    """Normalize URL (handle relative paths)"""
    if not url:
        return ""
    
    # If already absolute URL
    if url.startswith(('http://', 'https://')):
        return url
    
    # If relative URL and base_url provided
    if base_url:
        return urljoin(base_url, url)
    
    return url


def deduplicate_list(items: List[str]) -> List[str]:
    """Remove duplicates while preserving order"""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def save_to_file(filepath: str, content: str, mode: str = 'w'):
    """Save content to file"""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, mode, encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error saving to {filepath}: {e}")
        return False


def save_to_json(filepath: str, data: dict):
    """Save data to JSON file"""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving JSON to {filepath}: {e}")
        return False


def load_from_file(filepath: str) -> str:
    """Load content from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return ""


def is_javascript_file(url: str) -> bool:
    """Check if URL points to a JavaScript file"""
    js_extensions = ['.js', '.jsx', '.mjs']
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # Check extension
    for ext in js_extensions:
        if path.endswith(ext):
            return True
    
    # Check common JS patterns
    if '/js/' in path or '/javascript/' in path or '/scripts/' in path:
        if not any(path.endswith(x) for x in ['.css', '.html', '.json', '.xml']):
            return True
    
    return False


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system usage"""
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    if len(filename) > 200:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:200] + ('.' + ext if ext else '')
    return filename


def extract_js_urls_from_html(html_content: str, base_url: str) -> Set[str]:
    """Extract JavaScript URLs from HTML content"""
    js_urls = set()
    
    # Pattern for script src
    script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    matches = re.findall(script_pattern, html_content, re.IGNORECASE)
    
    for match in matches:
        normalized = normalize_url(match, base_url)
        if is_javascript_file(normalized):
            js_urls.add(normalized)
    
    return js_urls


def mask_sensitive_value(value: str, show_chars: int = 4) -> str:
    """Mask sensitive value for safe display"""
    if len(value) <= show_chars * 2:
        return '*' * len(value)
    return value[:show_chars] + '*' * (len(value) - show_chars * 2) + value[-show_chars:]
