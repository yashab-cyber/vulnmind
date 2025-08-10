"""
Utility functions for VulnMind
"""

import re
import hashlib
import base64
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import random
import string


def normalize_url(url: str) -> str:
    """Normalize URL for consistent processing"""
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    parsed = urlparse(url)
    
    # Remove default ports
    if parsed.port:
        if (parsed.scheme == 'http' and parsed.port == 80) or \
           (parsed.scheme == 'https' and parsed.port == 443):
            netloc = parsed.hostname
        else:
            netloc = f"{parsed.hostname}:{parsed.port}"
    else:
        netloc = parsed.netloc
    
    # Normalize path
    path = parsed.path or '/'
    if not path.startswith('/'):
        path = f"/{path}"
    
    return urlunparse((
        parsed.scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain"""
    return extract_domain(url1) == extract_domain(url2)


def generate_random_string(length: int = 8, charset: str = None) -> str:
    """Generate random string for testing"""
    if charset is None:
        charset = string.ascii_letters + string.digits
    
    return ''.join(random.choice(charset) for _ in range(length))


def calculate_md5(text: str) -> str:
    """Calculate MD5 hash of text"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def calculate_sha256(text: str) -> str:
    """Calculate SHA256 hash of text"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def encode_base64(text: str) -> str:
    """Encode text to base64"""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')


def decode_base64(encoded: str) -> str:
    """Decode base64 text"""
    try:
        return base64.b64decode(encoded).decode('utf-8')
    except Exception:
        return ""


def url_encode(text: str) -> str:
    """URL encode text"""
    return urllib.parse.quote(text)


def url_decode(encoded: str) -> str:
    """URL decode text"""
    return urllib.parse.unquote(encoded)


def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from text using regex"""
    url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    return re.findall(url_pattern, text)


def extract_emails_from_text(text: str) -> List[str]:
    """Extract email addresses from text"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(email_pattern, text)


def extract_parameters_from_url(url: str) -> Dict[str, List[str]]:
    """Extract parameters from URL"""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url_with_params(base_url: str, params: Dict[str, str]) -> str:
    """Build URL with parameters"""
    parsed = urlparse(base_url)
    query_params = parse_qs(parsed.query)
    
    # Add new parameters
    for key, value in params.items():
        query_params[key] = [value]
    
    # Encode query string
    new_query = urlencode(query_params, doseq=True)
    
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def parse_content_type(content_type: str) -> Tuple[str, Dict[str, str]]:
    """Parse Content-Type header"""
    parts = content_type.split(';')
    media_type = parts[0].strip().lower()
    
    parameters = {}
    for part in parts[1:]:
        if '=' in part:
            key, value = part.split('=', 1)
            parameters[key.strip().lower()] = value.strip().strip('"')
    
    return media_type, parameters


def is_html_content(content_type: str) -> bool:
    """Check if content type is HTML"""
    media_type, _ = parse_content_type(content_type)
    return media_type in ['text/html', 'application/xhtml+xml']


def is_json_content(content_type: str) -> bool:
    """Check if content type is JSON"""
    media_type, _ = parse_content_type(content_type)
    return media_type in ['application/json', 'text/json']


def is_xml_content(content_type: str) -> bool:
    """Check if content type is XML"""
    media_type, _ = parse_content_type(content_type)
    return media_type in ['application/xml', 'text/xml'] or media_type.endswith('+xml')


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system usage"""
    # Remove or replace invalid characters
    invalid_chars = r'<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate string to maximum length"""
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def extract_title_from_html(html: str) -> str:
    """Extract title from HTML content"""
    title_pattern = r'<title[^>]*>(.*?)</title>'
    match = re.search(title_pattern, html, re.IGNORECASE | re.DOTALL)
    
    if match:
        title = match.group(1).strip()
        # Clean up title
        title = re.sub(r'\s+', ' ', title)  # Normalize whitespace
        return title
    
    return ""


def extract_meta_description(html: str) -> str:
    """Extract meta description from HTML"""
    pattern = r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    
    if match:
        return match.group(1).strip()
    
    return ""


def detect_encoding(content: bytes) -> str:
    """Detect content encoding"""
    try:
        import chardet
        result = chardet.detect(content)
        return result.get('encoding', 'utf-8')
    except ImportError:
        # Fallback to common encodings
        for encoding in ['utf-8', 'iso-8859-1', 'windows-1252']:
            try:
                content.decode(encoding)
                return encoding
            except UnicodeDecodeError:
                continue
        
        return 'utf-8'  # Default fallback


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.0f}s"


def format_file_size(bytes_count: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024
    
    return f"{bytes_count:.1f} PB"


def is_valid_ip(ip: str) -> bool:
    """Check if string is valid IP address"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split('.')[-1].lower() if '.' in filename else ""


def create_user_agents() -> List[str]:
    """Create list of realistic user agents"""
    return [
        # Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        
        # Mobile
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
    ]


def get_random_user_agent() -> str:
    """Get random user agent string"""
    return random.choice(create_user_agents())


def clean_html(html: str) -> str:
    """Clean HTML content for text extraction"""
    # Remove script and style content
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove HTML tags
    html = re.sub(r'<[^>]+>', '', html)
    
    # Normalize whitespace
    html = re.sub(r'\s+', ' ', html)
    
    return html.strip()


def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def generate_csrf_token(length: int = 32) -> str:
    """Generate CSRF token"""
    import secrets
    return secrets.token_urlsafe(length)


def is_suspicious_response(response_text: str, payload: str) -> bool:
    """Check if response contains suspicious content that might indicate vulnerability"""
    suspicious_patterns = [
        # Error messages
        r'error|exception|warning|failed|denied|forbidden|unauthorized',
        
        # Database errors
        r'mysql|postgresql|oracle|mssql|sqlite|database',
        
        # Path traversal indicators
        r'root:|bin/|etc/passwd|windows\\system32',
        
        # Command injection indicators
        r'uid=|gid=|command not found|permission denied',
        
        # XSS indicators in unexpected places
        r'<script|javascript:|onerror=|onload=',
        
        # Debug information
        r'debug|trace|stack.*trace|line.*\d+',
    ]
    
    response_lower = response_text.lower()
    payload_lower = payload.lower()
    
    # Check if payload is reflected and response contains suspicious patterns
    if payload.lower() in response_lower:
        for pattern in suspicious_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True
    
    return False
