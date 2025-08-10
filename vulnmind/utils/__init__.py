"""
Utilities package initialization
"""

from .logger import get_logger, setup_logging, create_scan_logger, log_banner, log_configuration
from .http import HttpClient
from .helpers import (
    normalize_url, extract_domain, is_same_domain, generate_random_string,
    calculate_md5, calculate_sha256, encode_base64, decode_base64,
    url_encode, url_decode, extract_urls_from_text, extract_emails_from_text,
    format_duration, format_file_size, validate_url, clean_html,
    truncate_string, sanitize_filename
)

__all__ = [
    'get_logger', 'setup_logging', 'create_scan_logger', 'log_banner', 'log_configuration',
    'HttpClient',
    'normalize_url', 'extract_domain', 'is_same_domain', 'generate_random_string',
    'calculate_md5', 'calculate_sha256', 'encode_base64', 'decode_base64',
    'url_encode', 'url_decode', 'extract_urls_from_text', 'extract_emails_from_text',
    'format_duration', 'format_file_size', 'validate_url', 'clean_html',
    'truncate_string', 'sanitize_filename'
]
