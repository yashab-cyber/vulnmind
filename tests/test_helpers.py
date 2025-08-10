"""
Test helper utility functions
"""

import pytest
from vulnmind.utils.helpers import (
    normalize_url,
    extract_domain, 
    is_same_domain,
    generate_random_string,
    calculate_md5,
    calculate_sha256,
    encode_base64,
    decode_base64,
    url_encode,
    url_decode,
    extract_parameters_from_url,
    build_url_with_params,
    parse_content_type,
    is_html_content,
    sanitize_filename
)


class TestHelperFunctions:
    """Test helper utility functions"""
    
    def test_normalize_url(self):
        """Test URL normalization"""
        test_cases = [
            ("https://example.com", "https://example.com/"),
            ("https://example.com/", "https://example.com/"),
            ("https://example.com/path", "https://example.com/path"),
            ("https://EXAMPLE.COM/Path", "https://example.com/Path"),
        ]
        
        for url, expected in test_cases:
            result = normalize_url(url)
            assert result == expected, f"Normalization failed for {url}"
    
    def test_extract_domain(self):
        """Test domain extraction"""
        test_cases = [
            ("https://example.com/path", "example.com"),
            ("http://subdomain.example.com:8080", "subdomain.example.com"),
            ("https://example.com", "example.com"),
        ]
        
        for url, expected in test_cases:
            result = extract_domain(url)
            assert result == expected, f"Domain extraction failed for {url}"
    
    def test_is_same_domain(self):
        """Test same domain detection"""
        test_cases = [
            ("https://example.com/page1", "https://example.com/page2", True),
            ("http://test.com", "http://test.com/path", True),
            ("https://example.com", "https://other.com", False),
        ]
        
        for url1, url2, expected in test_cases:
            result = is_same_domain(url1, url2)
            assert result == expected, f"Same domain check failed for {url1}, {url2}"
    
    def test_generate_random_string(self):
        """Test random string generation"""
        result = generate_random_string(10)
        assert len(result) == 10
        assert isinstance(result, str)
        
        # Test different charset
        result = generate_random_string(5, charset="ABC")
        assert len(result) == 5
        assert all(c in "ABC" for c in result)
    
    def test_calculate_md5(self):
        """Test MD5 calculation"""
        result = calculate_md5("test")
        assert result == "098f6bcd4621d373cade4e832627b4f6"
    
    def test_calculate_sha256(self):
        """Test SHA256 calculation"""
        result = calculate_sha256("test")
        assert result == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    
    def test_encode_decode_base64(self):
        """Test base64 encoding and decoding"""
        original = "test string"
        encoded = encode_base64(original)
        decoded = decode_base64(encoded)
        assert decoded == original
    
    def test_url_encode_decode(self):
        """Test URL encoding and decoding"""
        original = "test string with spaces"
        encoded = url_encode(original)
        decoded = url_decode(encoded)
        assert decoded == original
        assert encoded == "test%20string%20with%20spaces"
    
    def test_extract_parameters_from_url(self):
        """Test parameter extraction from URL"""
        url = "https://example.com/path?param1=value1&param2=value2"
        params = extract_parameters_from_url(url)
        assert params['param1'] == ['value1']
        assert params['param2'] == ['value2']
    
    def test_build_url_with_params(self):
        """Test URL building with parameters"""
        base = "https://example.com/path"
        params = {"param1": "value1", "param2": "value2"}
        result = build_url_with_params(base, params)
        assert "param1=value1" in result
        assert "param2=value2" in result
        assert result.startswith(base)
    
    def test_parse_content_type(self):
        """Test content type parsing"""
        content_type = "text/html; charset=utf-8"
        media_type, params = parse_content_type(content_type)
        assert media_type == "text/html"
        assert params["charset"] == "utf-8"
    
    def test_is_html_content(self):
        """Test HTML content detection"""
        assert is_html_content("text/html")
        assert is_html_content("text/html; charset=utf-8")
        assert not is_html_content("application/json")
    
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        dangerous = "file<>:\"/|?*name.txt"
        safe = sanitize_filename(dangerous)
        assert "<" not in safe
        assert ">" not in safe
        assert ":" not in safe
        assert '"' not in safe
        assert "/" not in safe
        assert "|" not in safe
        assert "?" not in safe
        assert "*" not in safe


if __name__ == "__main__":
    pytest.main([__file__])
