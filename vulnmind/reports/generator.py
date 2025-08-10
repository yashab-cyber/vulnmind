"""
Report generation for VulnMind
"""

import json
import time
from typing import List, Dict, Any
from pathlib import Path
import html

from vulnmind.core.models import ScanResult, Vulnerability, SeverityLevel
from vulnmind.utils.logger import get_logger
from vulnmind.utils.helpers import format_duration, sanitize_filename

logger = get_logger(__name__)


class ReportGenerator:
    """Base class for report generators"""
    
    def __init__(self):
        pass
    
    def generate(self, scan_result: ScanResult, output_path: str = None) -> str:
        """Generate report from scan results"""
        raise NotImplementedError


class JSONReportGenerator(ReportGenerator):
    """JSON report generator"""
    
    def generate(self, scan_result: ScanResult, output_path: str = None) -> str:
        """Generate JSON report"""
        if output_path is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            domain = scan_result.target_url.replace('https://', '').replace('http://', '').replace('/', '_')
            output_path = f"vulnmind_report_{sanitize_filename(domain)}_{timestamp}.json"
        
        report_data = scan_result.to_dict()
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report saved to: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {str(e)}")
            return ""


class HTMLReportGenerator(ReportGenerator):
    """HTML report generator"""
    
    def generate(self, scan_result: ScanResult, output_path: str = None) -> str:
        """Generate HTML report"""
        if output_path is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            domain = scan_result.target_url.replace('https://', '').replace('http://', '').replace('/', '_')
            output_path = f"vulnmind_report_{sanitize_filename(domain)}_{timestamp}.html"
        
        try:
            html_content = self._generate_html_content(scan_result)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report saved to: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}")
            return ""
    
    def _generate_html_content(self, scan_result: ScanResult) -> str:
        """Generate HTML content for report"""
        summary = scan_result.get_summary()
        
        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnMind Security Report</title>
    {self._get_css_styles()}
</head>
<body>
    <div class="container">
        {self._generate_header(scan_result)}
        {self._generate_summary(summary)}
        {self._generate_severity_chart(summary)}
        {self._generate_vulnerabilities_section(scan_result.vulnerabilities)}
        {self._generate_scan_details(scan_result)}
        {self._generate_footer()}
    </div>
    {self._get_javascript()}
</body>
</html>
        """
        
        return html_content.strip()
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML report"""
        return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        
        .summary-card h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        
        .summary-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }
        
        .severity-chart {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .severity-bar {
            display: flex;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .severity-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .severity-segment:hover {
            filter: brightness(1.1);
        }
        
        .critical { background-color: #dc3545; }
        .high { background-color: #fd7e14; }
        .medium { background-color: #ffc107; color: #333; }
        .low { background-color: #28a745; }
        .info { background-color: #6c757d; }
        
        .vulnerabilities {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .vulnerabilities h2 {
            background: #f8f9fa;
            padding: 20px;
            margin: 0;
            border-bottom: 1px solid #dee2e6;
            color: #495057;
        }
        
        .vulnerability {
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .vulnerability:last-child {
            border-bottom: none;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vuln-title {
            font-size: 1.2rem;
            font-weight: bold;
            color: #333;
        }
        
        .vuln-severity {
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-size: 0.9rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .vuln-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .vuln-detail {
            background: #f8f9fa;
            padding: 10px 15px;
            border-radius: 5px;
        }
        
        .vuln-detail strong {
            color: #667eea;
        }
        
        .vuln-description {
            margin: 15px 0;
            padding: 15px;
            background: #f1f3f4;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        
        .vuln-remediation {
            margin: 15px 0;
            padding: 15px;
            background: #d4edda;
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }
        
        .vuln-evidence {
            margin: 15px 0;
            padding: 15px;
            background: #f8d7da;
            border-radius: 5px;
            border-left: 4px solid #dc3545;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }
        
        .scan-details {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .scan-details h2 {
            color: #495057;
            margin-bottom: 20px;
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .detail-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2rem;
        }
        
        .no-vulnerabilities i {
            font-size: 3rem;
            margin-bottom: 20px;
            display: block;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .vuln-details {
                grid-template-columns: 1fr;
            }
            
            .vuln-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .vulnerability {
            animation: fadeIn 0.5s ease forwards;
        }
    </style>
        """
    
    def _generate_header(self, scan_result: ScanResult) -> str:
        """Generate header section"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_result.start_time))
        
        return f"""
        <div class="header">
            <h1>🛡️ VulnMind Security Report</h1>
            <div class="subtitle">
                Target: {html.escape(scan_result.target_url)} | Generated: {timestamp}
            </div>
        </div>
        """
    
    def _generate_summary(self, summary: Dict[str, Any]) -> str:
        """Generate summary section"""
        duration_str = format_duration(summary.get('scan_duration', 0))
        
        return f"""
        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{summary['total_vulnerabilities']}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="value">{duration_str}</div>
            </div>
            <div class="summary-card">
                <h3>Critical Issues</h3>
                <div class="value" style="color: #dc3545;">{summary['severity_breakdown']['critical']}</div>
            </div>
            <div class="summary-card">
                <h3>High Risk Issues</h3>
                <div class="value" style="color: #fd7e14;">{summary['severity_breakdown']['high']}</div>
            </div>
        </div>
        """
    
    def _generate_severity_chart(self, summary: Dict[str, Any]) -> str:
        """Generate severity chart"""
        severity_counts = summary['severity_breakdown']
        total = summary['total_vulnerabilities']
        
        if total == 0:
            return ""
        
        # Calculate percentages
        percentages = {
            severity: (count / total) * 100 
            for severity, count in severity_counts.items()
        }
        
        chart_html = """
        <div class="severity-chart">
            <h2>Vulnerability Severity Distribution</h2>
            <div class="severity-bar">
        """
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            percentage = percentages.get(severity, 0)
            
            if percentage > 0:
                chart_html += f"""
                <div class="severity-segment {severity}" 
                     style="flex: {percentage};" 
                     title="{severity.title()}: {count} ({percentage:.1f}%)">
                    {count if percentage > 10 else ''}
                </div>
                """
        
        chart_html += """
            </div>
        </div>
        """
        
        return chart_html
    
    def _generate_vulnerabilities_section(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate vulnerabilities section"""
        if not vulnerabilities:
            return """
            <div class="vulnerabilities">
                <h2>Vulnerabilities Found</h2>
                <div class="no-vulnerabilities">
                    <i>✅</i>
                    <div>No vulnerabilities found! Your application appears to be secure.</div>
                </div>
            </div>
            """
        
        # Sort vulnerabilities by severity
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        
        sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.severity, 5))
        
        vulns_html = """
        <div class="vulnerabilities">
            <h2>Vulnerabilities Found</h2>
        """
        
        for vuln in sorted_vulns:
            vulns_html += self._generate_vulnerability_card(vuln)
        
        vulns_html += "</div>"
        
        return vulns_html
    
    def _generate_vulnerability_card(self, vuln: Vulnerability) -> str:
        """Generate individual vulnerability card"""
        return f"""
        <div class="vulnerability">
            <div class="vuln-header">
                <div class="vuln-title">{html.escape(vuln.vuln_type.value.replace('_', ' ').title())}</div>
                <div class="vuln-severity {vuln.severity.value}">{vuln.severity.value.upper()}</div>
            </div>
            
            <div class="vuln-details">
                <div class="vuln-detail">
                    <strong>URL:</strong><br>
                    {html.escape(vuln.url)}
                </div>
                <div class="vuln-detail">
                    <strong>Parameter:</strong><br>
                    {html.escape(vuln.parameter)}
                </div>
                <div class="vuln-detail">
                    <strong>Confidence:</strong><br>
                    {vuln.confidence:.2f} ({self._confidence_label(vuln.confidence)})
                </div>
                <div class="vuln-detail">
                    <strong>Detected By:</strong><br>
                    {html.escape(vuln.detected_by)}
                </div>
            </div>
            
            {f'<div class="vuln-description"><strong>Description:</strong><br>{html.escape(vuln.description)}</div>' if vuln.description else ''}
            
            {f'<div class="vuln-evidence"><strong>Evidence:</strong><br>{html.escape(vuln.evidence)}</div>' if vuln.evidence else ''}
            
            {f'<div class="vuln-remediation"><strong>Remediation:</strong><br>{html.escape(vuln.remediation)}</div>' if vuln.remediation else ''}
            
            {self._generate_vuln_metadata(vuln)}
        </div>
        """
    
    def _generate_vuln_metadata(self, vuln: Vulnerability) -> str:
        """Generate vulnerability metadata section"""
        metadata_html = ""
        
        if vuln.cvss_score or vuln.cwe_id or vuln.references:
            metadata_html = '<div class="vuln-details">'
            
            if vuln.cvss_score:
                metadata_html += f"""
                <div class="vuln-detail">
                    <strong>CVSS Score:</strong><br>
                    {vuln.cvss_score:.1f}
                </div>
                """
            
            if vuln.cwe_id:
                metadata_html += f"""
                <div class="vuln-detail">
                    <strong>CWE ID:</strong><br>
                    <a href="https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html" target="_blank">
                        CWE-{vuln.cwe_id}
                    </a>
                </div>
                """
            
            metadata_html += '</div>'
            
            if vuln.references:
                metadata_html += '<div class="vuln-detail"><strong>References:</strong><br>'
                for ref in vuln.references:
                    metadata_html += f'<a href="{html.escape(ref)}" target="_blank">{html.escape(ref)}</a><br>'
                metadata_html += '</div>'
        
        return metadata_html
    
    def _confidence_label(self, confidence: float) -> str:
        """Get confidence label"""
        if confidence >= 0.9:
            return "Very High"
        elif confidence >= 0.7:
            return "High"
        elif confidence >= 0.5:
            return "Medium"
        elif confidence >= 0.3:
            return "Low"
        else:
            return "Very Low"
    
    def _generate_scan_details(self, scan_result: ScanResult) -> str:
        """Generate scan details section"""
        stats = scan_result.scan_stats
        
        return f"""
        <div class="scan-details">
            <h2>Scan Details</h2>
            <div class="details-grid">
                <div class="detail-item">
                    <strong>Target URL:</strong><br>
                    {html.escape(scan_result.target_url)}
                </div>
                <div class="detail-item">
                    <strong>Scan Duration:</strong><br>
                    {format_duration(scan_result.duration or 0)}
                </div>
                <div class="detail-item">
                    <strong>Requests Sent:</strong><br>
                    {stats.get('requests_sent', 0)}
                </div>
                <div class="detail-item">
                    <strong>Scan Efficiency:</strong><br>
                    {stats.get('scan_efficiency', 0):.2%}
                </div>
                <div class="detail-item">
                    <strong>Average Response Time:</strong><br>
                    {stats.get('avg_response_time', 0):.2f}s
                </div>
                <div class="detail-item">
                    <strong>False Positive Rate:</strong><br>
                    {stats.get('false_positive_rate', 0):.2%}
                </div>
            </div>
        </div>
        """
    
    def _generate_footer(self) -> str:
        """Generate footer section"""
        return f"""
        <div class="footer">
            <p>Generated by VulnMind v1.0.0 - AI-Powered Self-Aware DAST Scanner</p>
            <p>Report generated on {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        """
    
    def _get_javascript(self) -> str:
        """Get JavaScript for interactive features"""
        return """
        <script>
            // Add smooth scrolling and interactive features
            document.addEventListener('DOMContentLoaded', function() {
                // Add click handlers for severity segments
                const segments = document.querySelectorAll('.severity-segment');
                segments.forEach(segment => {
                    segment.addEventListener('click', function() {
                        const severity = this.className.split(' ')[1];
                        const vulnerabilities = document.querySelectorAll('.vulnerability');
                        
                        vulnerabilities.forEach(vuln => {
                            const vulnSeverity = vuln.querySelector('.vuln-severity').textContent.toLowerCase();
                            if (vulnSeverity === severity.toUpperCase()) {
                                vuln.style.display = vuln.style.display === 'none' ? 'block' : 'none';
                            }
                        });
                    });
                });
                
                // Add tooltips
                const elements = document.querySelectorAll('[title]');
                elements.forEach(element => {
                    element.addEventListener('mouseenter', function(e) {
                        // Simple tooltip implementation
                        const tooltip = document.createElement('div');
                        tooltip.textContent = this.title;
                        tooltip.style.cssText = `
                            position: absolute;
                            background: rgba(0,0,0,0.8);
                            color: white;
                            padding: 5px 10px;
                            border-radius: 4px;
                            font-size: 0.8rem;
                            pointer-events: none;
                            z-index: 1000;
                        `;
                        document.body.appendChild(tooltip);
                        
                        const rect = this.getBoundingClientRect();
                        tooltip.style.left = rect.left + 'px';
                        tooltip.style.top = (rect.top - tooltip.offsetHeight - 5) + 'px';
                        
                        this.addEventListener('mouseleave', function() {
                            document.body.removeChild(tooltip);
                        }, { once: true });
                        
                        this.title = ''; // Remove original title to prevent double tooltip
                    });
                });
            });
        </script>
        """


def create_report_generator(format_type: str) -> ReportGenerator:
    """Factory function to create report generator"""
    if format_type.lower() == 'json':
        return JSONReportGenerator()
    elif format_type.lower() == 'html':
        return HTMLReportGenerator()
    else:
        raise ValueError(f"Unsupported report format: {format_type}")


def generate_report(scan_result: ScanResult, format_type: str = 'json', output_path: str = None) -> str:
    """Generate report from scan results"""
    generator = create_report_generator(format_type)
    return generator.generate(scan_result, output_path)
