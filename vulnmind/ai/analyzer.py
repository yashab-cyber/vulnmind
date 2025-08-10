"""
AI analysis module for VulnMind
"""

import asyncio
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from vulnmind.core.models import Vulnerability, SeverityLevel, VulnType
from vulnmind.utils.logger import get_logger

logger = get_logger(__name__)


class AIAnalyzer:
    """AI-powered vulnerability analysis and enhancement"""
    
    def __init__(self, api_key: str = None, model: str = "gpt-4", temperature: float = 0.1):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.client = None
        self.learning_data = []
        
        if api_key:
            try:
                import openai
                self.client = openai.AsyncOpenAI(api_key=api_key)
            except ImportError:
                logger.warning("OpenAI library not installed. AI features disabled.")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
    
    async def analyze_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Analyze and enhance vulnerability findings using AI"""
        if not self.client or not vulnerabilities:
            return vulnerabilities
        
        logger.info(f"Starting AI analysis of {len(vulnerabilities)} vulnerabilities")
        
        try:
            # Group vulnerabilities by type for batch analysis
            vuln_groups = self._group_vulnerabilities(vulnerabilities)
            
            enhanced_vulns = []
            
            for vuln_type, vulns in vuln_groups.items():
                enhanced_group = await self._analyze_vulnerability_group(vuln_type, vulns)
                enhanced_vulns.extend(enhanced_group)
            
            # Perform final risk assessment
            enhanced_vulns = await self._assess_overall_risk(enhanced_vulns)
            
            logger.info(f"AI analysis completed. Enhanced {len(enhanced_vulns)} vulnerabilities")
            
            return enhanced_vulns
            
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return vulnerabilities
    
    def _group_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by type for efficient analysis"""
        groups = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vuln_type.value
            if vuln_type not in groups:
                groups[vuln_type] = []
            groups[vuln_type].append(vuln)
        return groups
    
    async def _analyze_vulnerability_group(self, vuln_type: str, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Analyze a group of similar vulnerabilities"""
        if len(vulnerabilities) == 1:
            return [await self._analyze_single_vulnerability(vulnerabilities[0])]
        
        # For multiple vulnerabilities of same type, analyze for false positives and duplicates
        return await self._analyze_vulnerability_cluster(vuln_type, vulnerabilities)
    
    async def _analyze_single_vulnerability(self, vulnerability: Vulnerability) -> Vulnerability:
        """Analyze a single vulnerability in detail"""
        prompt = self._create_single_vuln_prompt(vulnerability)
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ]
            )
            
            analysis = self._parse_ai_response(response.choices[0].message.content)
            return self._apply_ai_analysis(vulnerability, analysis)
            
        except Exception as e:
            logger.error(f"Single vulnerability analysis failed: {str(e)}")
            return vulnerability
    
    async def _analyze_vulnerability_cluster(self, vuln_type: str, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Analyze multiple vulnerabilities of the same type"""
        prompt = self._create_cluster_prompt(vuln_type, vulnerabilities)
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ]
            )
            
            analysis = self._parse_cluster_response(response.choices[0].message.content)
            return self._apply_cluster_analysis(vulnerabilities, analysis)
            
        except Exception as e:
            logger.error(f"Vulnerability cluster analysis failed: {str(e)}")
            return vulnerabilities
    
    def _create_single_vuln_prompt(self, vulnerability: Vulnerability) -> str:
        """Create prompt for single vulnerability analysis"""
        return f"""
Analyze this security vulnerability and provide detailed assessment:

Vulnerability Type: {vulnerability.vuln_type.value}
Severity: {vulnerability.severity.value}
URL: {vulnerability.url}
Parameter: {vulnerability.parameter}
Payload: {vulnerability.payload}
Evidence: {vulnerability.evidence}
Confidence: {vulnerability.confidence}

Please provide:
1. Validate if this is a true positive or false positive
2. Assess the actual risk level (critical/high/medium/low/info)
3. Provide exploitation difficulty (trivial/easy/moderate/hard)
4. Suggest specific remediation steps
5. Estimate business impact
6. Rate the overall confidence (0.0-1.0)

Respond in JSON format:
{{
    "is_valid": true/false,
    "severity": "critical|high|medium|low|info",
    "confidence": 0.0-1.0,
    "exploitation_difficulty": "trivial|easy|moderate|hard",
    "business_impact": "critical|high|medium|low",
    "remediation": "specific remediation steps",
    "technical_details": "detailed technical explanation",
    "cvss_score": 0.0-10.0,
    "exploitability": 0.0-1.0
}}
        """
    
    def _create_cluster_prompt(self, vuln_type: str, vulnerabilities: List[Vulnerability]) -> str:
        """Create prompt for vulnerability cluster analysis"""
        vuln_data = []
        for i, vuln in enumerate(vulnerabilities):
            vuln_data.append({
                "id": i,
                "url": vuln.url,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "evidence": vuln.evidence,
                "confidence": vuln.confidence
            })
        
        return f"""
Analyze these {len(vulnerabilities)} {vuln_type} vulnerabilities for duplicates and false positives:

{json.dumps(vuln_data, indent=2)}

Please provide:
1. Identify which vulnerabilities are duplicates
2. Rank vulnerabilities by exploitability
3. Identify potential false positives
4. Suggest which vulnerabilities to prioritize
5. Group related vulnerabilities

Respond in JSON format:
{{
    "duplicates": [[0,1], [2,3]],
    "false_positives": [4, 5],
    "priority_ranking": [0, 2, 1, 3],
    "groups": {{"group_1": [0,1], "group_2": [2,3]}},
    "recommendations": "overall recommendations"
}}
        """
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for AI analysis"""
        return """
You are a cybersecurity expert specializing in web application security testing. 
Your job is to analyze vulnerability findings from automated security scans and provide 
accurate assessments to reduce false positives and improve remediation guidance.

Key principles:
- Be conservative with severity ratings
- Focus on actual exploitability
- Consider business context
- Provide actionable remediation advice
- Identify patterns that suggest false positives
- Always respond in valid JSON format
        """
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI response for single vulnerability analysis"""
        try:
            # Extract JSON from response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_text = response_text[start_idx:end_idx]
                return json.loads(json_text)
            
            return {}
        except Exception as e:
            logger.error(f"Failed to parse AI response: {str(e)}")
            return {}
    
    def _parse_cluster_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI response for vulnerability cluster analysis"""
        return self._parse_ai_response(response_text)
    
    def _apply_ai_analysis(self, vulnerability: Vulnerability, analysis: Dict[str, Any]) -> Vulnerability:
        """Apply AI analysis to enhance vulnerability"""
        if not analysis:
            return vulnerability
        
        # Update confidence based on AI assessment
        if 'confidence' in analysis:
            vulnerability.confidence = min(max(analysis['confidence'], 0.0), 1.0)
        
        # Update severity if AI suggests different level
        if 'severity' in analysis and analysis['is_valid']:
            try:
                new_severity = SeverityLevel(analysis['severity'])
                vulnerability.severity = new_severity
            except ValueError:
                pass
        
        # Add CVSS score if provided
        if 'cvss_score' in analysis:
            vulnerability.cvss_score = analysis['cvss_score']
        
        # Enhance remediation advice
        if 'remediation' in analysis and analysis['remediation']:
            ai_remediation = analysis['remediation']
            vulnerability.remediation = f"{vulnerability.remediation}\n\nAI-Enhanced Guidance: {ai_remediation}"
        
        # Add technical details to description
        if 'technical_details' in analysis and analysis['technical_details']:
            vulnerability.description = f"{vulnerability.description}\n\nTechnical Analysis: {analysis['technical_details']}"
        
        # Mark as false positive if AI determines it's not valid
        if analysis.get('is_valid') is False:
            vulnerability.confidence = 0.1
            vulnerability.description = f"[POTENTIAL FALSE POSITIVE] {vulnerability.description}"
        
        return vulnerability
    
    def _apply_cluster_analysis(self, vulnerabilities: List[Vulnerability], analysis: Dict[str, Any]) -> List[Vulnerability]:
        """Apply cluster analysis to group of vulnerabilities"""
        if not analysis:
            return vulnerabilities
        
        result_vulns = vulnerabilities.copy()
        
        # Mark false positives
        if 'false_positives' in analysis:
            for idx in analysis['false_positives']:
                if 0 <= idx < len(result_vulns):
                    result_vulns[idx].confidence = 0.1
                    result_vulns[idx].description = f"[POTENTIAL FALSE POSITIVE] {result_vulns[idx].description}"
        
        # Handle duplicates by keeping only the highest confidence one
        if 'duplicates' in analysis:
            to_remove = set()
            for duplicate_group in analysis['duplicates']:
                if len(duplicate_group) > 1:
                    # Keep the one with highest confidence
                    best_idx = max(duplicate_group, key=lambda i: result_vulns[i].confidence if i < len(result_vulns) else 0)
                    for idx in duplicate_group:
                        if idx != best_idx and 0 <= idx < len(result_vulns):
                            to_remove.add(idx)
            
            # Remove duplicates (in reverse order to maintain indices)
            for idx in sorted(to_remove, reverse=True):
                if idx < len(result_vulns):
                    result_vulns.pop(idx)
        
        return result_vulns
    
    async def _assess_overall_risk(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Perform overall risk assessment across all vulnerabilities"""
        if not vulnerabilities or len(vulnerabilities) < 2:
            return vulnerabilities
        
        # Create risk assessment prompt
        risk_data = []
        for i, vuln in enumerate(vulnerabilities):
            risk_data.append({
                "id": i,
                "type": vuln.vuln_type.value,
                "severity": vuln.severity.value,
                "url": vuln.url,
                "confidence": vuln.confidence
            })
        
        prompt = f"""
Perform overall security risk assessment for this web application based on these vulnerabilities:

{json.dumps(risk_data, indent=2)}

Provide:
1. Overall security posture (critical/high/medium/low)
2. Primary attack vectors
3. Recommended prioritization order
4. Risk correlation analysis

Respond in JSON format:
{{
    "overall_risk": "critical|high|medium|low",
    "primary_vectors": ["vector1", "vector2"],
    "priority_order": [0, 2, 1, 3],
    "risk_correlations": {{"explanation": "details"}},
    "executive_summary": "brief summary for management"
}}
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ]
            )
            
            risk_analysis = self._parse_ai_response(response.choices[0].message.content)
            
            # Apply risk assessment insights
            if 'priority_order' in risk_analysis:
                # Adjust confidence based on priority
                for priority, vuln_idx in enumerate(risk_analysis['priority_order']):
                    if 0 <= vuln_idx < len(vulnerabilities):
                        # Higher priority = higher confidence boost
                        boost = 0.1 * (len(risk_analysis['priority_order']) - priority) / len(risk_analysis['priority_order'])
                        vulnerabilities[vuln_idx].confidence = min(1.0, vulnerabilities[vuln_idx].confidence + boost)
            
        except Exception as e:
            logger.error(f"Overall risk assessment failed: {str(e)}")
        
        return vulnerabilities
    
    async def suggest_remediation(self, vulnerability: Vulnerability, context: Dict[str, Any] = None) -> str:
        """Generate specific remediation advice for a vulnerability"""
        if not self.client:
            return vulnerability.remediation
        
        context_info = ""
        if context:
            context_info = f"\nContext: {json.dumps(context, indent=2)}"
        
        prompt = f"""
Generate specific, actionable remediation advice for this vulnerability:

Type: {vulnerability.vuln_type.value}
URL: {vulnerability.url}
Parameter: {vulnerability.parameter}
Payload: {vulnerability.payload}
Evidence: {vulnerability.evidence}
{context_info}

Provide:
1. Immediate fix steps
2. Code examples (if applicable)
3. Prevention strategies
4. Testing recommendations
5. Additional security measures

Format as detailed markdown.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert providing remediation guidance."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Remediation suggestion failed: {str(e)}")
            return vulnerability.remediation
    
    def learn_from_scan(self, vulnerabilities: List[Vulnerability], scan_results: Dict[str, Any]):
        """Learn from scan results to improve future analysis"""
        learning_entry = {
            'timestamp': asyncio.get_event_loop().time(),
            'vulnerability_count': len(vulnerabilities),
            'severity_distribution': self._calculate_severity_distribution(vulnerabilities),
            'false_positive_indicators': self._identify_false_positive_patterns(vulnerabilities),
            'scan_efficiency': scan_results.get('scan_efficiency', 0),
            'payload_effectiveness': self._analyze_payload_effectiveness(vulnerabilities)
        }
        
        self.learning_data.append(learning_entry)
        
        # Keep only recent learning data
        if len(self.learning_data) > 100:
            self.learning_data = self.learning_data[-100:]
    
    def _calculate_severity_distribution(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Calculate distribution of vulnerability severities"""
        distribution = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            distribution[severity] = distribution.get(severity, 0) + 1
        return distribution
    
    def _identify_false_positive_patterns(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Identify patterns that might indicate false positives"""
        patterns = []
        
        for vuln in vulnerabilities:
            if vuln.confidence < 0.3:
                patterns.append(f"Low confidence {vuln.vuln_type.value} in parameter {vuln.parameter}")
        
        return patterns
    
    def _analyze_payload_effectiveness(self, vulnerabilities: List[Vulnerability]) -> Dict[str, float]:
        """Analyze which payloads were most effective"""
        payload_success = {}
        
        for vuln in vulnerabilities:
            if vuln.payload:
                key = f"{vuln.vuln_type.value}:{vuln.payload[:50]}"
                if key not in payload_success:
                    payload_success[key] = []
                payload_success[key].append(vuln.confidence)
        
        # Calculate average confidence per payload
        effectiveness = {}
        for key, confidences in payload_success.items():
            effectiveness[key] = sum(confidences) / len(confidences)
        
        return effectiveness


def create_ai_analyzer(api_key: str = None, **kwargs) -> Optional[AIAnalyzer]:
    """Factory function to create AI analyzer"""
    if not api_key:
        return None
    
    return AIAnalyzer(api_key=api_key, **kwargs)
