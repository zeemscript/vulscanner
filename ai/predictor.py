import json
import re
from typing import List, Dict, Any, Tuple
from datetime import datetime
from config import ScanResult

class VulnerabilityPredictor:
    """AI-powered vulnerability prediction and risk assessment"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'sql_injection': {
                'patterns': [
                    r'(\b(union|select|insert|update|delete|drop|create|alter)\b)',
                    r'(\b(or|and)\s+\d+\s*=\s*\d+)',
                    r'(\'|\"|;|\-\-)',
                    r'(\b(exec|execute|sp_)\b)'
                ],
                'severity': 'high',
                'confidence': 0.8
            },
            'xss': {
                'patterns': [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'<iframe[^>]*>',
                    r'<object[^>]*>',
                    r'<embed[^>]*>'
                ],
                'severity': 'high',
                'confidence': 0.7
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./',
                    r'\.\.\\',
                    r'%2e%2e%2f',
                    r'%2e%2e%5c',
                    r'\.\.%2f',
                    r'\.\.%5c'
                ],
                'severity': 'high',
                'confidence': 0.9
            },
            'command_injection': {
                'patterns': [
                    r'[;&|`$]',
                    r'\b(cat|ls|dir|type|more|less|head|tail|grep|find|locate)\b',
                    r'\b(rm|del|mv|cp|chmod|chown)\b',
                    r'\b(wget|curl|nc|netcat|telnet|ssh|ftp)\b'
                ],
                'severity': 'critical',
                'confidence': 0.8
            },
            'ldap_injection': {
                'patterns': [
                    r'[()=*!]',
                    r'\b(ou|dc|cn|uid|mail|sn|givenName)\b',
                    r'\(&\([^)]+\)\)',
                    r'\(|\([^)]*\)'
                ],
                'severity': 'high',
                'confidence': 0.7
            },
            'xxe': {
                'patterns': [
                    r'<!DOCTYPE[^>]*>',
                    r'<!ENTITY[^>]*>',
                    r'&[a-zA-Z0-9_]+;',
                    r'file://',
                    r'http://',
                    r'ftp://'
                ],
                'severity': 'high',
                'confidence': 0.6
            }
        }
        
        self.risk_indicators = {
            'high_risk_technologies': [
                'WordPress', 'Drupal', 'Joomla', 'Magento',
                'phpMyAdmin', 'cPanel', 'Plesk'
            ],
            'outdated_versions': [
                'PHP 5.', 'Apache 2.2', 'IIS 6', 'IIS 7',
                'MySQL 5.5', 'PostgreSQL 9.'
            ],
            'dangerous_ports': [21, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432],
            'sensitive_paths': [
                '/admin', '/wp-admin', '/administrator', '/phpmyadmin',
                '/.git', '/.env', '/config', '/backup'
            ]
        }

    def predict_vulnerabilities(self, results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Predict potential vulnerabilities based on scan results"""
        predictions = []
        
        for result in results:
            # Analyze web scan results
            if result.scan_type == 'web':
                web_predictions = self._analyze_web_vulnerabilities(result)
                predictions.extend(web_predictions)
            
            # Analyze port scan results
            elif result.scan_type == 'port':
                port_predictions = self._analyze_port_vulnerabilities(result)
                predictions.extend(port_predictions)
            
            # Analyze SSL scan results
            elif result.scan_type == 'ssl':
                ssl_predictions = self._analyze_ssl_vulnerabilities(result)
                predictions.extend(ssl_predictions)
        
        return predictions

    def _analyze_web_vulnerabilities(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Analyze web scan results for potential vulnerabilities"""
        predictions = []
        
        for finding in result.findings:
            description = finding.get('description', '').lower()
            category = finding.get('category', '')
            
            # Check for SQL injection patterns
            if any(re.search(pattern, description, re.IGNORECASE) 
                   for pattern in self.vulnerability_patterns['sql_injection']['patterns']):
                predictions.append({
                    'type': 'SQL Injection',
                    'severity': 'high',
                    'confidence': 0.8,
                    'description': 'Potential SQL injection vulnerability detected based on patterns',
                    'recommendation': 'Implement parameterized queries and input validation',
                    'category': 'injection'
                })
            
            # Check for XSS patterns
            if any(re.search(pattern, description, re.IGNORECASE) 
                   for pattern in self.vulnerability_patterns['xss']['patterns']):
                predictions.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'high',
                    'confidence': 0.7,
                    'description': 'Potential XSS vulnerability detected',
                    'recommendation': 'Implement proper input sanitization and output encoding',
                    'category': 'xss'
                })
            
            # Check for path traversal
            if any(re.search(pattern, description, re.IGNORECASE) 
                   for pattern in self.vulnerability_patterns['path_traversal']['patterns']):
                predictions.append({
                    'type': 'Path Traversal',
                    'severity': 'high',
                    'confidence': 0.9,
                    'description': 'Potential path traversal vulnerability detected',
                    'recommendation': 'Validate and sanitize file paths',
                    'category': 'injection'
                })
            
            # Check for technology-specific vulnerabilities
            if category == 'cms':
                predictions.append({
                    'type': 'CMS Vulnerability',
                    'severity': 'medium',
                    'confidence': 0.6,
                    'description': 'CMS detected - potential for plugin/theme vulnerabilities',
                    'recommendation': 'Keep CMS and plugins updated, use security plugins',
                    'category': 'cms'
                })
            
            # Check for missing security headers
            if category == 'headers':
                predictions.append({
                    'type': 'Security Headers Missing',
                    'severity': 'medium',
                    'confidence': 0.8,
                    'description': 'Missing security headers increase attack surface',
                    'recommendation': 'Implement comprehensive security headers',
                    'category': 'headers'
                })

    def _analyze_port_vulnerabilities(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Analyze port scan results for potential vulnerabilities"""
        predictions = []
        
        for finding in result.findings:
            description = finding.get('description', '')
            severity = finding.get('severity', 'low')
            
            # Check for dangerous ports
            for port in self.risk_indicators['dangerous_ports']:
                if f'port {port}' in description.lower():
                    predictions.append({
                        'type': 'Dangerous Port Open',
                        'severity': 'high',
                        'confidence': 0.9,
                        'description': f'Port {port} is open - potential security risk',
                        'recommendation': 'Close unnecessary ports or secure them properly',
                        'category': 'network'
                    })
            
            # Check for database ports
            if any(db_port in description for db_port in ['3306', '5432', '1433']):
                predictions.append({
                    'type': 'Database Port Exposed',
                    'severity': 'critical',
                    'confidence': 0.9,
                    'description': 'Database port is accessible from outside',
                    'recommendation': 'Restrict database access to internal networks only',
                    'category': 'database'
                })

    def _analyze_ssl_vulnerabilities(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Analyze SSL scan results for potential vulnerabilities"""
        predictions = []
        
        for finding in result.findings:
            description = finding.get('description', '')
            severity = finding.get('severity', 'low')
            
            if 'expired' in description.lower():
                predictions.append({
                    'type': 'SSL Certificate Expired',
                    'severity': 'high',
                    'confidence': 1.0,
                    'description': 'SSL certificate has expired',
                    'recommendation': 'Renew SSL certificate immediately',
                    'category': 'ssl'
                })
            
            if 'outdated' in description.lower() or 'tlsv1' in description.lower():
                predictions.append({
                    'type': 'Outdated SSL/TLS Version',
                    'severity': 'high',
                    'confidence': 0.9,
                    'description': 'Using outdated SSL/TLS version',
                    'recommendation': 'Upgrade to TLS 1.2 or higher',
                    'category': 'ssl'
                })

    def calculate_risk_score(self, results: List[ScanResult], predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall risk score including predictions"""
        base_score = 0
        prediction_score = 0
        
        # Calculate base score from actual findings
        for result in results:
            for finding in result.findings:
                severity = finding.get('severity', 'low')
                if severity == 'critical':
                    base_score += 20
                elif severity == 'high':
                    base_score += 15
                elif severity == 'medium':
                    base_score += 10
                elif severity == 'low':
                    base_score += 5
        
        # Calculate prediction score
        for prediction in predictions:
            severity = prediction.get('severity', 'low')
            confidence = prediction.get('confidence', 0.5)
            
            if severity == 'critical':
                prediction_score += int(20 * confidence)
            elif severity == 'high':
                prediction_score += int(15 * confidence)
            elif severity == 'medium':
                prediction_score += int(10 * confidence)
            elif severity == 'low':
                prediction_score += int(5 * confidence)
        
        total_score = min(base_score + prediction_score, 100)
        
        # Determine risk level
        if total_score >= 80:
            risk_level = "Critical"
        elif total_score >= 60:
            risk_level = "High"
        elif total_score >= 40:
            risk_level = "Medium"
        elif total_score >= 20:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            'total_score': total_score,
            'base_score': base_score,
            'prediction_score': prediction_score,
            'risk_level': risk_level,
            'predictions_count': len(predictions)
        }

    def generate_security_recommendations(self, predictions: List[Dict[str, Any]]) -> List[str]:
        """Generate specific security recommendations based on predictions"""
        recommendations = []
        categories = set()
        
        for prediction in predictions:
            categories.add(prediction.get('category', 'general'))
        
        # Category-specific recommendations
        if 'injection' in categories:
            recommendations.extend([
                "Implement comprehensive input validation",
                "Use parameterized queries for database operations",
                "Apply output encoding for all user-generated content",
                "Implement Web Application Firewall (WAF)"
            ])
        
        if 'xss' in categories:
            recommendations.extend([
                "Implement Content Security Policy (CSP)",
                "Sanitize all user inputs",
                "Use proper output encoding",
                "Avoid inline scripts and event handlers"
            ])
        
        if 'ssl' in categories:
            recommendations.extend([
                "Upgrade to TLS 1.2 or higher",
                "Implement HSTS header",
                "Use strong cipher suites",
                "Regularly update SSL certificates"
            ])
        
        if 'network' in categories:
            recommendations.extend([
                "Close unnecessary ports",
                "Implement network segmentation",
                "Use firewall rules to restrict access",
                "Monitor network traffic"
            ])
        
        if 'database' in categories:
            recommendations.extend([
                "Restrict database access to internal networks",
                "Use strong authentication",
                "Implement database encryption",
                "Regular security updates"
            ])
        
        return list(set(recommendations))

def predict_vulnerabilities(results: List[ScanResult]) -> Dict[str, Any]:
    """Main prediction function"""
    predictor = VulnerabilityPredictor()
    
    predictions = predictor.predict_vulnerabilities(results)
    risk_analysis = predictor.calculate_risk_score(results, predictions)
    recommendations = predictor.generate_security_recommendations(predictions)
    
    return {
        'predictions': predictions,
        'risk_analysis': risk_analysis,
        'recommendations': recommendations,
        'summary': f"Found {len(predictions)} potential vulnerabilities with {risk_analysis['risk_level']} risk level"
    }
