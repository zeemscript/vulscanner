import json
from typing import List, Dict, Any
from datetime import datetime
from config import ScanResult

class VulnerabilityAnalyzer:
    """AI-powered vulnerability analysis and recommendations"""
    
    def __init__(self):
        self.risk_patterns = {
            'critical': {
                'keywords': ['exposed', 'accessible', 'vulnerable', 'critical', 'severe'],
                'weight': 10
            },
            'high': {
                'keywords': ['missing', 'enabled', 'found', 'high', 'serious'],
                'weight': 7
            },
            'medium': {
                'keywords': ['potential', 'consider', 'medium', 'moderate'],
                'weight': 4
            },
            'low': {
                'keywords': ['info', 'detected', 'low', 'minor'],
                'weight': 2
            }
        }
        
        self.recommendations = {
            'ssl': [
                "Implement HTTPS redirect for all HTTP traffic",
                "Configure HSTS header with appropriate max-age",
                "Use strong SSL/TLS configuration",
                "Regularly update SSL certificates"
            ],
            'headers': [
                "Implement Content Security Policy (CSP)",
                "Add X-Frame-Options to prevent clickjacking",
                "Configure X-Content-Type-Options",
                "Set up Referrer-Policy header",
                "Implement Permissions-Policy for feature control"
            ],
            'api_endpoints': [
                "Implement proper authentication for all API endpoints",
                "Use rate limiting to prevent abuse",
                "Validate all input parameters",
                "Implement proper error handling",
                "Use HTTPS for all API communications"
            ],
            'sensitive_files': [
                "Remove or secure access to sensitive files",
                "Implement proper file access controls",
                "Use .htaccess or similar to block access",
                "Move sensitive files outside web root"
            ],
            'framework': [
                "Keep all frameworks and libraries updated",
                "Regularly check for security patches",
                "Use dependency scanning tools",
                "Implement Content Security Policy"
            ],
            'csrf': [
                "Implement CSRF tokens for all forms",
                "Use SameSite cookie attribute",
                "Validate request origin",
                "Implement proper session management"
            ],
            'xss': [
                "Sanitize all user inputs",
                "Use Content Security Policy",
                "Avoid inline scripts",
                "Implement proper output encoding"
            ],
            'information_disclosure': [
                "Remove or modify server information headers",
                "Configure error pages to not reveal system info",
                "Use generic error messages",
                "Implement proper logging without sensitive data"
            ]
        }

    def analyze_risk_score(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Calculate overall risk score and provide analysis"""
        total_score = 0
        category_scores = {}
        technology_risks = {}
        
        for result in results:
            for finding in result.findings:
                severity = finding.get('severity', 'medium')
                category = finding.get('category', 'general')
                
                # Calculate score based on severity
                score = self.risk_patterns.get(severity, {}).get('weight', 1)
                total_score += score
                
                # Track category scores
                if category not in category_scores:
                    category_scores[category] = 0
                category_scores[category] += score
                
                # Track technology-specific risks
                if 'technologies' in finding:
                    for tech in finding.get('technologies', []):
                        tech_name = tech.get('name', 'Unknown')
                        if tech_name not in technology_risks:
                            technology_risks[tech_name] = []
                        technology_risks[tech_name].append(finding['description'])
        
        # Determine overall risk level
        if total_score >= 50:
            risk_level = "Critical"
        elif total_score >= 30:
            risk_level = "High"
        elif total_score >= 15:
            risk_level = "Medium"
        elif total_score >= 5:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            'total_score': total_score,
            'risk_level': risk_level,
            'category_scores': category_scores,
            'technology_risks': technology_risks
        }

    def generate_recommendations(self, results: List[ScanResult]) -> List[str]:
        """Generate specific recommendations based on findings"""
        recommendations = []
        categories_found = set()
        
        for result in results:
            for finding in result.findings:
                category = finding.get('category', 'general')
                categories_found.add(category)
        
        # Add recommendations for each category found
        for category in categories_found:
            if category in self.recommendations:
                recommendations.extend(self.recommendations[category])
        
        # Add general recommendations
        recommendations.extend([
            "Conduct regular security assessments",
            "Implement a security monitoring solution",
            "Train development team on secure coding practices",
            "Establish incident response procedures",
            "Keep all systems and dependencies updated"
        ])
        
        return list(set(recommendations))  # Remove duplicates

    def generate_executive_summary(self, results: List[ScanResult]) -> str:
        """Generate an executive summary of the scan results"""
        risk_analysis = self.analyze_risk_score(results)
        total_findings = sum(len(result.findings) for result in results)
        
        # Count findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in results:
            for finding in result.findings:
                severity = finding.get('severity', 'medium')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        summary = f"""
EXECUTIVE SUMMARY

Target: {results[0].target if results else 'N/A'}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Overall Risk Level: {risk_analysis['risk_level']}
Risk Score: {risk_analysis['total_score']}/100

FINDINGS OVERVIEW:
• Total Findings: {total_findings}
• Critical: {severity_counts['critical']}
• High: {severity_counts['high']}
• Medium: {severity_counts['medium']}
• Low: {severity_counts['low']}
• Informational: {severity_counts['info']}

KEY INSIGHTS:
"""
        
        # Add insights based on findings
        if severity_counts['critical'] > 0:
            summary += "• CRITICAL: Immediate action required for critical vulnerabilities\n"
        if severity_counts['high'] > 0:
            summary += "• HIGH: Significant security risks that need prompt attention\n"
        if risk_analysis['category_scores'].get('ssl', 0) > 0:
            summary += "• SSL/TLS: Security configuration issues detected\n"
        if risk_analysis['category_scores'].get('api_endpoints', 0) > 0:
            summary += "• API: Exposed endpoints may pose security risks\n"
        if risk_analysis['technology_risks']:
            summary += f"• Technologies: {len(risk_analysis['technology_risks'])} different technologies detected\n"
        
        return summary

    def generate_technical_report(self, results: List[ScanResult]) -> str:
        """Generate detailed technical report"""
        risk_analysis = self.analyze_risk_score(results)
        recommendations = self.generate_recommendations(results)
        
        report = f"""
TECHNICAL VULNERABILITY REPORT

{self.generate_executive_summary(results)}

DETAILED ANALYSIS:
"""
        
        # Add category analysis
        for category, score in risk_analysis['category_scores'].items():
            if score > 0:
                report += f"\n{category.upper()} CATEGORY (Score: {score}):\n"
                report += f"• Risk Level: {'High' if score >= 10 else 'Medium' if score >= 5 else 'Low'}\n"
                if category in self.recommendations:
                    report += f"• Key Recommendations:\n"
                    for rec in self.recommendations[category][:3]:  # Top 3 recommendations
                        report += f"  - {rec}\n"
        
        # Add technology analysis
        if risk_analysis['technology_risks']:
            report += f"\nTECHNOLOGY ANALYSIS:\n"
            for tech, risks in risk_analysis['technology_risks'].items():
                report += f"\n{tech}:\n"
                for risk in risks[:3]:  # Top 3 risks
                    report += f"  - {risk}\n"
        
        # Add recommendations
        report += f"\nRECOMMENDATIONS:\n"
        for i, rec in enumerate(recommendations[:10], 1):  # Top 10 recommendations
            report += f"{i}. {rec}\n"
        
        return report

def analyze_scan_results(results: List[ScanResult]) -> Dict[str, Any]:
    """Main analysis function"""
    analyzer = VulnerabilityAnalyzer()
    
    return {
        'risk_analysis': analyzer.analyze_risk_score(results),
        'recommendations': analyzer.generate_recommendations(results),
        'executive_summary': analyzer.generate_executive_summary(results),
        'technical_report': analyzer.generate_technical_report(results)
    }
