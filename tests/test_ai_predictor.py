#!/usr/bin/env python3
"""
Unit tests for AI predictor module
"""

import pytest
from vulnscan_ai.config import ScanResult
from vulnscan_ai.ai.predictor import VulnerabilityPredictor, predict_vulnerabilities


class TestVulnerabilityPredictor:
    """Test VulnerabilityPredictor class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.predictor = VulnerabilityPredictor()
    
    def test_init(self):
        """Test predictor initialization"""
        assert self.predictor is not None
        assert hasattr(self.predictor, 'vulnerability_patterns')
        assert hasattr(self.predictor, 'risk_indicators')
    
    def test_vulnerability_patterns(self):
        """Test vulnerability patterns are loaded"""
        patterns = self.predictor.vulnerability_patterns
        
        # Check that key vulnerability types are present
        assert 'sql_injection' in patterns
        assert 'xss' in patterns
        assert 'path_traversal' in patterns
        assert 'command_injection' in patterns
        
        # Check pattern structure
        for vuln_type, pattern_data in patterns.items():
            assert 'patterns' in pattern_data
            assert 'severity' in pattern_data
            assert 'confidence' in pattern_data
            assert isinstance(pattern_data['patterns'], list)
            assert len(pattern_data['patterns']) > 0
    
    def test_risk_indicators(self):
        """Test risk indicators are loaded"""
        indicators = self.predictor.risk_indicators
        
        # Check that key indicator types are present
        assert 'high_risk_technologies' in indicators
        assert 'outdated_versions' in indicators
        assert 'dangerous_ports' in indicators
        assert 'sensitive_paths' in indicators
        
        # Check indicator structure
        assert isinstance(indicators['high_risk_technologies'], list)
        assert isinstance(indicators['dangerous_ports'], list)
        assert isinstance(indicators['sensitive_paths'], list)
    
    def test_predict_vulnerabilities_empty_results(self):
        """Test prediction with empty results"""
        results = []
        predictions = self.predictor.predict_vulnerabilities(results)
        assert predictions == []
    
    def test_predict_vulnerabilities_web_scan(self):
        """Test prediction with web scan results"""
        # Create mock web scan result
        web_result = ScanResult(
            target="example.com",
            scan_type="web",
            findings=[
                {
                    "description": "Form without CSRF protection found",
                    "severity": "high",
                    "category": "csrf"
                },
                {
                    "description": "Missing X-Frame-Options header",
                    "severity": "medium",
                    "category": "headers"
                }
            ],
            timestamp="2024-01-01T00:00:00",
            severity="high",
            confidence=0.8
        )
        
        predictions = self.predictor.predict_vulnerabilities([web_result])
        
        # Should have predictions for the findings
        assert len(predictions) > 0
        
        # Check prediction structure
        for prediction in predictions:
            assert 'type' in prediction
            assert 'severity' in prediction
            assert 'confidence' in prediction
            assert 'description' in prediction
            assert 'recommendation' in prediction
            assert 'category' in prediction
    
    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        # Create mock results
        results = [
            ScanResult(
                target="example.com",
                scan_type="web",
                findings=[
                    {"description": "Critical vulnerability", "severity": "critical"},
                    {"description": "High vulnerability", "severity": "high"},
                    {"description": "Medium vulnerability", "severity": "medium"}
                ],
                timestamp="2024-01-01T00:00:00",
                severity="critical",
                confidence=0.9
            )
        ]
        
        predictions = [
            {
                "type": "SQL Injection",
                "severity": "high",
                "confidence": 0.8,
                "category": "injection"
            }
        ]
        
        risk_analysis = self.predictor.calculate_risk_score(results, predictions)
        
        # Check risk analysis structure
        assert 'total_score' in risk_analysis
        assert 'base_score' in risk_analysis
        assert 'prediction_score' in risk_analysis
        assert 'risk_level' in risk_analysis
        assert 'predictions_count' in risk_analysis
        
        # Check score calculation
        assert risk_analysis['total_score'] > 0
        assert risk_analysis['base_score'] > 0
        assert risk_analysis['predictions_count'] == 1
        assert risk_analysis['risk_level'] in ['Critical', 'High', 'Medium', 'Low', 'Minimal']
    
    def test_generate_security_recommendations(self):
        """Test security recommendations generation"""
        predictions = [
            {
                "type": "SQL Injection",
                "severity": "high",
                "confidence": 0.8,
                "category": "injection"
            },
            {
                "type": "XSS",
                "severity": "high",
                "confidence": 0.7,
                "category": "xss"
            }
        ]
        
        recommendations = self.predictor.generate_security_recommendations(predictions)
        
        # Should have recommendations
        assert len(recommendations) > 0
        
        # Check recommendation structure
        for rec in recommendations:
            assert isinstance(rec, str)
            assert len(rec) > 0


class TestPredictVulnerabilitiesFunction:
    """Test main prediction function"""
    
    def test_predict_vulnerabilities_function(self):
        """Test the main prediction function"""
        # Create mock results
        results = [
            ScanResult(
                target="example.com",
                scan_type="web",
                findings=[
                    {"description": "Test finding", "severity": "medium", "category": "test"}
                ],
                timestamp="2024-01-01T00:00:00",
                severity="medium",
                confidence=0.7
            )
        ]
        
        analysis = predict_vulnerabilities(results)
        
        # Check analysis structure
        assert 'predictions' in analysis
        assert 'risk_analysis' in analysis
        assert 'recommendations' in analysis
        assert 'summary' in analysis
        
        # Check that all components are present
        assert isinstance(analysis['predictions'], list)
        assert isinstance(analysis['recommendations'], list)
        assert isinstance(analysis['summary'], str)
        assert len(analysis['summary']) > 0
