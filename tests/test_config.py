#!/usr/bin/env python3
"""
Unit tests for configuration module
"""

import pytest
from vulnscan_ai.config import ScannerConfig, ScanResult, default_config


class TestScannerConfig:
    """Test ScannerConfig class"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ScannerConfig(target="example.com")
        
        assert config.target == "example.com"
        assert config.threads == 10
        assert config.timeout == 30
        assert config.user_agent == "Mozilla/5.0 (compatible; VulnScanner/1.0)"
        assert config.scan_types == ["port", "web", "ssl", "dns"]
        assert config.output_format == "json"
        assert config.web_scan_batch_size == 20
    
    def test_custom_config(self):
        """Test custom configuration values"""
        config = ScannerConfig(
            target="test.com",
            threads=5,
            timeout=60,
            scan_types=["web", "ssl"],
            output_format="html"
        )
        
        assert config.target == "test.com"
        assert config.threads == 5
        assert config.timeout == 60
        assert config.scan_types == ["web", "ssl"]
        assert config.output_format == "html"
    
    def test_validation_errors(self):
        """Test configuration validation"""
        # Test invalid thread count
        with pytest.raises(ValueError):
            ScannerConfig(target="test.com", threads=0)
        
        with pytest.raises(ValueError):
            ScannerConfig(target="test.com", threads=100)
        
        # Test invalid timeout
        with pytest.raises(ValueError):
            ScannerConfig(target="test.com", timeout=1)
        
        with pytest.raises(ValueError):
            ScannerConfig(target="test.com", timeout=500)
        
        # Test invalid output format
        with pytest.raises(ValueError):
            ScannerConfig(target="test.com", output_format="invalid")
        
        # Test invalid batch size
        with pytest.raises(ValueError):
            ScannerConfig(target="test.com", web_scan_batch_size=1)
        
        with pytest.raises(ValueError):
            ScannerConfig(target="test.com", web_scan_batch_size=200)


class TestScanResult:
    """Test ScanResult class"""
    
    def test_scan_result_creation(self):
        """Test creating a scan result"""
        findings = [
            {"description": "Test finding", "severity": "high", "category": "test"}
        ]
        
        result = ScanResult(
            target="example.com",
            scan_type="web",
            findings=findings,
            timestamp="2024-01-01T00:00:00",
            severity="high",
            confidence=0.8
        )
        
        assert result.target == "example.com"
        assert result.scan_type == "web"
        assert len(result.findings) == 1
        assert result.findings[0]["description"] == "Test finding"
        assert result.severity == "high"
        assert result.confidence == 0.8
    
    def test_confidence_validation(self):
        """Test confidence validation"""
        # Test valid confidence values
        result = ScanResult(
            target="test.com",
            scan_type="web",
            findings=[],
            timestamp="2024-01-01T00:00:00",
            severity="low",
            confidence=0.0
        )
        assert result.confidence == 0.0
        
        result = ScanResult(
            target="test.com",
            scan_type="web",
            findings=[],
            timestamp="2024-01-01T00:00:00",
            severity="low",
            confidence=1.0
        )
        assert result.confidence == 1.0
        
        # Test invalid confidence values
        with pytest.raises(ValueError):
            ScanResult(
                target="test.com",
                scan_type="web",
                findings=[],
                timestamp="2024-01-01T00:00:00",
                severity="low",
                confidence=-0.1
            )
        
        with pytest.raises(ValueError):
            ScanResult(
                target="test.com",
                scan_type="web",
                findings=[],
                timestamp="2024-01-01T00:00:00",
                severity="low",
                confidence=1.1
            )


class TestDefaultConfig:
    """Test default configuration"""
    
    def test_default_config_values(self):
        """Test default configuration values"""
        assert default_config.target == ""
        assert default_config.threads == 10
        assert default_config.timeout == 30
        assert default_config.scan_types == ["port", "web", "ssl", "dns"]
        assert default_config.output_format == "json"
