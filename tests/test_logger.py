#!/usr/bin/env python3
"""
Unit tests for logger module
"""

import pytest
import tempfile
import os
from vulnscan_ai.utils.logger import VulnScanLogger, log


class TestVulnScanLogger:
    """Test VulnScanLogger class"""
    
    def test_logger_initialization(self):
        """Test logger initialization"""
        logger = VulnScanLogger("test_logger")
        
        assert logger.logger.name == "test_logger"
        assert logger.logger.level == 20  # INFO level
    
    def test_logger_with_file(self):
        """Test logger with file output"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            logger = VulnScanLogger("test_logger", log_file=tmp_path)
            
            # Test that file was created
            assert os.path.exists(tmp_path)
            
            # Test logging
            logger.info("Test message")
            
            # Check that message was written to file
            with open(tmp_path, 'r') as f:
                content = f.read()
                assert "Test message" in content
        
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def test_structured_logging(self):
        """Test structured logging with extra data"""
        logger = VulnScanLogger("test_logger")
        
        # Test info logging with extra data
        logger.info("Test message", extra_field="extra_value")
        
        # Test warning logging
        logger.warning("Warning message", severity="high")
        
        # Test error logging
        logger.error("Error message", error_code=500)
        
        # Test debug logging
        logger.debug("Debug message", debug_info="debug_value")
        
        # Test critical logging
        logger.critical("Critical message", critical_info="critical_value")
    
    def test_scan_specific_logging(self):
        """Test scan-specific logging methods"""
        logger = VulnScanLogger("test_logger")
        
        # Test scan start logging
        logger.scan_start("example.com", ["web", "ssl"], threads=10)
        
        # Test scan complete logging
        logger.scan_complete("example.com", 5, 30.5, risk_level="high")
        
        # Test finding detected logging
        logger.finding_detected("XSS", "high", "example.com", url="/test")
        
        # Test scanner error logging
        logger.scanner_error("web", "Connection timeout", "example.com", retry_count=3)


class TestBackwardCompatibility:
    """Test backward compatibility functions"""
    
    def test_log_function(self):
        """Test backward compatible log function"""
        # Test basic logging
        log("Test message")
        
        # Test logging with level
        log("Warning message", level="warning")
        
        # Test logging with extra data
        log("Info message", level="info", extra_data="test_value")
