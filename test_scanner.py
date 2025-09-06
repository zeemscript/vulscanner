#!/usr/bin/env python3
"""
Test script for the AI-Powered Vulnerability Scanner
"""

import asyncio
from config import ScannerConfig
from scanners import web_scan, port_scan, ssl_scan, dns_scan
from ai.summary import analyze_scan_results
from ai.predictor import predict_vulnerabilities

async def test_scanner():
    """Test the scanner with a safe target"""
    print("🧪 Testing AI-Powered Vulnerability Scanner")
    print("=" * 50)
    
    # Create test configuration
    config = ScannerConfig(
        target="httpbin.org",  # Safe test target
        threads=5,
        timeout=10,
        scan_types=["web", "ssl", "dns"],  # Skip port and nikto for safety
        output_format="json"
    )
    
    print(f"Target: {config.target}")
    print(f"Scan types: {config.scan_types}")
    print()
    
    try:
        # Test web scanner
        print("🔍 Testing web scanner...")
        web_result = await web_scan(config)
        print(f"✅ Web scan completed: {len(web_result.findings)} findings")
        
        # Test SSL scanner
        print("🔒 Testing SSL scanner...")
        ssl_result = await ssl_scan(config)
        print(f"✅ SSL scan completed: {len(ssl_result.findings)} findings")
        
        # Test DNS scanner
        print("🌐 Testing DNS scanner...")
        dns_result = await dns_scan(config)
        print(f"✅ DNS scan completed: {len(dns_result.findings)} findings")
        
        # Combine results
        results = [web_result, ssl_result, dns_result]
        
        # Test AI analysis
        print("\n🤖 Testing AI analysis...")
        analysis = analyze_scan_results(results)
        print(f"✅ AI analysis completed: Risk level {analysis['risk_analysis']['risk_level']}")
        
        # Test AI predictions
        print("🔮 Testing AI predictions...")
        predictions = predict_vulnerabilities(results)
        print(f"✅ AI predictions completed: {len(predictions['predictions'])} predictions")
        
        print("\n🎉 All tests passed successfully!")
        print(f"Total findings: {sum(len(r.findings) for r in results)}")
        print(f"Risk level: {analysis['risk_analysis']['risk_level']}")
        print(f"Risk score: {analysis['risk_analysis']['total_score']}/100")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_scanner())
    exit(0 if success else 1)
