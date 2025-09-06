#!/usr/bin/env python3
"""
Setup script for AI-Powered Vulnerability Scanner
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Python dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python dependencies: {e}")
        return False

def install_system_dependencies():
    """Install system dependencies based on OS"""
    system = platform.system().lower()
    
    if system == "darwin":  # macOS
        print("\n🍎 Installing system dependencies for macOS...")
        try:
            # Check if Homebrew is installed
            subprocess.check_call(["which", "brew"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Install nmap and nikto
            subprocess.check_call(["brew", "install", "nmap", "nikto"])
            print("✅ System dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("❌ Homebrew not found. Please install Homebrew first:")
            print("   /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
            return False
    
    elif system == "linux":
        print("\n🐧 Installing system dependencies for Linux...")
        try:
            # Try apt (Debian/Ubuntu)
            subprocess.check_call(["sudo", "apt", "update"])
            subprocess.check_call(["sudo", "apt", "install", "-y", "nmap", "nikto"])
            print("✅ System dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            try:
                # Try yum (RHEL/CentOS)
                subprocess.check_call(["sudo", "yum", "install", "-y", "nmap", "nikto"])
                print("✅ System dependencies installed successfully")
                return True
            except subprocess.CalledProcessError:
                print("❌ Failed to install system dependencies")
                print("Please install nmap and nikto manually:")
                print("  - Debian/Ubuntu: sudo apt install nmap nikto")
                print("  - RHEL/CentOS: sudo yum install nmap nikto")
                return False
    
    else:
        print(f"❌ Unsupported operating system: {system}")
        print("Please install nmap and nikto manually for your system")
        return False

def create_env_file():
    """Create .env.example file"""
    env_example = """# AI-Powered Vulnerability Scanner Configuration
# Copy this file to .env and fill in your API keys

# Optional API keys for enhanced scanning
SHODAN_API_KEY=your_shodan_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Scanner configuration
VULNSCANNER_THREADS=10
VULNSCANNER_TIMEOUT=30
VULNSCANNER_USER_AGENT=Mozilla/5.0 (compatible; VulnScanner/1.0)
"""
    
    env_file = Path(".env.example")
    if not env_file.exists():
        with open(env_file, "w") as f:
            f.write(env_example)
        print("✅ Created .env.example file")
    else:
        print("✅ .env.example file already exists")

def test_installation():
    """Test if the installation works"""
    print("\n🧪 Testing installation...")
    try:
        # Test basic imports
        from config import ScannerConfig, ScanResult
        from scanners import web_scan, port_scan, ssl_scan, dns_scan, nikto_scan
        from ai.summary import analyze_scan_results
        from ai.predictor import predict_vulnerabilities
        print("✅ All modules imported successfully")
        
        # Test basic functionality
        config = ScannerConfig(target="example.com")
        print("✅ Configuration created successfully")
        
        return True
    except Exception as e:
        print(f"❌ Installation test failed: {e}")
        return False

def main():
    """Main setup function"""
    print("🔍 AI-Powered Vulnerability Scanner Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        sys.exit(1)
    
    # Install system dependencies
    if not install_system_dependencies():
        print("⚠️  System dependencies installation failed, but continuing...")
    
    # Create environment file
    create_env_file()
    
    # Test installation
    if not test_installation():
        print("❌ Installation test failed")
        sys.exit(1)
    
    print("\n🎉 Setup completed successfully!")
    print("\n📖 Usage:")
    print("  python main.py example.com")
    print("  python main.py example.com --scan-types web ssl --output html")
    print("  python main.py example.com --threads 20 --timeout 60")
    
    print("\n📚 For more information, see README.md")

if __name__ == "__main__":
    main()
