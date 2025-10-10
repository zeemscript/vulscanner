# 🚀 Quick Start Guide

Get your AI-powered vulnerability scanner running in under 2 minutes!

## ⚡ Install & Run

```bash
# Install from PyPI
pip install vulnscan-ai

# Scan any website
vulnscan example.com
```

That's it! You're now scanning for vulnerabilities! 🎉

## 🎯 Essential Commands

### Basic Security Scan

```bash
# Scan any website for vulnerabilities
vulnscan yourwebsite.com
```

### Developer Pre-Production Check

```bash
# Quick security check before deployment
vulnscan localhost:3000 --scan-types web --timeout 30
```

### API Security Focus

```bash
# Focus on API security (perfect for developers)
vulnscan api.yoursite.com --scan-types web --batch-size 50
```

### Custom Output

```bash
# Save results to custom file
vulnscan yoursite.com --output json --output-file security_report

# Generate HTML report
vulnscan yoursite.com --output html --output-file report.html
```

### High-Performance Scanning

```bash
# Use more threads and larger batch sizes for faster scanning
vulnscan yoursite.com --threads 20 --batch-size 50
```

## 🔧 What It Checks

- **Technology Stack**: Detects React, Angular, Vue, jQuery, WordPress, etc.
- **API Security**: Authentication, CORS, rate limiting, sensitive endpoints
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more
- **Vulnerabilities**: XSS, CSRF, injection attacks, information disclosure
- **Outdated Software**: Flags technologies with known security issues

## 📊 Sample Output

```
🛠️ TECHNOLOGY STACK ANALYSIS

Frontend Technologies:
  • React.js v16.8.0 [HIGH] (OUTDATED)
  • jQuery v3.4.1 [MEDIUM] (OUTDATED)

Technology Security Summary:
  • High Risk Technologies: 1
  • Medium Risk Technologies: 1
  • Low Risk Technologies: 0
  • Outdated Technologies: 2

HIGH FINDINGS:
┌────────────────────────┬───────────┬──────────┬────────────────────────────┐
│ Target                 │ Scan Type │ Category │ Finding                    │
├────────────────────────┼───────────┼──────────┼────────────────────────────┤
│ example.com            │ web       │ csrf     │ Form without CSRF protection│
└────────────────────────┴───────────┴──────────┴────────────────────────────┘

🤖 AI-POWERED ANALYSIS
Risk Level: High
Risk Score: 67/100

🔧 TOP RECOMMENDATIONS:
1. Update React.js from v16.8.0 to latest version
2. Implement rate limiting on API endpoints
3. Fix CORS configuration for production
4. Add Content Security Policy headers
5. Update jQuery to latest version
```

## 🛠️ Installation Options

### Option 1: PyPI (Recommended)

```bash
pip install vulnscan-ai
```

### Option 2: From Source

```bash
# Clone repository
git clone https://github.com/zeemscript/vulnscanner.git
cd vulnscanner

# Install in development mode
pip install -e .
```

### Prerequisites

- Python 3.8+
- nmap (for port scanning) - `brew install nmap` or `sudo apt install nmap`
- nikto (for web server scanning) - `brew install nikto` or `sudo apt install nikto`

## 🎯 Perfect For

- **Developers**: Pre-production security checks
- **DevOps**: CI/CD pipeline integration
- **Security Teams**: Quick vulnerability assessments
- **Startups**: Affordable security testing
- **Students**: Learning web security

## ⚡ Performance

- **Lightweight**: Minimal dependencies, fast startup
- **Fast**: Parallel scanning with configurable batch sizes
- **Efficient**: Smart caching and minimal resource usage
- **Scalable**: Handles everything from localhost to enterprise sites

## 🚨 Why Use VulnScan AI?

- **AI-Powered**: Intelligent risk assessment and recommendations
- **Developer-Friendly**: Simple CLI, clear output, easy integration
- **Comprehensive**: Covers all major web security vectors
- **Free & Open Source**: No licensing fees, full transparency
- **Production-Ready**: Battle-tested with real-world applications

## 🔧 Advanced Usage

```bash
# Get help
vulnscan --help

# Scan specific types only
vulnscan yoursite.com --scan-types web ssl

# Don't save results to file
vulnscan yoursite.com --no-save

# CI/CD integration
vulnscan $TARGET_URL --output json --no-save | jq '.risk_score'
```

---

**Ready to secure your web applications?** Start with `vulnscan yoursite.com` and see the magic happen! ✨
