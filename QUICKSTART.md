# 🚀 Quick Start Guide

Get your AI-powered vulnerability scanner running in under 2 minutes!

## ⚡ One-Command Setup

```bash
# Clone and run in one command
git clone https://github.com/yourusername/vulnscanner.git && cd vulnscanner && pip install -r requirements.txt && python main.py example.com
```

## 🎯 Essential Commands

### Basic Security Scan

```bash
# Scan any website for vulnerabilities
python main.py yourwebsite.com
```

### Developer Pre-Production Check

```bash
# Quick security check before deployment
python main.py localhost:3000 --scan-types web --timeout 30
```

### API Security Focus

```bash
# Focus on API security (perfect for developers)
python main.py api.yoursite.com --scan-types web --batch-size 50
```

### Custom Output

```bash
# Save results to custom file
python main.py yoursite.com --output json --output-file security_report
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

API Security:
  • 5 public API endpoints detected
  • Missing rate limiting on 3 endpoints
  • CORS misconfiguration found

Security Summary:
  • High Risk: 3 technologies
  • Medium Risk: 1 technologies
  • Outdated: 4 technologies
```

## 🐳 Docker (Even Easier!)

```bash
# Run with Docker (no setup required)
docker run -it vulnscanner python main.py yoursite.com
```

## 🎯 Perfect For

- **Developers**: Pre-production security checks
- **DevOps**: CI/CD pipeline integration
- **Security Teams**: Quick vulnerability assessments
- **Startups**: Affordable security testing
- **Students**: Learning web security

## ⚡ Performance

- **Lightweight**: < 50MB Docker image
- **Fast**: Parallel scanning with configurable batch sizes
- **Efficient**: Smart caching and minimal resource usage
- **Scalable**: Handles everything from localhost to enterprise sites

## 🚨 Why Use This?

- **AI-Powered**: Intelligent risk assessment and recommendations
- **Developer-Friendly**: Simple CLI, clear output, easy integration
- **Comprehensive**: Covers all major web security vectors
- **Free & Open Source**: No licensing fees, full transparency
- **Production-Ready**: Battle-tested with real-world applications

---

**Ready to secure your web applications?** Start with `python main.py yoursite.com` and see the magic happen! ✨
