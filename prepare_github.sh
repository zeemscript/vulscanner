#!/bin/bash

# 🚀 GitHub Repository Preparation Script
# This script prepares your project for GitHub by copying only the public files

echo "🚀 Preparing AI-Powered Vulnerability Scanner for GitHub..."

# Create public directory if it doesn't exist
mkdir -p public

# Copy public files (files that should be in the GitHub repo)
echo "📁 Copying public files..."

# Core project files
cp README_PUBLIC.md public/README.md
cp QUICKSTART.md public/
cp CONTRIBUTING.md public/
cp LICENSE public/
cp .gitignore public/

# Python files
cp main.py public/
cp config.py public/
cp requirements.txt public/
cp setup.py public/
cp test_scanner.py public/

# Docker files
cp Dockerfile public/
cp docker-compose.yml public/

# Directories
cp -r scanners public/
cp -r ai public/
cp -r utils public/
cp -r .github public/

echo "✅ Public files copied to 'public/' directory"
echo ""
echo "📋 Files in public directory:"
ls -la public/

echo ""
echo "🚫 Files NOT included (personal use only):"
echo "  - SOCIAL_MEDIA_CONTENT.md"
echo "  - GITHUB_SETUP.md"
echo "  - RELEASE_TEMPLATE.md"
echo "  - README.md (original)"
echo "  - DEPLOYMENT.md"
echo "  - nginx.conf"
echo "  - All .json files (scan results)"
echo "  - nikto_results.json"
echo "  - test_output.*"
echo ""
echo "🎯 Next steps:"
echo "1. cd public/"
echo "2. git init"
echo "3. git add ."
echo "4. git commit -m 'Initial commit: AI-Powered Vulnerability Scanner'"
echo "5. Create GitHub repository"
echo "6. git remote add origin https://github.com/yourusername/vulnscanner.git"
echo "7. git push -u origin main"
echo ""
echo "✨ Your project is ready for GitHub!"
