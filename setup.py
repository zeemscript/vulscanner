#!/usr/bin/env python3
"""
Setup script for AI-Powered Vulnerability Scanner PyPI package
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vulnscan-ai",
    version="1.0.0",
    author="Abdulhazeem",
    author_email="sakariyahabdulhazeem@gmail.com",
    description="AI-Powered Vulnerability Scanner for web applications",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/zeemscript/vulnscanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "vulnscan=vulnscan_ai.main:main",
        ],
    },
    keywords="security, vulnerability, scanner, web, penetration-testing, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/zeemscript/vulnscanner/issues",
        "Source": "https://github.com/zeemscript/vulnscanner",
        "Documentation": "https://github.com/zeemscript/vulnscanner#readme",
    },
)
