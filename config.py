from pydantic import BaseModel, Field
from typing import List, Optional
import os
from dotenv import load_dotenv

load_dotenv()

class ScannerConfig(BaseModel):
    """Configuration for vulnerability scanner"""
    target: str
    threads: int = Field(default=10, ge=1, le=50)
    timeout: int = Field(default=30, ge=5, le=300)
    user_agent: str = "Mozilla/5.0 (compatible; VulnScanner/1.0)"
    scan_types: List[str] = Field(default=["port", "web", "ssl", "dns"])
    output_format: str = Field(default="json", pattern="^(json|html|txt)$")
    
    # Performance settings
    web_scan_batch_size: int = Field(default=20, ge=5, le=100, description="Number of parallel requests for web scanning")
    
    # API Keys and sensitive data
    shodan_api_key: Optional[str] = Field(default=os.getenv("SHODAN_API_KEY"))
    virustotal_api_key: Optional[str] = Field(default=os.getenv("VIRUSTOTAL_API_KEY"))
    
    class Config:
        env_prefix = "VULNSCANNER_"

class ScanResult(BaseModel):
    """Model for scan results"""
    target: str
    scan_type: str
    findings: List[dict]
    timestamp: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)

# Default configuration
default_config = ScannerConfig(
    target="",
    threads=10,
    timeout=30,
    scan_types=["port", "web", "ssl", "dns"],
    output_format="json"
)
