import subprocess
import asyncio
import json
from datetime import datetime
from typing import List, Dict
from config import ScannerConfig, ScanResult

async def scan(config: ScannerConfig) -> ScanResult:
    """Run Nikto scan and parse results"""
    findings = []
    
    try:
        from rich.console import Console
        console = Console()
        
        console.print("[yellow]  → Starting Nikto web server scan...[/yellow]")
        # Run Nikto scan
        cmd = [
            "nikto",
            "-h", config.target,
            "-Format", "json",
    "-o", "nikto_results.json",
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        console.print("[yellow]  → Nikto scan in progress (this may take a few minutes)...[/yellow]")
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            # Parse Nikto results
            try:
                with open("nikto_results.json", "r") as f:
                    results = f.read()
                    
                # Try to parse as JSON first
                try:
                    nikto_data = json.loads(results)
                    if isinstance(nikto_data, dict) and 'vulnerabilities' in nikto_data:
                        for vuln in nikto_data['vulnerabilities']:
                            findings.append({
                                'description': f"Nikto: {vuln.get('description', 'Vulnerability found')}",
                                'severity': 'high' if 'OSVDB' in str(vuln) else 'medium',
                                'category': 'nikto'
                            })
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    if "OSVDB" in results:
                        findings.append({
                            'description': "Nikto found potential vulnerabilities (OSVDB entries)",
                            'severity': 'high',
                            'category': 'nikto'
                        })
                    
                    if "robots.txt" in results:
                        findings.append({
                            'description': "robots.txt file found",
                            'severity': 'info',
                            'category': 'nikto'
                        })
                    
                    if "Server" in results:
                        findings.append({
                            'description': "Server information disclosure",
                            'severity': 'medium',
                            'category': 'nikto'
                        })
                    
                    if "X-Frame-Options" in results:
                        findings.append({
                            'description': "Missing X-Frame-Options header",
                            'severity': 'medium',
                            'category': 'nikto'
                        })
                    
                    if "XSS" in results:
                        findings.append({
                            'description': "Potential XSS vulnerability detected",
                            'severity': 'high',
                            'category': 'nikto'
                        })
                    
                    if "SQL" in results:
                        findings.append({
                            'description': "Potential SQL injection vulnerability detected",
                            'severity': 'high',
                            'category': 'nikto'
                        })
            except FileNotFoundError:
                findings.append({
                    'description': "Nikto scan completed but no results file found",
                    'severity': 'info',
                    'category': 'nikto'
                })
        else:
            # Nikto scan failed
            stderr_text = stderr.decode() if stderr else "Unknown error"
            findings.append({
                'description': f"Nikto scan failed: {stderr_text}",
                'severity': 'low',
                'category': 'nikto'
            })
        
        return ScanResult(
            target=config.target,
            scan_type="nikto",
            findings=findings,
            timestamp=datetime.now().isoformat(),
            severity="high" if any(f.get('severity') == 'high' for f in findings) else "medium",
            confidence=0.9
        )
        
    except Exception as e:
        return ScanResult(
            target=config.target,
            scan_type="nikto",
            findings=[{'description': f"Error during Nikto scan: {str(e)}"}],
            timestamp=datetime.now().isoformat(),
            severity="error",
            confidence=0.0
        )
