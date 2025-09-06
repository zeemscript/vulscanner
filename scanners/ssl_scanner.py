import ssl
import socket
import asyncio
from datetime import datetime
from typing import List, Dict
from config import ScannerConfig, ScanResult

async def check_ssl(config: ScannerConfig) -> ScanResult:
    """Check SSL/TLS configuration and vulnerabilities"""
    findings = []
    
    try:
        from rich.console import Console
        console = Console()
        
        console.print("[yellow]  → Creating SSL context...[/yellow]")
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        console.print("[yellow]  → Connecting to SSL endpoint...[/yellow]")
        # Connect to the target
        with socket.create_connection((config.target, 443), timeout=config.timeout) as sock:
            console.print("[yellow]  → Performing SSL handshake...[/yellow]")
            with context.wrap_socket(sock, server_hostname=config.target) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                if cert:
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        findings.append({
                            'description': "SSL certificate has expired",
                            'severity': 'high'
                        })
                
                # Check SSL/TLS version
                version = ssock.version()
                if version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                    findings.append({
                        'description': f"Outdated SSL/TLS version: {version}",
                        'severity': 'high'
                    })
                
                # Check cipher suite
                cipher = ssock.cipher()
                if cipher:
                    findings.append({
                        'description': f"Using cipher suite: {cipher[0]}",
                        'severity': 'info'
                    })
        
        return ScanResult(
            target=config.target,
            scan_type="ssl",
            findings=findings,
            timestamp=datetime.now().isoformat(),
            severity="high" if any(f.get('severity') == 'high' for f in findings) else "medium",
            confidence=0.9
        )
        
    except ssl.SSLError as e:
        return ScanResult(
            target=config.target,
            scan_type="ssl",
            findings=[{'description': f"SSL Error: {str(e)}"}],
            timestamp=datetime.now().isoformat(),
            severity="high",
            confidence=0.9
        )
    except Exception as e:
        return ScanResult(
            target=config.target,
            scan_type="ssl",
            findings=[{'description': f"Error during SSL scan: {str(e)}"}],
            timestamp=datetime.now().isoformat(),
            severity="error",
            confidence=0.0
        ) 