import dns.resolver
import dns.zone
import dns.exception
import asyncio
from datetime import datetime
from typing import List, Dict
from config import ScannerConfig, ScanResult

async def scan(config: ScannerConfig) -> ScanResult:
    """Perform DNS security checks"""
    findings = []
    
    try:
        from rich.console import Console
        console = Console()
        
        # Check for common DNS records
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        console.print(f"[yellow]  → Querying {len(record_types)} DNS record types...[/yellow]")
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(config.target, record_type)
                for rdata in answers:
                    findings.append({
                        'description': f"Found {record_type} record: {rdata}",
                        'severity': 'info'
                    })
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                findings.append({
                    'description': f"Domain does not exist (NXDOMAIN)",
                    'severity': 'high'
                })
                break
        
        # Check for zone transfer vulnerability
        console.print("[yellow]  → Testing for zone transfer vulnerabilities...[/yellow]")
        try:
            ns_records = dns.resolver.resolve(config.target, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), config.target))
                    findings.append({
                        'description': f"Zone transfer possible from {ns}",
                        'severity': 'high'
                    })
                except:
                    continue
        except:
            pass
        
        # Check for SPF record
        try:
            spf_records = dns.resolver.resolve(config.target, 'TXT')
            has_spf = False
            for record in spf_records:
                if str(record).startswith('"v=spf1'):
                    has_spf = True
                    break
            if not has_spf:
                findings.append({
                    'description': "No SPF record found",
                    'severity': 'medium'
                })
        except:
            findings.append({
                'description': "No SPF record found",
                'severity': 'medium'
            })
        
        return ScanResult(
            target=config.target,
            scan_type="dns",
            findings=findings,
            timestamp=datetime.now().isoformat(),
            severity="high" if any(f.get('severity') == 'high' for f in findings) else "medium",
            confidence=0.9
        )
        
    except Exception as e:
        return ScanResult(
            target=config.target,
            scan_type="dns",
            findings=[{'description': f"Error during DNS scan: {str(e)}"}],
            timestamp=datetime.now().isoformat(),
            severity="error",
            confidence=0.0
        ) 