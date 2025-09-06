import socket
import asyncio
from typing import List, Dict
from datetime import datetime
from config import ScannerConfig, ScanResult
import nmap
import sys
import concurrent.futures

class PortScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.findings: List[Dict] = []
        # Common ports to scan
        self.common_ports = {
            20: "FTP (Data)",
            21: "FTP (Control)",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        # Potentially dangerous ports
        self.dangerous_ports = {
            23: "Telnet - Unencrypted remote access",
            445: "SMB - Windows file sharing",
            3389: "RDP - Remote Desktop Protocol",
            1433: "MSSQL - Microsoft SQL Server",
            3306: "MySQL - Database server",
            5432: "PostgreSQL - Database server"
        }
        
        # Unnecessary ports for web servers
        self.unnecessary_web_ports = {
            20: "FTP (Data) - File transfer",
            21: "FTP (Control) - File transfer",
            23: "Telnet - Remote access",
            25: "SMTP - Mail server",
            110: "POP3 - Mail server",
            143: "IMAP - Mail server",
            3389: "RDP - Remote Desktop",
            1433: "MSSQL - Database",
            3306: "MySQL - Database",
            5432: "PostgreSQL - Database"
        }

    def check_port(self, port: int) -> bool:
        """Check if a port is open using socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((self.config.target, port))
            sock.close()
            return result == 0
        except:
            return False

    async def scan_ports_socket(self) -> List[int]:
        """Scan for open ports using socket with thread pool"""
        open_ports = []
        
        # Use ThreadPoolExecutor for parallel port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # Create a list of futures
            future_to_port = {
                executor.submit(self.check_port, port): port 
                for port in self.common_ports.keys()
            }
            
            # Process completed futures
            for future in concurrent.futures.as_completed(future_to_port, timeout=30):  # 30 second overall timeout
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    continue
        
        return open_ports

    async def scan_ports_nmap(self) -> List[Dict]:
        """Scan for open ports using nmap"""
        try:
            nm = nmap.PortScanner()
            # Focus on most common ports first
            ports = "20-25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
            
            # Run the scan with service and version detection
            nm.scan(self.config.target, ports, arguments="-sS -sV -T4 --min-rate=1000 --max-retries=2 --host-timeout=30s")
            
            findings = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            service = nm[host][proto][port]['name']
                            version = nm[host][proto][port].get('version', 'unknown')
                            product = nm[host][proto][port].get('product', 'unknown')
                            
                            # Check if it's a dangerous port
                            if port in self.dangerous_ports:
                                findings.append({
                                    'description': f"Potentially dangerous port {port} ({self.dangerous_ports[port]}) is open running {service} {product} {version}",
                                    'severity': 'high'
                                })
                            # Check if it's an unnecessary port for web servers
                            elif port in self.unnecessary_web_ports:
                                findings.append({
                                    'description': f"Unnecessary port {port} ({self.unnecessary_web_ports[port]}) is open running {service} {product} {version}",
                                    'severity': 'medium'
                                })
                            # Regular port information
                            else:
                                findings.append({
                                    'description': f"Port {port} ({self.common_ports.get(port, 'Unknown')}) is open running {service} {product} {version}",
                                    'severity': 'low'
                                })
            
            return findings
        except Exception as e:
            if "requires root privileges" in str(e):
                return []  # Return empty list to trigger fallback to socket scanning
            raise e

    def analyze_ports(self, open_ports: List[int]):
        """Analyze open ports for security issues"""
        for port in open_ports:
            if port in self.dangerous_ports:
                self.findings.append({
                    'description': f"Potentially dangerous port {port} ({self.dangerous_ports[port]}) is open",
                    'severity': 'high'
                })
            
            if port in self.unnecessary_web_ports:
                self.findings.append({
                    'description': f"Unnecessary port {port} ({self.unnecessary_web_ports[port]}) is open for a web server",
                    'severity': 'medium'
                })
            
            if port in self.common_ports:
                self.findings.append({
                    'description': f"Port {port} ({self.common_ports[port]}) is open",
                    'severity': 'low'
                })

    async def scan(self) -> ScanResult:
        """Perform port scan"""
        try:
            from rich.console import Console
            console = Console()
            
            # Try nmap first
            console.print("[yellow]  → Attempting nmap port scan...[/yellow]")
            nmap_findings = await self.scan_ports_nmap()
            
            if nmap_findings:
                # If nmap scan was successful, use its findings
                console.print("[yellow]  → nmap scan completed successfully[/yellow]")
                self.findings = nmap_findings
            else:
                # Fall back to socket-based scanning
                console.print("[yellow]  → Falling back to socket-based port scanning...[/yellow]")
                console.print(f"[yellow]  → Scanning {len(self.common_ports)} common ports...[/yellow]")
                open_ports = await self.scan_ports_socket()
                console.print(f"[yellow]  → Found {len(open_ports)} open ports[/yellow]")
                self.analyze_ports(open_ports)
                
                if not open_ports:
                    self.findings.append({
                        'description': "No common ports were found open",
                        'severity': 'low'
                    })
            
            return ScanResult(
                target=self.config.target,
                scan_type="port",
                findings=self.findings,
                timestamp=datetime.now().isoformat(),
                severity="high" if any(f.get('severity') == 'high' for f in self.findings) else "medium",
                confidence=0.9
            )
            
        except Exception as e:
            return ScanResult(
                target=self.config.target,
                scan_type="port",
                findings=[{'description': f"Error during port scan: {str(e)}"}],
                timestamp=datetime.now().isoformat(),
                severity="error",
                confidence=0.0
            )

async def scan(config: ScannerConfig) -> ScanResult:
    """Entry point for port scanning"""
    scanner = PortScanner(config)
    return await scanner.scan() 