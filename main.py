import argparse
import asyncio
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import List, Optional
import shutil
import json
import os

from config import ScannerConfig, ScanResult, default_config
from scanners import (
    nikto_scan,
    port_scan,
    ssl_scan,
    dns_scan,
    web_scan
)
from ai.summary import analyze_scan_results

console = Console()

def check_required_tools():
    """Check if required tools are installed"""
    tools = {
        'nmap': 'Port scanning and service detection',
        'nikto': 'Web server scanning'
    }
    
    missing_tools = []
    for tool, description in tools.items():
        if not shutil.which(tool):
            missing_tools.append(f"{tool} ({description})")
    
    if missing_tools:
        console.print("[yellow]Warning: Some tools are not installed:[/yellow]")
        for tool in missing_tools:
            console.print(f"  - {tool}")
        console.print("\n[yellow]You can install them using:[/yellow]")
        console.print("  brew install nmap nikto")
        return False
    return True

async def run_scans_with_progress(config: ScannerConfig, progress, task_id) -> List[ScanResult]:
    """Run all enabled scans with detailed progress tracking"""
    results = []
    scan_tasks = []
    
    # Create scan tasks with progress tracking
    if "port" in config.scan_types:
        scan_tasks.append(("Port Scanning", port_scan(config)))
    if "web" in config.scan_types:
        scan_tasks.append(("Web Application Security", web_scan(config)))
    if "ssl" in config.scan_types:
        scan_tasks.append(("SSL/TLS Analysis", ssl_scan(config)))
    if "dns" in config.scan_types:
        scan_tasks.append(("DNS Security Analysis", dns_scan(config)))
    if "nikto" in config.scan_types:
        scan_tasks.append(("Nikto Web Server Scan", nikto_scan(config)))
    
    # Update progress to show total scans
    progress.update(task_id, total=len(scan_tasks))
    
    # Run scans with individual progress updates
    for i, (scan_name, scan_task) in enumerate(scan_tasks):
        progress.update(task_id, description=f"Running {scan_name}...")
        try:
            result = await scan_task
            results.append(result)
            progress.update(task_id, completed=i + 1)
            console.print(f"[green]✓ {scan_name} completed - {len(result.findings)} findings[/green]")
        except Exception as e:
            console.print(f"[red]✗ {scan_name} failed: {str(e)}[/red]")
            # Create error result
            from datetime import datetime
            error_result = ScanResult(
                target=config.target,
                scan_type=scan_name.lower().replace(" ", "_").replace("/", "_"),
                findings=[{'description': f"Scan failed: {str(e)}", 'severity': 'error'}],
                timestamp=datetime.now().isoformat(),
                severity="error",
                confidence=0.0
            )
            results.append(error_result)
            progress.update(task_id, completed=i + 1)
    
    return results

async def run_scans(config: ScannerConfig) -> List[ScanResult]:
    """Run all enabled scans concurrently (legacy function for compatibility)"""
    tasks = []
    
    if "port" in config.scan_types:
        tasks.append(port_scan(config))
    if "web" in config.scan_types:
        tasks.append(web_scan(config))
    if "ssl" in config.scan_types:
        tasks.append(ssl_scan(config))
    if "dns" in config.scan_types:
        tasks.append(dns_scan(config))
    if "nikto" in config.scan_types:
        tasks.append(nikto_scan(config))
    
    return await asyncio.gather(*tasks)

def categorize_findings(results: List[ScanResult]) -> dict:
    """Categorize findings by severity and type"""
    categories = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    for result in results:
        for finding in result.findings:
            severity = finding.get('severity', 'medium')
            if severity in categories:
                categories[severity].append({
                    'target': result.target,
                    'scan_type': result.scan_type,
                    'finding': finding
                })
    
    return categories

def display_technology_stack(results: List[ScanResult]):
    """Display detected technology stack"""
    for result in results:
        if result.scan_type == "web":
            for finding in result.findings:
                if finding.get('category') == 'technology_stack' and 'details' in finding:
                    details = finding['details']
                    console.print("\n[bold blue]🛠️  TECHNOLOGY STACK ANALYSIS[/bold blue]")
                    
                    # Display technology categories
                    if details['frontend_technologies']:
                        console.print("\n[bold cyan]Frontend Technologies:[/bold cyan]")
                        for tech in details['frontend_technologies']:
                            version_str = f" v{tech['version']}" if tech['version'] else ""
                            risk_color = "red" if tech['security_risk'] == 'high' else "yellow" if tech['security_risk'] == 'medium' else "green"
                            outdated_str = " [red](OUTDATED)[/red]" if tech['is_outdated'] else ""
                            console.print(f"  • {tech['name']}{version_str} [{risk_color}]{tech['security_risk'].upper()}[/{risk_color}]{outdated_str}")
                    
                    if details['cms_technologies']:
                        console.print("\n[bold cyan]Content Management Systems:[/bold cyan]")
                        for tech in details['cms_technologies']:
                            version_str = f" v{tech['version']}" if tech['version'] else ""
                            risk_color = "red" if tech['security_risk'] == 'high' else "yellow" if tech['security_risk'] == 'medium' else "green"
                            outdated_str = " [red](OUTDATED)[/red]" if tech['is_outdated'] else ""
                            console.print(f"  • {tech['name']}{version_str} [{risk_color}]{tech['security_risk'].upper()}[/{risk_color}]{outdated_str}")
                    
                    if details['analytics_technologies']:
                        console.print("\n[bold cyan]Analytics & Tracking:[/bold cyan]")
                        for tech in details['analytics_technologies']:
                            version_str = f" v{tech['version']}" if tech['version'] else ""
                            console.print(f"  • {tech['name']}{version_str}")
                    
                    # Display security summary
                    security = details['security_summary']
                    console.print(f"\n[bold yellow]Security Summary:[/bold yellow]")
                    console.print(f"  • High Risk: {security['high_risk']} technologies")
                    console.print(f"  • Medium Risk: {security['medium_risk']} technologies")
                    console.print(f"  • Low Risk: {security['low_risk']} technologies")
                    console.print(f"  • Outdated: {details['outdated_count']} technologies")
                    
                    break

def display_results(results: List[ScanResult]):
    """Display scan results in a formatted table"""
    # Summary panel
    total_findings = sum(len(result.findings) for result in results)
    categories = categorize_findings(results)
    
    summary_text = f"""
    Target: {results[0].target if results else 'N/A'}
    Total Findings: {total_findings}
    Critical: {len(categories['critical'])}
    High: {len(categories['high'])}
    Medium: {len(categories['medium'])}
    Low: {len(categories['low'])}
    Info: {len(categories['info'])}
    """
    
    console.print(Panel(summary_text, title="🔍 Scan Summary", border_style="blue"))
    
    # Display technology stack
    display_technology_stack(results)
    
    # Display findings by severity
    severity_colors = {
        'critical': 'red',
        'high': 'bright_red',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'green'
    }
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if categories[severity]:
            console.print(f"\n[bold {severity_colors[severity]}]{severity.upper()} FINDINGS:[/bold {severity_colors[severity]}]")
            
            table = Table(show_header=True, header_style=f"bold {severity_colors[severity]}")
            table.add_column("Target", style="cyan")
            table.add_column("Scan Type", style="magenta")
            table.add_column("Category", style="green")
            table.add_column("Finding", style="white")
            
            for item in categories[severity]:
                finding = item['finding']
                table.add_row(
                    item['target'],
                    item['scan_type'],
                    finding.get('category', 'general'),
                    finding['description']
                )
            
            console.print(table)

def save_results(results: List[ScanResult], config: ScannerConfig, custom_filename: str = None) -> str:
    """Save results to file"""
    if custom_filename:
        filename = custom_filename
        # Ensure the file has the correct extension
        if not filename.endswith(f".{config.output_format}"):
            filename = f"{filename}.{config.output_format}"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnscan_{config.target.replace('.', '_')}_{timestamp}.{config.output_format}"
    
    if config.output_format == "json":
        # Convert results to JSON-serializable format
        json_results = []
        for result in results:
            json_results.append({
                'target': result.target,
                'scan_type': result.scan_type,
                'findings': result.findings,
                'timestamp': result.timestamp,
                'severity': result.severity,
                'confidence': result.confidence
            })
        
        with open(filename, 'w') as f:
            json.dump(json_results, f, indent=2)
    
    elif config.output_format == "html":
        html_content = generate_html_report(results, config)
        with open(filename, 'w') as f:
            f.write(html_content)
    
    elif config.output_format == "txt":
        with open(filename, 'w') as f:
            f.write(f"Vulnerability Scan Report\n")
            f.write(f"Target: {config.target}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("=" * 50 + "\n\n")
            
            for result in results:
                f.write(f"Scan Type: {result.scan_type}\n")
                f.write(f"Severity: {result.severity}\n")
                f.write(f"Findings:\n")
                for finding in result.findings:
                    f.write(f"  - {finding['description']} (Severity: {finding.get('severity', 'medium')})\n")
                f.write("\n")
    
    return filename

def generate_html_report(results: List[ScanResult], config: ScannerConfig) -> str:
    """Generate HTML report"""
    categories = categorize_findings(results)
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Scan Report - {config.target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .summary {{ margin: 20px 0; }}
            .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
            .critical {{ border-left-color: #ff0000; background: #fff5f5; }}
            .high {{ border-left-color: #ff4444; background: #fff8f8; }}
            .medium {{ border-left-color: #ffaa00; background: #fffbf0; }}
            .low {{ border-left-color: #0088ff; background: #f0f8ff; }}
            .info {{ border-left-color: #00aa00; background: #f0fff0; }}
            .severity-section {{ margin: 20px 0; }}
            .severity-title {{ font-size: 18px; font-weight: bold; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Vulnerability Scan Report</h1>
            <p><strong>Target:</strong> {config.target}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total Findings: {sum(len(categories[sev]) for sev in categories)}</p>
            <p>Critical: {len(categories['critical'])} | High: {len(categories['high'])} | Medium: {len(categories['medium'])} | Low: {len(categories['low'])} | Info: {len(categories['info'])}</p>
        </div>
    """
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if categories[severity]:
            html += f'<div class="severity-section">'
            html += f'<div class="severity-title">{severity.upper()} FINDINGS</div>'
            
            for item in categories[severity]:
                finding = item['finding']
                html += f'''
                <div class="finding {severity}">
                    <strong>{item['scan_type'].upper()}</strong> - {finding.get('category', 'general')}<br>
                    {finding['description']}
                </div>
                '''
            
            html += '</div>'
    
    html += """
    </body>
    </html>
    """
    
    return html

def main():
    parser = argparse.ArgumentParser(description="🔍 AI-Powered Vulnerability Scanner")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--threads", type=int, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    parser.add_argument("--scan-types", nargs="+", choices=["port", "web", "ssl", "dns", "nikto"], 
                       help="Types of scans to run")
    parser.add_argument("--output", choices=["json", "html", "txt"], help="Output format (default: json)")
    parser.add_argument("--output-file", type=str, help="Custom output file path (optional)")
    parser.add_argument("--no-save", action="store_true", help="Don't save results to file")
    parser.add_argument("--batch-size", type=int, help="Web scan parallel batch size (5-100)")
    
    args = parser.parse_args()
    
    # Check for required tools
    if not check_required_tools():
        return 1
    
    # Update config with command line arguments
    config = default_config.model_copy()
    config.target = args.target
    if args.threads:
        config.threads = args.threads
    if args.timeout:
        config.timeout = args.timeout
    if args.scan_types:
        config.scan_types = args.scan_types
    if args.output:
        config.output_format = args.output
    if args.batch_size:
        config.web_scan_batch_size = args.batch_size
    
    try:
        console.print("[bold green]Starting comprehensive vulnerability scan...[/bold green]")
        console.print(f"[cyan]Target: {config.target}[/cyan]")
        console.print(f"[cyan]Scan types: {', '.join(config.scan_types)}[/cyan]")
        console.print(f"[cyan]Threads: {config.threads}, Timeout: {config.timeout}s, Batch size: {config.web_scan_batch_size}[/cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Initializing scans...", total=None)
            results = asyncio.run(run_scans_with_progress(config, progress, task))
        
        console.print("\n[bold green]All scans completed![/bold green]")
        console.print(f"[cyan]Total findings: {sum(len(result.findings) for result in results)}[/cyan]\n")
        
        # Display results
        display_results(results)
        
        # Save results to file
        if not args.no_save:
            filename = save_results(results, config, args.output_file)
            console.print(f"\n[bold green]Results saved to: {filename}[/bold green]")
        
        # AI-powered analysis
        console.print("\n[bold blue]🤖 AI-POWERED ANALYSIS[/bold blue]")
        analysis = analyze_scan_results(results)
        
        # Display risk analysis
        risk_analysis = analysis['risk_analysis']
        console.print(f"\n[bold]Risk Level:[/bold] {risk_analysis['risk_level']}")
        console.print(f"[bold]Risk Score:[/bold] {risk_analysis['total_score']}/100")
        
        # Display top recommendations
        recommendations = analysis['recommendations'][:5]  # Top 5
        if recommendations:
            console.print("\n[bold yellow]🔧 TOP RECOMMENDATIONS:[/bold yellow]")
            for i, rec in enumerate(recommendations, 1):
                console.print(f"{i}. {rec}")
        
        # Provide critical recommendations
        categories = categorize_findings(results)
        if categories['critical'] or categories['high']:
            console.print("\n[bold red]⚠️  CRITICAL RECOMMENDATIONS:[/bold red]")
            console.print("• Address critical and high severity findings immediately")
            console.print("• Review security headers and SSL configuration")
            console.print("• Check for exposed sensitive files and API endpoints")
            console.print("• Ensure all detected technologies are up to date")
        
    except Exception as e:
        console.print(f"[bold red]Error during scan: {str(e)}[/bold red]")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
