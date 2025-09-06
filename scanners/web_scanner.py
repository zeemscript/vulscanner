import aiohttp
import asyncio
from bs4 import BeautifulSoup
from datetime import datetime
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
import re
import json
from config import ScannerConfig, ScanResult

class WebScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = None
        self.base_url = f"http://{config.target}"
        self.visited_urls: Set[str] = set()
        self.findings: Set[Dict] = set()  # Changed to Set for automatic deduplication
        self.detected_technologies = []
        self.common_paths = [
            '/robots.txt',
            '/.git/HEAD',
            '/.env',
            '/wp-config.php',
            '/phpinfo.php',
            '/server-status',
            '/.htaccess',
            '/.well-known/security.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/.DS_Store',
            '/config.php',
            '/config.yml',
            '/config.json',
            '/backup/',
            '/admin/',
            '/login/',
            '/wp-admin/',
            '/administrator/',
            '/phpmyadmin/',
            '/dbadmin/',
            '/mysql/',
            '/myadmin/',
            '/sql/',
            '/webdb/',
            '/websql/',
            '/webadmin/',
            '/admin.php',
            '/admin.html',
            '/admin.asp',
            '/admin.aspx',
            '/admin.jsp',
            '/admin.cgi',
            '/admin.pl',
            '/admin.py',
            '/admin.rb',
            '/admin.xml',
            '/admin.json',
            '/admin.yml',
            '/admin.yaml',
            '/admin.ini',
            '/admin.conf',
            '/admin.config',
            '/admin.cfg',
            '/admin.txt',
            '/admin.log',
            '/admin.bak',
            '/admin.backup',
            '/admin.old',
            '/admin.tmp',
            '/admin.temp',
            '/admin.swp',
            '/admin.swo',
            '/admin.swn',
            '/admin.swn',
            '/admin.swo',
            '/admin.swp',
            '/admin.tmp',
            '/admin.temp',
            '/admin.old',
            '/admin.bak',
            '/admin.backup',
            '/admin.txt',
            '/admin.log',
            '/admin.conf',
            '/admin.config',
            '/admin.cfg',
            '/admin.ini',
            '/admin.yml',
            '/admin.yaml',
            '/admin.json',
            '/admin.xml',
            '/admin.rb',
            '/admin.py',
            '/admin.pl',
            '/admin.cgi',
            '/admin.jsp',
            '/admin.aspx',
            '/admin.asp',
            '/admin.html',
            '/admin.php',
            # Additional sensitive paths
            '/api/',
            '/graphql',
            '/swagger/',
            '/docs/',
            '/test/',
            '/dev/',
            '/staging/',
            '/debug/',
            '/console/',
            '/shell/',
            '/terminal/',
            '/cmd/',
            '/exec/',
            '/system/',
            '/info.php',
            '/test.php',
            '/debug.php',
            '/phpinfo.php',
            '/.git/config',
            '/.gitignore',
            '/package.json',
            '/composer.json',
            '/requirements.txt',
            '/pom.xml',
            '/build.gradle',
            '/Dockerfile',
            '/docker-compose.yml',
            '/.env.local',
            '/.env.production',
            '/.env.development',
            '/config/database.yml',
            '/config/database.php',
            '/wp-config.php.bak',
            '/wp-config.php~',
            '/wp-config.php.old',
            '/wp-config.php.save',
            '/wp-config.php.swp',
            '/wp-config.php.swo',
            '/wp-config.php.swn',
            '/wp-config.php.tmp',
            '/wp-config.php.temp',
            '/wp-config.php.backup',
            '/wp-config.php.bak',
            '/wp-config.php.old',
            '/wp-config.php.save',
            '/wp-config.php.swp',
            '/wp-config.php.swo',
            '/wp-config.php.swn',
            '/wp-config.php.tmp',
            '/wp-config.php.temp',
            '/wp-config.php.backup'
        ]

    async def init_session(self):
        """Initialize aiohttp session with custom headers"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={
                    "User-Agent": self.config.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1"
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    def add_finding(self, description: str, severity: str, category: str = "general"):
        """Add a finding with deduplication"""
        finding = {
            'description': description,
            'severity': severity,
            'category': category
        }
        self.findings.add(tuple(finding.items()))  # Convert dict to tuple for set storage

    def add_technology(self, name: str, version: str = None, confidence: str = "medium"):
        """Add detected technology with security analysis"""
        tech = {
            'name': name,
            'version': version,
            'confidence': confidence,
            'security_status': self.analyze_technology_security(name, version)
        }
        if tech not in self.detected_technologies:
            self.detected_technologies.append(tech)
    
    def analyze_technology_security(self, name: str, version: str = None) -> dict:
        """Analyze technology for security issues and outdated versions"""
        security_status = {
            'is_outdated': False,
            'security_risk': 'low',
            'recommendations': [],
            'cve_count': 0
        }
        
        # Known outdated versions and security issues
        outdated_versions = {
            'jQuery': {
                'outdated': ['1.x', '2.x', '3.0', '3.1', '3.2', '3.3', '3.4'],
                'current': '3.7.1',
                'security_issues': ['XSS vulnerabilities', 'Prototype pollution']
            },
            'Bootstrap': {
                'outdated': ['3.x', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5'],
                'current': '5.3.2',
                'security_issues': ['XSS in tooltips', 'Data attribute vulnerabilities']
            },
            'Angular': {
                'outdated': ['1.x', '2.x', '4.x', '5.x', '6.x', '7.x', '8.x', '9.x', '10.x', '11.x', '12.x'],
                'current': '17.0.0',
                'security_issues': ['XSS vulnerabilities', 'Prototype pollution', 'SSRF']
            },
            'React': {
                'outdated': ['0.14', '15.x', '16.0', '16.1', '16.2', '16.3', '16.4', '16.5', '16.6', '16.7', '16.8'],
                'current': '18.2.0',
                'security_issues': ['XSS vulnerabilities', 'Server-side rendering issues']
            },
            'Vue.js': {
                'outdated': ['1.x', '2.0', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6'],
                'current': '3.3.8',
                'security_issues': ['XSS vulnerabilities', 'Template injection']
            },
            'WordPress': {
                'outdated': ['4.x', '5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9', '6.0', '6.1', '6.2'],
                'current': '6.4.2',
                'security_issues': ['SQL injection', 'XSS', 'File upload vulnerabilities', 'Privilege escalation']
            },
            'Drupal': {
                'outdated': ['7.x', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5', '8.6', '8.7', '8.8', '8.9', '9.0', '9.1', '9.2', '9.3', '9.4', '9.5'],
                'current': '10.1.6',
                'security_issues': ['SQL injection', 'XSS', 'Remote code execution', 'CSRF']
            },
            'Joomla': {
                'outdated': ['3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8', '3.9', '4.0', '4.1', '4.2'],
                'current': '4.4.0',
                'security_issues': ['SQL injection', 'XSS', 'File upload vulnerabilities', 'Authentication bypass']
            }
        }
        
        if name in outdated_versions:
            tech_info = outdated_versions[name]
            
            if version:
                # Check if version is outdated
                for outdated in tech_info['outdated']:
                    if version.startswith(outdated):
                        security_status['is_outdated'] = True
                        security_status['security_risk'] = 'high'
                        security_status['recommendations'].append(f"Update {name} from {version} to {tech_info['current']}")
                        break
            else:
                # No version detected, recommend checking
                security_status['recommendations'].append(f"Verify {name} version and update to {tech_info['current']}")
            
            # Add general security recommendations
            for issue in tech_info['security_issues']:
                security_status['recommendations'].append(f"Check for {issue} vulnerabilities")
        
        return security_status

    async def detect_frontend_frameworks(self, response: aiohttp.ClientResponse):
        """Detect common frontend frameworks/libraries"""
        if response.status == 200:
            content = await response.text()
            soup = BeautifulSoup(content, 'html.parser')
            scripts = soup.find_all('script', src=True)
            html = content.lower()
            
            # React detection with version extraction
            react_version = None
            if 'data-reactroot' in html or '__REACT_DEVTOOLS_GLOBAL_HOOK__' in html:
                # Try to extract React version from script tags
                for script in scripts:
                    if 'react' in script.get('src', '').lower():
                        # Extract version from URL like /react/16.8.0/react.min.js
                        import re
                        version_match = re.search(r'react/(\d+\.\d+\.\d+)', script.get('src', ''))
                        if version_match:
                            react_version = version_match.group(1)
                            break
                
                self.add_technology("React.js", react_version, "high")
                if react_version:
                    self.add_finding(f"React.js {react_version} detected - Check for security updates", "info", "framework")
                else:
                 self.add_finding("React.js detected - Consider security implications of client-side rendering", "info", "framework")
            
            if any('/static/js/' in s['src'] and 'main.' in s['src'] for s in scripts):
                self.add_technology("React.js (Build)", confidence="medium")
            
            # Angular detection
            if soup.find(attrs={"ng-version": True}):
                version = soup.find(attrs={"ng-version": True})["ng-version"]
                self.add_technology("Angular", version, "high")
                self.add_finding(f"Angular {version} detected", "info", "framework")
            
            if any('main.' in s['src'] and 'angular' in s['src'] for s in scripts):
                self.add_technology("Angular (Build)", confidence="medium")
            
            # Vue detection
            if '__VUE_DEVTOOLS_GLOBAL_HOOK__' in html:
                self.add_technology("Vue.js", confidence="high")
                self.add_finding("Vue.js detected", "info", "framework")
            
            if any('vue' in s['src'] for s in scripts):
                self.add_technology("Vue.js (Script)", confidence="medium")
            
            # Next.js detection
            if '/_next/' in html:
                self.add_technology("Next.js", confidence="high")
                self.add_finding("Next.js detected - Server-side rendering framework", "info", "framework")
            
            # Nuxt.js detection
            if '/_nuxt/' in html:
                self.add_technology("Nuxt.js", confidence="high")
                self.add_finding("Nuxt.js detected - Vue.js SSR framework", "info", "framework")
            
            # Svelte detection
            if 'data-svelte' in html:
                self.add_technology("Svelte", confidence="high")
                self.add_finding("Svelte detected", "info", "framework")
            
            # jQuery detection with version extraction
            jquery_version = None
            if 'jquery' in html or any('jquery' in s['src'] for s in scripts):
                # Try to extract jQuery version
                for script in scripts:
                    if 'jquery' in script.get('src', '').lower():
                        import re
                        version_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', script.get('src', ''))
                        if version_match:
                            jquery_version = version_match.group(1)
                            break
                
                # Also check for jQuery version in global variables
                if not jquery_version:
                    version_match = re.search(r'jQuery\.fn\.jquery["\']?\s*:\s*["\']?(\d+\.\d+\.\d+)', content)
                    if version_match:
                        jquery_version = version_match.group(1)
                
                self.add_technology("jQuery", jquery_version, "medium")
                if jquery_version:
                    self.add_finding(f"jQuery {jquery_version} detected - Check for security updates", "low", "framework")
                else:
                 self.add_finding("jQuery detected - Consider modern alternatives for security", "low", "framework")
            
            # Bootstrap detection
            if 'bootstrap' in html or any('bootstrap' in s['src'] for s in scripts):
                self.add_technology("Bootstrap", confidence="medium")
            
            # WordPress detection
            if 'wp-content' in html or 'wp-includes' in html:
                self.add_technology("WordPress", confidence="high")
                self.add_finding("WordPress detected - Ensure plugins and themes are updated", "medium", "cms")
            
            # Drupal detection
            if 'drupal' in html or 'Drupal.settings' in html:
                self.add_technology("Drupal", confidence="high")
                self.add_finding("Drupal detected - Check for security updates", "medium", "cms")
            
            # Joomla detection
            if 'joomla' in html or 'Joomla!' in html:
                self.add_technology("Joomla", confidence="high")
                self.add_finding("Joomla detected - Verify security patches", "medium", "cms")

    async def detect_analytics_tracking(self, response: aiohttp.ClientResponse):
        """Detect analytics and tracking services"""
        if response.status == 200:
            content = await response.text()
            html = content.lower()
            
            # Google Analytics
            if 'google-analytics' in html or 'gtag' in html or 'ga(' in html:
                self.add_technology("Google Analytics", confidence="high")
                self.add_finding("Google Analytics detected - Privacy implications", "info", "tracking")
            
            # Facebook Pixel
            if 'facebook' in html and 'pixel' in html:
                self.add_technology("Facebook Pixel", confidence="high")
                self.add_finding("Facebook Pixel detected - Privacy and GDPR considerations", "medium", "tracking")
            
            # Hotjar
            if 'hotjar' in html:
                self.add_technology("Hotjar", confidence="high")
                self.add_finding("Hotjar detected - Session recording implications", "medium", "tracking")
            
            # Mixpanel
            if 'mixpanel' in html:
                self.add_technology("Mixpanel", confidence="high")
                self.add_finding("Mixpanel detected - User behavior tracking", "info", "tracking")

    async def check_security_headers(self, response: aiohttp.ClientResponse):
        """Check for security headers"""
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking protection)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header (MIME-sniffing protection)',
            'X-XSS-Protection': 'Missing X-XSS-Protection header (XSS protection)',
            'Strict-Transport-Security': 'Missing HSTS header (HTTPS enforcement)',
            'Content-Security-Policy': 'Missing Content-Security-Policy header (XSS protection)',
            'Referrer-Policy': 'Missing Referrer-Policy header (information leakage)',
            'Permissions-Policy': 'Missing Permissions-Policy header (feature control)',
            'Cross-Origin-Opener-Policy': 'Missing Cross-Origin-Opener-Policy header (cross-origin isolation)',
            'Cross-Origin-Embedder-Policy': 'Missing Cross-Origin-Embedder-Policy header (cross-origin isolation)',
            'Cross-Origin-Resource-Policy': 'Missing Cross-Origin-Resource-Policy header (cross-origin isolation)'
        }

        headers = response.headers
        for header, message in security_headers.items():
            if header not in headers:
                self.add_finding(message, 'medium', 'headers')

    async def check_server_info(self, response: aiohttp.ClientResponse):
        """Check for server information disclosure"""
        headers = response.headers
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        
        for header in info_headers:
            if header in headers:
                self.add_finding(f"{header} header reveals: {headers[header]}", 'low', 'information_disclosure')

    async def check_directory_listing(self, response: aiohttp.ClientResponse):
        """Check for directory listing vulnerability"""
        if response.status == 200:
            content = await response.text()
            indicators = [
                "Index of /",
                "Directory listing for",
                "Parent Directory",
                "[To Parent Directory]",
                "Last modified</a>",
                "Size</a>",
                "Name</a>",
                "Description</a>"
            ]
            
            if any(indicator in content for indicator in indicators):
                self.add_finding("Directory listing is enabled", 'high', 'directory_listing')

    async def check_sensitive_files(self):
        """Check for sensitive files in parallel"""
        import asyncio
        
        async def check_single_file(path):
            try:
                url = urljoin(self.base_url, path)
                async with self.session.get(url, allow_redirects=False) as response:
                    if response.status == 200:
                        self.add_finding(f"Potentially sensitive file accessible: {path}", 'high', 'sensitive_files')
            except:
                pass
        
        # Create tasks for parallel execution
        tasks = [check_single_file(path) for path in self.common_paths]
        # Run in batches to avoid overwhelming the server
        batch_size = self.config.web_scan_batch_size
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)

    async def check_forms(self, response: aiohttp.ClientResponse):
        """Check forms for security issues"""
        if response.status == 200:
            content = await response.text()
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for forms without CSRF protection
            forms = soup.find_all('form')
            for form in forms:
                csrf_tokens = form.find_all('input', {
                    'name': ['csrf_token', '_csrf', 'csrf', 'authenticity_token', 'token']
                })
                if not csrf_tokens:
                    self.add_finding("Form without CSRF protection found", 'high', 'csrf')
                
                # Check for password fields without autocomplete=off
                password_fields = form.find_all('input', {'type': 'password'})
                for field in password_fields:
                    if field.get('autocomplete') != 'off':
                        self.add_finding("Password field without autocomplete=off", 'medium', 'password_security')

    async def check_xss_vulnerabilities(self, response: aiohttp.ClientResponse):
        """Check for potential XSS vulnerabilities"""
        if response.status == 200:
            content = await response.text()
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for inline scripts
            inline_scripts = soup.find_all('script')
            has_inline_script = False
            for script in inline_scripts:
                if script.string and not script.get('nonce') and not script.get('src'):
                    has_inline_script = True
                    break
            
            if has_inline_script:
                self.add_finding("Inline JavaScript found without nonce", 'medium', 'xss')
            
            # Check for event handlers
            event_handlers = ['onclick', 'onmouseover', 'onload', 'onerror']
            has_event_handlers = False
            for tag in soup.find_all():
                for handler in event_handlers:
                    if tag.get(handler):
                        has_event_handlers = True
                        break
                if has_event_handlers:
                    break
            
            if has_event_handlers:
                self.add_finding("Event handlers found in HTML", 'medium', 'xss')

    async def check_ssl_redirect(self):
        """Check if HTTP to HTTPS redirect is properly configured"""
        try:
            async with self.session.get(self.base_url, allow_redirects=True) as response:
                if response.url.startswith('http://'):
                    self.add_finding("No HTTPS redirect configured", 'high', 'ssl')
        except:
            pass

    async def check_api_endpoints(self):
        """Check for common API endpoints"""
        api_paths = [
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/rest/',
            '/graphql',
            '/swagger/',
            '/swagger-ui/',
            '/docs/',
            '/redoc/',
            '/openapi.json',
            '/swagger.json',
            '/api-docs/',
            '/admin/api/',
            '/api/admin/',
            '/api/users/',
            '/api/auth/',
            '/api/login/',
            '/api/register/',
            '/api/profile/',
            '/api/settings/',
            '/api/config/',
            '/api/health/',
            '/api/status/',
            '/api/version/',
            '/api/info/',
            '/api/debug/',
            '/api/test/',
            '/api/dev/',
            '/api/staging/',
            '/api/production/',
            '/api/development/',
            '/api/local/',
            '/api/localhost/',
            '/api/127.0.0.1/',
            '/api/0.0.0.0/',
            '/api/::1/',
            '/api/fe80::/',
            '/api/169.254./',
            '/api/10./',
            '/api/172.16./',
            '/api/172.17./',
            '/api/172.18./',
            '/api/172.19./',
            '/api/172.20./',
            '/api/172.21./',
            '/api/172.22./',
            '/api/172.23./',
            '/api/172.24./',
            '/api/172.25./',
            '/api/172.26./',
            '/api/172.27./',
            '/api/172.28./',
            '/api/172.29./',
            '/api/172.30./',
            '/api/172.31./',
            '/api/192.168./',
            '/api/127./',
            '/api/0./',
            '/api/255.255.255.255/',
            '/api/224.0.0./',
            '/api/240.0.0./',
            '/api/::/',
            '/api/fe80::/',
            '/api/fc00::/',
            '/api/fd00::/',
            '/api/2001:db8::/',
            '/api/2001:db8:1::/',
            '/api/2001:db8:2::/',
            '/api/2001:db8:3::/',
            '/api/2001:db8:4::/',
            '/api/2001:db8:5::/',
            '/api/2001:db8:6::/',
            '/api/2001:db8:7::/',
            '/api/2001:db8:8::/',
            '/api/2001:db8:9::/',
            '/api/2001:db8:a::/',
            '/api/2001:db8:b::/',
            '/api/2001:db8:c::/',
            '/api/2001:db8:d::/',
            '/api/2001:db8:e::/',
            '/api/2001:db8:f::/'
        ]
        
        # Check API endpoints in parallel with comprehensive security analysis
        async def check_single_api(path):
            try:
                url = urljoin(self.base_url, path)
                async with self.session.get(url, allow_redirects=False) as response:
                    if response.status in [200, 401, 403, 405]:
                        # Perform comprehensive API security analysis
                        await self.analyze_api_security(url, response, path)
            except:
                pass
        
        # Create tasks for parallel execution
        tasks = [check_single_api(path) for path in api_paths]
        # Run in batches to avoid overwhelming the server
        batch_size = self.config.web_scan_batch_size
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)

    async def analyze_api_security(self, url: str, response: aiohttp.ClientResponse, path: str):
        """Comprehensive API security analysis"""
        from rich.console import Console
        console = Console()
        
        # Basic API endpoint detection
        self.add_finding(f"API endpoint accessible: {path} (Status: {response.status})", 'medium', 'api_endpoints')
        
        # Check for authentication requirements
        if response.status == 401:
            self.add_finding(f"API endpoint requires authentication: {path}", 'info', 'api_auth')
        elif response.status == 403:
            self.add_finding(f"API endpoint access forbidden: {path}", 'medium', 'api_auth')
        elif response.status == 200:
            self.add_finding(f"API endpoint publicly accessible: {path}", 'high', 'api_security')
        
        # Analyze response headers for security
        headers = response.headers
        
        # Check for CORS headers
        if 'Access-Control-Allow-Origin' in headers:
            cors_origin = headers['Access-Control-Allow-Origin']
            if cors_origin == '*':
                self.add_finding(f"API endpoint allows CORS from any origin: {path}", 'high', 'api_cors')
            elif cors_origin != self.base_url:
                self.add_finding(f"API endpoint has CORS configuration: {path} (Origin: {cors_origin})", 'medium', 'api_cors')
        
        # Check for rate limiting headers
        if 'X-RateLimit-Limit' not in headers and 'RateLimit-Limit' not in headers:
            self.add_finding(f"API endpoint missing rate limiting headers: {path}", 'medium', 'api_rate_limiting')
        
        # Check for API versioning
        if '/api/v' in path:
            self.add_finding(f"API endpoint uses versioning: {path}", 'info', 'api_versioning')
        
        # Check for sensitive API patterns
        sensitive_patterns = [
            ('/admin/', 'Administrative API'),
            ('/auth/', 'Authentication API'),
            ('/user/', 'User management API'),
            ('/config/', 'Configuration API'),
            ('/debug/', 'Debug API'),
            ('/test/', 'Test API'),
            ('/dev/', 'Development API')
        ]
        
        for pattern, description in sensitive_patterns:
            if pattern in path:
                self.add_finding(f"Sensitive API endpoint detected: {description} at {path}", 'high', 'api_sensitive')
        
        # Analyze response content for API information disclosure
        try:
            content = await response.text()
            if content:
                # Check for API documentation exposure
                if any(doc in content.lower() for doc in ['swagger', 'openapi', 'api-docs', 'redoc']):
                    self.add_finding(f"API documentation exposed: {path}", 'medium', 'api_documentation')
                
                # Check for error information disclosure
                if any(error in content.lower() for error in ['error', 'exception', 'stack trace', 'debug']):
                    self.add_finding(f"API endpoint may expose error information: {path}", 'medium', 'api_error_disclosure')
                
                # Check for data structure exposure
                if any(data in content.lower() for data in ['password', 'token', 'key', 'secret', 'credential']):
                    self.add_finding(f"API endpoint may expose sensitive data structure: {path}", 'high', 'api_data_exposure')
                
                # Check for GraphQL endpoint
                if 'graphql' in content.lower() or 'query' in content.lower():
                    self.add_finding(f"GraphQL endpoint detected: {path}", 'info', 'api_graphql')
                
                # Check for REST API patterns
                if any(method in content.upper() for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']):
                    self.add_finding(f"REST API endpoint detected: {path}", 'info', 'api_rest')
        
        except Exception:
            pass  # Skip content analysis if there's an error

    def generate_technology_stack_report(self) -> dict:
        """Generate comprehensive technology stack report"""
        # Categorize technologies
        frontend_tech = []
        backend_tech = []
        cms_tech = []
        analytics_tech = []
        outdated_tech = []
        
        for tech in self.detected_technologies:
            tech_info = {
                'name': tech['name'],
                'version': tech['version'],
                'confidence': tech['confidence'],
                'security_risk': tech['security_status']['security_risk'],
                'is_outdated': tech['security_status']['is_outdated']
            }
            
            if tech['security_status']['is_outdated']:
                outdated_tech.append(tech_info)
            
            # Categorize by type
            if tech['name'] in ['React.js', 'Angular', 'Vue.js', 'Next.js', 'Nuxt.js', 'Svelte', 'jQuery', 'Bootstrap']:
                frontend_tech.append(tech_info)
            elif tech['name'] in ['WordPress', 'Drupal', 'Joomla']:
                cms_tech.append(tech_info)
            elif tech['name'] in ['Google Analytics', 'Facebook Pixel', 'Hotjar', 'Mixpanel']:
                analytics_tech.append(tech_info)
            else:
                backend_tech.append(tech_info)
        
        # Generate report
        report = {
            'description': f"Technology Stack Analysis - {len(self.detected_technologies)} technologies detected",
            'severity': 'high' if outdated_tech else 'info',
            'category': 'technology_stack',
            'details': {
                'total_technologies': len(self.detected_technologies),
                'outdated_count': len(outdated_tech),
                'frontend_technologies': frontend_tech,
                'backend_technologies': backend_tech,
                'cms_technologies': cms_tech,
                'analytics_technologies': analytics_tech,
                'outdated_technologies': outdated_tech,
                'security_summary': {
                    'high_risk': len([t for t in self.detected_technologies if t['security_status']['security_risk'] == 'high']),
                    'medium_risk': len([t for t in self.detected_technologies if t['security_status']['security_risk'] == 'medium']),
                    'low_risk': len([t for t in self.detected_technologies if t['security_status']['security_risk'] == 'low'])
                }
            }
        }
        
        return report

    async def scan(self) -> ScanResult:
        """Perform web security checks"""
        try:
            from rich.console import Console
            console = Console()
            
            await self.init_session()
            console.print("[yellow]  → Initializing web session...[/yellow]")
            
            # Check SSL redirect
            console.print("[yellow]  → Checking SSL redirect configuration...[/yellow]")
            await self.check_ssl_redirect()
            
            # Check sensitive files
            console.print(f"[yellow]  → Scanning {len(self.common_paths)} sensitive file paths in parallel...[/yellow]")
            await self.check_sensitive_files()
            
            # Check API endpoints
            console.print("[yellow]  → Discovering API endpoints in parallel...[/yellow]")
            await self.check_api_endpoints()
            
            # Main page scan
            console.print("[yellow]  → Analyzing main page content...[/yellow]")
            async with self.session.get(self.base_url) as response:
                # Detect frontend frameworks
                console.print("[yellow]  → Detecting frontend frameworks...[/yellow]")
                await self.detect_frontend_frameworks(response)
                
                # Detect analytics and tracking
                console.print("[yellow]  → Detecting analytics and tracking services...[/yellow]")
                await self.detect_analytics_tracking(response)
                
                # Check security headers
                console.print("[yellow]  → Analyzing security headers...[/yellow]")
                await self.check_security_headers(response)
                
                # Check server information
                console.print("[yellow]  → Checking server information disclosure...[/yellow]")
                await self.check_server_info(response)
                
                # Check directory listing
                console.print("[yellow]  → Checking for directory listing vulnerabilities...[/yellow]")
                await self.check_directory_listing(response)
                
                # Check forms
                console.print("[yellow]  → Analyzing form security...[/yellow]")
                await self.check_forms(response)
                
                # Check XSS vulnerabilities
                console.print("[yellow]  → Scanning for XSS vulnerabilities...[/yellow]")
                await self.check_xss_vulnerabilities(response)
            
            # Convert set of tuples back to list of dicts
            findings_list = [dict(finding) for finding in self.findings]
            
            # Add comprehensive technology stack analysis
            if self.detected_technologies:
                # Create detailed technology stack report
                tech_report = self.generate_technology_stack_report()
                findings_list.append(tech_report)
                
                # Add individual technology security findings
                for tech in self.detected_technologies:
                    if tech['security_status']['is_outdated']:
                        self.add_finding(
                            f"Outdated {tech['name']} {tech['version'] or 'version'} detected - Security risk: {tech['security_status']['security_risk']}",
                            'high' if tech['security_status']['security_risk'] == 'high' else 'medium',
                            'outdated_software'
                        )
                    
                    # Add security recommendations for each technology
                    for recommendation in tech['security_status']['recommendations']:
                        self.add_finding(
                            f"{tech['name']} Security: {recommendation}",
                            'medium',
                            'security_recommendation'
                        )
            
            return ScanResult(
                target=self.config.target,
                scan_type="web",
                findings=findings_list,
                timestamp=datetime.now().isoformat(),
                severity="high" if any(f.get('severity') == 'high' for f in findings_list) else "medium",
                confidence=0.9
            )
            
        except Exception as e:
            return ScanResult(
                target=self.config.target,
                scan_type="web",
                findings=[{'description': f"Error during web scan: {str(e)}"}],
                timestamp=datetime.now().isoformat(),
                severity="error",
                confidence=0.0
            )
        finally:
            await self.close_session()

async def scan(config: ScannerConfig) -> ScanResult:
    """Entry point for web scanning"""
    scanner = WebScanner(config)
    return await scanner.scan() 