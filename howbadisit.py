#!/usr/bin/env python3
"""
HowBadIsIt? - Professional Web Application Security Scanner
Version: 2.1.0
Author: Security Research Team
License: MIT

A comprehensive web security scanner designed for penetration testers,
red teams, and MSSPs. Performs automated security assessments and
generates professional reports with visual evidence.
"""

import argparse
import requests
import socket
import ssl
import subprocess
import json
import logging
import sys
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('howbadisit.log'),
        logging.StreamHandler()
    ]
)

class HowBadIsIt:
    """
    Main security scanner class for web application vulnerability assessment.
    """
    
    def __init__(self, target: str, timeout: int = 10, threads: int = 5):
        """
        Initialize the security scanner.
        
        Args:
            target: Target domain or URL to scan
            timeout: Request timeout in seconds
            threads: Number of concurrent threads for scanning
        """
        self.target = self._normalize_target(target)
        self.domain = self._extract_domain(self.target)
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.scan_metadata = {
            'target': self.target,
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'scanner_version': '2.1.0',
            'scanner_name': 'HowBadIsIt?'
        }
        
        # User agent
        self.headers = {
            'User-Agent': 'HowBadIsIt?/2.1.0 (Security Scanner)'
        }
        
        logging.info(f"Initialized scanner for target: {self.target}")
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL to include protocol."""
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling.
        
        Args:
            url: URL to request
            method: HTTP method
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object or None if request fails
        """
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('headers', self.headers)
            kwargs.setdefault('verify', False)
            kwargs.setdefault('allow_redirects', True)
            
            response = requests.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed for {url}: {str(e)}")
            return None
    
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Execute all security tests.
        
        Returns:
            Dictionary containing all test results
        """
        logging.info("Starting comprehensive security assessment...")
        
        tests = [
            self.test_technology_detection,
            self.test_subdomain_enumeration,
            self.test_information_disclosure,
            self.test_port_scanning,
            self.test_ssl_tls_configuration,
            self.test_security_headers,
            self.test_form_analysis,
            self.test_cors_misconfiguration,
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test): test.__name__ for test in tests}
            
            for future in as_completed(futures):
                test_name = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    logging.info(f"Completed: {test_name}")
                except Exception as e:
                    logging.error(f"Test {test_name} failed: {str(e)}")
                    self.results.append({
                        'test_name': test_name,
                        'status': 'ERROR',
                        'severity': 'INFO',
                        'error': str(e)
                    })
        
        return self._generate_report()
    
    def test_technology_detection(self) -> Dict[str, Any]:
        """Detect web technologies and versions."""
        logging.info("Running technology detection test...")
        
        result = {
            'test_name': 'Technology Detection',
            'description': 'Identifies web server, frameworks, and technologies in use',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        try:
            response = self._make_request(self.target)
            if not response:
                result['status'] = 'ERROR'
                result['error'] = 'Failed to connect to target'
                return result
            
            technologies = []
            
            # Server header
            server = response.headers.get('Server', '')
            if server:
                technologies.append({
                    'type': 'Web Server',
                    'name': server,
                    'detected_from': 'HTTP Header'
                })
                result['findings'].append(f"Web server: {server}")
            
            # X-Powered-By
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                technologies.append({
                    'type': 'Backend Technology',
                    'name': powered_by,
                    'detected_from': 'HTTP Header'
                })
                result['findings'].append(f"Backend: {powered_by}")
            
            # Content analysis
            content = response.text.lower()
            
            # Common frameworks/CMSs
            tech_signatures = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Joomla': ['joomla', 'com_content'],
                'Drupal': ['drupal', 'sites/all'],
                'jQuery': ['jquery'],
                'React': ['react', 'reactjs'],
                'Angular': ['angular', 'ng-'],
                'Vue.js': ['vue', 'vuejs']
            }
            
            for tech, signatures in tech_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies.append({
                        'type': 'Framework/Library',
                        'name': tech,
                        'detected_from': 'HTML Content'
                    })
                    result['findings'].append(f"Framework/Library: {tech}")
            
            result['technologies'] = technologies
            
            if server or powered_by:
                result['severity'] = 'LOW'
                result['status'] = 'VULNERABLE'
                result['recommendations'].append(
                    "Consider removing or obfuscating server banners to reduce information leakage"
                )
            
            if not technologies:
                result['findings'].append("No technologies detected from standard signatures")
        
        except Exception as e:
            logging.error(f"Technology detection failed: {str(e)}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_subdomain_enumeration(self) -> Dict[str, Any]:
        """Enumerate subdomains using common wordlist."""
        logging.info("Running subdomain enumeration test...")
        
        result = {
            'test_name': 'Subdomain Enumeration',
            'description': 'Discovers subdomains that may expand attack surface',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        # Common subdomain wordlist
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'api', 'dev', 'staging',
            'test', 'portal', 'blog', 'shop', 'store', 'vpn', 'remote', 'secure',
            'login', 'dashboard', 'panel', 'cpanel', 'control', 'ns1', 'ns2',
            'smtp', 'pop', 'imap', 'm', 'mobile', 'app', 'cdn', 'static',
            'media', 'images', 'img', 'assets'
        ]
        
        found_subdomains = []
        
        try:
            for subdomain in subdomains:
                full_domain = f"{subdomain}.{self.domain}"
                try:
                    socket.gethostbyname(full_domain)
                    found_subdomains.append(full_domain)
                    logging.debug(f"Found subdomain: {full_domain}")
                except socket.gaierror:
                    pass
            
            result['subdomains'] = found_subdomains
            result['findings'].append(f"Discovered {len(found_subdomains)} active subdomains")
            
            if found_subdomains:
                result['recommendations'].append(
                    "Review all subdomains for proper security configuration"
                )
                result['recommendations'].append(
                    "Ensure unused subdomains are properly decommissioned"
                )
                
                # Check for potential takeover (basic check)
                takeover_keywords = ['github', 'heroku', 'aws', 'azure', 's3']
                for subdomain in found_subdomains[:5]:  # Check first 5 to avoid rate limiting
                    try:
                        response = self._make_request(f"https://{subdomain}")
                        if response and any(keyword in response.text.lower() for keyword in takeover_keywords):
                            result['severity'] = 'CRITICAL'
                            result['status'] = 'VULNERABLE'
                            result['findings'].append(
                                f"Potential subdomain takeover vulnerability on: {subdomain}"
                            )
                            break
                    except:
                        pass
        
        except Exception as e:
            logging.error(f"Subdomain enumeration failed: {str(e)}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_information_disclosure(self) -> Dict[str, Any]:
        """Check for exposed sensitive files and information."""
        logging.info("Running information disclosure test...")
        
        result = {
            'test_name': 'Information Disclosure',
            'description': 'Checks for exposed sensitive files and directories',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        # Common sensitive files/directories
        sensitive_paths = [
            '/.git/config',
            '/.git/HEAD',
            '/.env',
            '/.env.local',
            '/.env.production',
            '/config.php',
            '/configuration.php',
            '/wp-config.php',
            '/config.yml',
            '/settings.py',
            '/.aws/credentials',
            '/backup.sql',
            '/database.sql',
            '/dump.sql',
            '/robots.txt',
            '/sitemap.xml',
            '/.htaccess',
            '/web.config',
            '/phpinfo.php',
            '/info.php',
            '/.DS_Store',
            '/composer.json',
            '/package.json'
        ]
        
        exposed_files = []
        
        try:
            for path in sensitive_paths:
                url = urljoin(self.target, path)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    exposed_files.append({
                        'path': path,
                        'url': url,
                        'status_code': response.status_code,
                        'size': len(response.content)
                    })
                    
                    # Determine severity based on file type
                    if any(x in path for x in ['.git', '.env', 'config', '.sql', 'backup', 'dump']):
                        severity = 'HIGH'
                    elif any(x in path for x in ['robots.txt', 'sitemap.xml']):
                        severity = 'INFO'
                    else:
                        severity = 'MEDIUM'
                    
                    result['findings'].append(
                        f"Exposed file [{severity}]: {path} (HTTP {response.status_code})"
                    )
            
            result['exposed_files'] = exposed_files
            
            if exposed_files:
                result['status'] = 'VULNERABLE'
                
                # Determine overall severity
                if any('.git' in f['path'] or '.env' in f['path'] or '.sql' in f['path'] 
                       for f in exposed_files):
                    result['severity'] = 'HIGH'
                else:
                    result['severity'] = 'MEDIUM'
                
                result['recommendations'].extend([
                    "Remove or restrict access to sensitive files",
                    "Implement proper .htaccess or server configuration rules",
                    "Avoid exposing version control directories (.git)",
                    "Use environment variables instead of config files in web root"
                ])
            else:
                result['findings'].append("No obvious sensitive files exposed")
        
        except Exception as e:
            logging.error(f"Information disclosure test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_port_scanning(self) -> Dict[str, Any]:
        """Scan common ports for exposed services."""
        logging.info("Running port scanning test...")
        
        result = {
            'test_name': 'Port Scanning & Service Detection',
            'description': 'Identifies open ports and potentially vulnerable services',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        # Common ports to scan
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        open_ports = []
        
        try:
            for port, service in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                try:
                    result_code = sock.connect_ex((self.domain, port))
                    if result_code == 0:
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
                        
                        # Determine severity
                        if port in [23, 3306, 3389, 5432, 6379, 27017]:
                            severity = 'HIGH'
                            result['findings'].append(
                                f"Potentially dangerous port open: {port}/{service}"
                            )
                        else:
                            severity = 'INFO'
                            result['findings'].append(
                                f"Port open: {port}/{service}"
                            )
                except:
                    pass
                finally:
                    sock.close()
            
            result['open_ports'] = open_ports
            
            if open_ports:
                # Check for high-risk ports
                high_risk_ports = [p for p in open_ports if p['port'] in [23, 3306, 3389, 5432, 6379, 27017]]
                
                if high_risk_ports:
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'HIGH'
                    result['recommendations'].extend([
                        "Close unnecessary ports or restrict access with firewall rules",
                        "Never expose database ports (3306, 5432, 6379, 27017) to the internet",
                        "Disable Telnet (port 23) and use SSH (port 22) instead",
                        "Restrict RDP (3389) access to VPN only"
                    ])
                else:
                    result['recommendations'].append(
                        "Review open ports and ensure only necessary services are exposed"
                    )
            else:
                result['findings'].append("Only standard web ports detected")
        
        except Exception as e:
            logging.error(f"Port scanning failed: {str(e)}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_ssl_tls_configuration(self) -> Dict[str, Any]:
        """Test SSL/TLS configuration and certificate validity."""
        logging.info("Running SSL/TLS configuration test...")
        
        result = {
            'test_name': 'SSL/TLS Configuration',
            'description': 'Validates SSL/TLS implementation and certificate security',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        try:
            # Parse target
            parsed = urlparse(self.target)
            hostname = parsed.netloc or parsed.path
            port = 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Certificate information
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    result['certificate'] = {
                        'subject': subject.get('commonName', 'Unknown'),
                        'issuer': issuer.get('commonName', 'Unknown'),
                        'valid_from': cert['notBefore'],
                        'valid_until': cert['notAfter'],
                        'version': version,
                        'cipher': cipher
                    }
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    result['findings'].append(
                        f"Certificate expires in {days_until_expiry} days"
                    )
                    result['findings'].append(
                        f"TLS version: {version}"
                    )
                    result['findings'].append(
                        f"Cipher: {cipher[0]}"
                    )
                    
                    # Certificate warnings
                    if days_until_expiry < 30:
                        result['status'] = 'VULNERABLE'
                        result['severity'] = 'MEDIUM'
                        result['findings'].append(
                            f"Certificate expires soon ({days_until_expiry} days)"
                        )
                        result['recommendations'].append(
                            "Renew SSL certificate before expiration"
                        )
                    
                    # TLS version check
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        result['status'] = 'VULNERABLE'
                        result['severity'] = 'HIGH'
                        result['findings'].append(
                            f"Insecure TLS version detected: {version}"
                        )
                        result['recommendations'].append(
                            "Upgrade to TLS 1.2 or higher"
                        )
                    
                    # Weak cipher check
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        result['status'] = 'VULNERABLE'
                        result['severity'] = 'HIGH'
                        result['findings'].append(
                            f"Weak cipher detected: {cipher[0]}"
                        )
                        result['recommendations'].append(
                            "Configure server to use strong cipher suites only"
                        )
        
        except ssl.SSLError as e:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'HIGH'
            result['findings'].append(f"SSL Error: {str(e)}")
            result['recommendations'].append("Fix SSL/TLS configuration errors")
        
        except Exception as e:
            if 'http://' in self.target:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'HIGH'
                result['findings'].append("Site not using HTTPS")
                result['recommendations'].append("Implement HTTPS for all traffic")
            else:
                logging.error(f"SSL/TLS test failed: {str(e)}")
                result['status'] = 'ERROR'
                result['error'] = str(e)
        
        return result
    
    def test_security_headers(self) -> Dict[str, Any]:
        """Check for security-related HTTP headers."""
        logging.info("Running security headers test...")
        
        result = {
            'test_name': 'Security Headers Analysis',
            'description': 'Validates presence and configuration of security headers',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'description': 'HSTS - Enforces HTTPS',
                'severity': 'MEDIUM'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'severity': 'MEDIUM'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME-sniffing',
                'severity': 'LOW'
            },
            'Content-Security-Policy': {
                'description': 'CSP - Prevents XSS and injection attacks',
                'severity': 'MEDIUM'
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS filter',
                'severity': 'LOW'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'severity': 'LOW'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features',
                'severity': 'LOW'
            }
        }
        
        try:
            response = self._make_request(self.target)
            if not response:
                result['status'] = 'ERROR'
                result['error'] = 'Failed to connect to target'
                return result
            
            missing_headers = []
            present_headers = []
            
            for header, info in security_headers.items():
                if header in response.headers:
                    present_headers.append({
                        'header': header,
                        'value': response.headers[header],
                        'description': info['description']
                    })
                    result['findings'].append(
                        f"✓ {header}: {response.headers[header][:50]}"
                    )
                else:
                    missing_headers.append({
                        'header': header,
                        'description': info['description'],
                        'severity': info['severity']
                    })
                    result['findings'].append(
                        f"✗ Missing: {header} - {info['description']}"
                    )
            
            result['present_headers'] = present_headers
            result['missing_headers'] = missing_headers
            
            if missing_headers:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
                
                result['recommendations'].extend([
                    "Implement missing security headers",
                    "Add Strict-Transport-Security with max-age=31536000",
                    "Set X-Frame-Options to DENY or SAMEORIGIN",
                    "Implement Content-Security-Policy",
                    "Add X-Content-Type-Options: nosniff"
                ])
            else:
                result['findings'].append("All recommended security headers present")
        
        except Exception as e:
            logging.error(f"Security headers test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_form_analysis(self) -> Dict[str, Any]:
        """Analyze forms for potential security issues."""
        logging.info("Running form analysis test...")
        
        result = {
            'test_name': 'Form Security Analysis',
            'description': 'Analyzes forms for CSRF protection and secure transmission',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        try:
            response = self._make_request(self.target)
            if not response:
                result['status'] = 'ERROR'
                result['error'] = 'Failed to connect to target'
                return result
            
            # Find forms in HTML
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.IGNORECASE | re.DOTALL)
            
            result['findings'].append(f"Found {len(forms)} form(s)")
            
            if forms:
                forms_without_csrf = 0
                forms_without_https = 0
                
                for i, form in enumerate(forms, 1):
                    # Check for CSRF token (common patterns)
                    has_csrf = any(token in form.lower() for token in 
                                 ['csrf', '_token', 'authenticity_token', 'csrfmiddlewaretoken'])
                    
                    if not has_csrf:
                        forms_without_csrf += 1
                    
                    # Check for password fields
                    if 'type="password"' in form.lower() or 'type=\'password\'' in form.lower():
                        if 'http://' in self.target:
                            forms_without_https += 1
                
                if forms_without_csrf > 0:
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'MEDIUM'
                    result['findings'].append(
                        f"{forms_without_csrf} form(s) without apparent CSRF protection"
                    )
                    result['recommendations'].append(
                        "Implement CSRF tokens in all forms"
                    )
                
                if forms_without_https > 0:
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'HIGH'
                    result['findings'].append(
                        f"{forms_without_https} password form(s) transmitted over HTTP"
                    )
                    result['recommendations'].append(
                        "Use HTTPS for all forms, especially those with passwords"
                    )
                
                if forms_without_csrf == 0 and forms_without_https == 0:
                    result['findings'].append("Forms appear to have basic security measures")
            else:
                result['findings'].append("No forms detected on landing page")
        
        except Exception as e:
            logging.error(f"Form analysis failed: {str(e)}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_cors_misconfiguration(self) -> Dict[str, Any]:
        """Test for CORS misconfigurations."""
        logging.info("Running CORS misconfiguration test...")
        
        result = {
            'test_name': 'CORS Misconfiguration',
            'description': 'Tests for permissive Cross-Origin Resource Sharing policies',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        try:
            # Test with different origins
            test_origins = [
                'https://evil.com',
                'null',
                self.target
            ]
            
            vulnerable = False
            
            for origin in test_origins:
                headers = self.headers.copy()
                headers['Origin'] = origin
                
                response = self._make_request(self.target, headers=headers)
                
                if response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    # Check for wildcard with credentials
                    if acao == '*' and acac == 'true':
                        result['status'] = 'VULNERABLE'
                        result['severity'] = 'HIGH'
                        result['findings'].append(
                            "Critical: CORS allows any origin (*) with credentials"
                        )
                        vulnerable = True
                    
                    # Check for reflected origin
                    elif acao == origin and origin != self.target:
                        result['status'] = 'VULNERABLE'
                        result['severity'] = 'MEDIUM'
                        result['findings'].append(
                            f"CORS reflects arbitrary origin: {origin}"
                        )
                        vulnerable = True
                    
                    # Check for null origin
                    elif acao == 'null':
                        result['status'] = 'VULNERABLE'
                        result['severity'] = 'MEDIUM'
                        result['findings'].append(
                            "CORS allows 'null' origin"
                        )
                        vulnerable = True
            
            if vulnerable:
                result['recommendations'].extend([
                    "Implement strict CORS policy with whitelist of allowed origins",
                    "Never use wildcard (*) with Access-Control-Allow-Credentials: true",
                    "Validate Origin header on server-side",
                    "Consider if CORS is necessary for your application"
                ])
            else:
                result['findings'].append("CORS policy appears secure")
        
        except Exception as e:
            logging.error(f"CORS test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate final scan report."""
        logging.info("Generating final report...")
        
        # Calculate summary statistics
        summary = {
            'total_tests': len(self.results),
            'critical': sum(1 for r in self.results if r.get('severity') == 'CRITICAL'),
            'high': sum(1 for r in self.results if r.get('severity') == 'HIGH'),
            'medium': sum(1 for r in self.results if r.get('severity') == 'MEDIUM'),
            'low': sum(1 for r in self.results if r.get('severity') == 'LOW'),
            'info': sum(1 for r in self.results if r.get('severity') == 'INFO'),
            'passed': sum(1 for r in self.results if r.get('status') == 'PASS'),
            'vulnerable': sum(1 for r in self.results if r.get('status') == 'VULNERABLE'),
            'errors': sum(1 for r in self.results if r.get('status') == 'ERROR')
        }
        
        # Overall security score (0-100)
        total_weight = summary['critical'] * 10 + summary['high'] * 5 + summary['medium'] * 2 + summary['low']
        max_weight = summary['total_tests'] * 10
        score = max(0, 100 - (total_weight / max_weight * 100)) if max_weight > 0 else 100
        
        report = {
            **self.scan_metadata,
            'summary': summary,
            'security_score': round(score, 1),
            'results': self.results,
            'scan_completed': datetime.now().isoformat()
        }
        
        logging.info(f"Assessment completed. Security score: {score:.1f}/100")
        
        return report


def main():
    """Main entry point for the scanner."""
    
    # ASCII banner
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                     HowBadIsIt? v2.1.0                            ║
║            Professional Web Security Scanner                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    
    print(banner)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='HowBadIsIt? - Professional Web Application Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s -t https://example.com -o json
  %(prog)s -t example.com -o html -f report.html
  %(prog)s -t example.com -o json -f report.json
  %(prog)s -t example.com --timeout 15 --threads 10

For more information, visit: https://github.com/hsdesouza/howbadisit
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target domain or URL to scan (e.g., example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['json', 'text', 'html'],
        default='text',
        help='Output format: json, text, or html (default: text)'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='Output file path (default: stdout)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=5,
        help='Number of concurrent threads (default: 5)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='HowBadIsIt? v2.1.0'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        # Initialize scanner
        scanner = HowBadIsIt(
            target=args.target,
            timeout=args.timeout,
            threads=args.threads
        )
        
        # Run scan
        print(f"\n[*] Starting security assessment of: {args.target}")
        print(f"[*] Timeout: {args.timeout}s | Threads: {args.threads}")
        print("[*] Running comprehensive security tests...\n")
        
        report = scanner.run_all_tests()
        
        # Output results
        if args.output == 'json':
            output = json.dumps(report, indent=2)
        elif args.output == 'html':
            # Import HTML generator
            try:
                from html_report_generator import HTMLReportGenerator
                generator = HTMLReportGenerator()
                output = generator.generate(report)
            except ImportError:
                print("\n[!] HTML report generator not found. Falling back to JSON.")
                output = json.dumps(report, indent=2)
            except Exception as e:
                print(f"\n[!] Error generating HTML report: {e}")
                print("[!] Falling back to JSON output.")
                output = json.dumps(report, indent=2)
        else:
            # Text format
            output = f"""
{'='*70}
SECURITY ASSESSMENT REPORT
{'='*70}

Target: {report['target']}
Date: {report['scan_date']}
Security Score: {report['security_score']}/100

SUMMARY:
  Total Tests: {report['summary']['total_tests']}
  Critical: {report['summary']['critical']}
  High: {report['summary']['high']}
  Medium: {report['summary']['medium']}
  Low: {report['summary']['low']}
  Info: {report['summary']['info']}

{'='*70}
DETAILED FINDINGS:
{'='*70}

"""
            for result in report['results']:
                output += f"\n[{result['severity']}] {result['test_name']}\n"
                output += f"Status: {result['status']}\n"
                output += f"Description: {result['description']}\n"
                
                if result.get('findings'):
                    output += "\nFindings:\n"
                    for finding in result['findings']:
                        output += f"  - {finding}\n"
                
                if result.get('recommendations'):
                    output += "\nRecommendations:\n"
                    for rec in result['recommendations']:
                        output += f"  • {rec}\n"
                
                output += "-" * 70 + "\n"
        
        # Save or print output
        if args.file:
            with open(args.file, 'w') as f:
                f.write(output)
            print(f"\n[✓] Report saved to: {args.file}")
        else:
            print(output)
        
        # Exit with appropriate code
        if report['summary']['critical'] > 0:
            sys.exit(3)
        elif report['summary']['high'] > 0:
            sys.exit(2)
        elif report['summary']['medium'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n\n[!] Assessment interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        print(f"\n[✗] Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
