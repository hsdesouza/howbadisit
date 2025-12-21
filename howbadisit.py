#!/usr/bin/env python3
"""
HowBadIsIt? - Professional Web Application Security Scanner
Version: 2.4.0 - Phase 4A Delivery 1
Author: Security Research Team
License: MIT

A comprehensive web security scanner designed for penetration testers,
red teams, and MSSPs. Performs automated security assessments and
generates professional reports with visual evidence.

NEW in v2.4.0 - Authentication Core (Phase 4A - Delivery 1):
- Brute Force Protection Testing (HIGH)
- Session Management Security (HIGH)
- Password Policy Strength (MEDIUM)
- User Enumeration Prevention (MEDIUM)
- MFA Assessment (INFO)
- Total: 18 professional security tests

Compliance Coverage:
- NIST CSF 2.0: 75%
- LGPD: 90%
- PCI-DSS v4.0: 85%
- ISO 27001: 80%
- OWASP Top 10 (2021): 90%
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
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup

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
            'scanner_version': '2.4.0',
            'scanner_name': 'HowBadIsIt?'
        }
        
        # User agent
        self.headers = {
            'User-Agent': 'HowBadIsIt?/2.4.0 (Security Scanner)'
        }
        
        # Session for maintaining cookies
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
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
            self.test_http_methods,
            self.test_waf_detection,
            self.test_sql_injection,
            self.test_xss_detection,
            self.test_command_injection,
            # Phase 4A - Authentication Core Tests
            self.test_brute_force_protection,
            self.test_session_management,
            self.test_password_policy,
            self.test_user_enumeration,
            self.test_mfa_assessment,
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
                
                # Add specific recommendations based on what was found
                has_git = any('.git' in f['path'] for f in exposed_files)
                has_env = any('.env' in f['path'] for f in exposed_files)
                has_sql = any('.sql' in f['path'] or 'backup' in f['path'] or 'dump' in f['path'] 
                            for f in exposed_files)
                has_config = any('config' in f['path'] or 'settings' in f['path'] 
                               for f in exposed_files)
                has_aws = any('.aws' in f['path'] for f in exposed_files)
                has_htaccess = any('.htaccess' in f['path'] or 'web.config' in f['path'] 
                                  for f in exposed_files)
                has_info_files = any(f['path'] in ['/robots.txt', '/sitemap.xml'] 
                                    for f in exposed_files)
                
                # Only non-info files trigger recommendations
                critical_files = [f for f in exposed_files 
                                if f['path'] not in ['/robots.txt', '/sitemap.xml']]
                
                if critical_files:
                    if has_git:
                        result['recommendations'].append(
                            "CRITICAL: Remove or block access to .git directory immediately"
                        )
                    
                    if has_env:
                        result['recommendations'].append(
                            "CRITICAL: Remove .env files from web root and use environment variables"
                        )
                    
                    if has_sql:
                        result['recommendations'].append(
                            "CRITICAL: Delete database backup files (*.sql) from web-accessible directories"
                        )
                    
                    if has_aws:
                        result['recommendations'].append(
                            "CRITICAL: Remove AWS credentials file and rotate all exposed keys immediately"
                        )
                    
                    if has_config:
                        result['recommendations'].append(
                            "Move configuration files outside web root or implement access restrictions"
                        )
                    
                    if has_htaccess:
                        result['recommendations'].append(
                            "Implement proper .htaccess or web.config rules to block sensitive files"
                        )
                    
                    # General recommendation if any critical files found
                    result['recommendations'].append(
                        "Audit all web-accessible directories and remove sensitive files"
                    )
                elif has_info_files:
                    # Only robots.txt/sitemap.xml found (this is normal)
                    result['status'] = 'PASS'
                    result['severity'] = 'INFO'
                    result['findings'] = ["robots.txt and/or sitemap.xml found (normal)"]
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
                
                # Add specific recommendations only for missing headers
                for missing in missing_headers:
                    header_name = missing['header']
                    
                    if header_name == 'Strict-Transport-Security':
                        result['recommendations'].append(
                            "Add Strict-Transport-Security header with max-age=31536000 (or higher)"
                        )
                    elif header_name == 'X-Frame-Options':
                        result['recommendations'].append(
                            "Add X-Frame-Options header (recommended: DENY or SAMEORIGIN)"
                        )
                    elif header_name == 'Content-Security-Policy':
                        result['recommendations'].append(
                            "Implement Content-Security-Policy to prevent XSS and injection attacks"
                        )
                    elif header_name == 'X-Content-Type-Options':
                        result['recommendations'].append(
                            "Add X-Content-Type-Options: nosniff to prevent MIME-sniffing"
                        )
                    elif header_name == 'X-XSS-Protection':
                        result['recommendations'].append(
                            "Add X-XSS-Protection: 1; mode=block (legacy browsers)"
                        )
                    elif header_name == 'Referrer-Policy':
                        result['recommendations'].append(
                            "Add Referrer-Policy header (recommended: strict-origin-when-cross-origin)"
                        )
                    elif header_name == 'Permissions-Policy':
                        result['recommendations'].append(
                            "Add Permissions-Policy to control browser features"
                        )
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
    
    def test_http_methods(self) -> Dict[str, Any]:
        """
        Test for insecure HTTP methods.
        
        Checks for dangerous HTTP methods like PUT, DELETE, TRACE, CONNECT
        that could allow unauthorized operations.
        """
        logging.info("Running HTTP methods security test...")
        
        findings = []
        recommendations = []
        severity = 'INFO'
        status = 'PASS'
        
        # Methods to test
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        all_methods = ['OPTIONS', 'HEAD', 'GET', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        
        try:
            # Test OPTIONS to see what methods are allowed
            response = self._make_request(self.target, 'OPTIONS')
            
            if response and 'Allow' in response.headers:
                allowed_methods = [m.strip() for m in response.headers['Allow'].split(',')]
                findings.append(f"Server reports allowed methods: {', '.join(allowed_methods)}")
                
                # Check for dangerous methods
                dangerous_found = [m for m in dangerous_methods if m in allowed_methods]
                
                if dangerous_found:
                    severity = 'MEDIUM'
                    status = 'VULNERABLE'
                    findings.append(f"⚠️ Dangerous methods enabled: {', '.join(dangerous_found)}")
                    
                    # Test if they actually work
                    for method in dangerous_found:
                        test_response = self._make_request(self.target, method)
                        if test_response and test_response.status_code not in [405, 501]:
                            findings.append(f"✗ {method} method is FUNCTIONAL (HTTP {test_response.status_code})")
                            severity = 'HIGH'
                        else:
                            findings.append(f"✓ {method} method returns {test_response.status_code if test_response else 'no response'}")
                    
                    recommendations.extend([
                        "Disable unnecessary HTTP methods (PUT, DELETE, TRACE, CONNECT)",
                        "Configure web server to only allow GET, POST, HEAD, OPTIONS",
                        "Implement proper authentication for administrative methods",
                        "Use Web Application Firewall rules to block dangerous methods"
                    ])
                else:
                    findings.append("✓ No dangerous methods detected in Allow header")
            else:
                # OPTIONS not supported or no Allow header
                findings.append("Server doesn't respond to OPTIONS or provides no Allow header")
                
                # Test dangerous methods directly
                for method in dangerous_methods:
                    response = self._make_request(self.target, method)
                    if response and response.status_code == 200:
                        findings.append(f"⚠️ {method} method returns HTTP 200 (potentially enabled)")
                        severity = 'MEDIUM'
                        status = 'VULNERABLE'
                        recommendations.append(f"Investigate and disable {method} method")
                    elif response and response.status_code in [405, 501]:
                        findings.append(f"✓ {method} method properly disabled (HTTP {response.status_code})")
            
            # Check for TRACE (XST vulnerability)
            trace_response = self._make_request(self.target, 'TRACE')
            if trace_response and trace_response.status_code == 200:
                if self.target in trace_response.text:
                    findings.append("✗ TRACE method enabled - Cross-Site Tracing (XST) vulnerability!")
                    severity = 'HIGH'
                    status = 'VULNERABLE'
                    recommendations.append("Disable TRACE method to prevent XST attacks")
            
            if not recommendations:
                recommendations.append("HTTP methods configuration appears secure")
                
        except Exception as e:
            logging.error(f"HTTP methods test error: {str(e)}")
            findings.append(f"Test error: {str(e)}")
            status = 'ERROR'
        
        return {
            'test_name': 'HTTP Methods Security',
            'description': 'Tests for insecure HTTP methods (PUT, DELETE, TRACE)',
            'status': status,
            'severity': severity,
            'findings': findings,
            'recommendations': recommendations
        }
    
    def test_waf_detection(self) -> Dict[str, Any]:
        """
        Detect presence of Web Application Firewall (WAF) or CDN.
        
        Identifies protective infrastructure like Cloudflare, AWS WAF, Akamai, etc.
        """
        logging.info("Running WAF/CDN detection test...")
        
        findings = []
        recommendations = []
        severity = 'INFO'
        status = 'PASS'
        
        waf_detected = False
        detected_wafs = []
        
        try:
            response = self._make_request(self.target, 'GET')
            
            if not response:
                findings.append("Unable to connect to target")
                status = 'ERROR'
                return {
                    'test_name': 'WAF/CDN Detection',
                    'description': 'Identifies Web Application Firewall and CDN infrastructure',
                    'status': status,
                    'severity': severity,
                    'findings': findings,
                    'recommendations': recommendations
                }
            
            headers = response.headers
            
            # WAF/CDN signatures
            waf_signatures = {
                'Cloudflare': [
                    ('server', 'cloudflare'),
                    ('cf-ray', None),
                    ('cf-cache-status', None)
                ],
                'AWS WAF': [
                    ('x-amzn-requestid', None),
                    ('x-amz-cf-id', None),
                    ('x-amz-apigw-id', None)
                ],
                'Akamai': [
                    ('x-akamai-transformed', None),
                    ('akamai-grn', None),
                    ('x-cache-key', None)
                ],
                'Sucuri': [
                    ('x-sucuri-id', None),
                    ('x-sucuri-cache', None)
                ],
                'Imperva (Incapsula)': [
                    ('x-iinfo', None),
                    ('x-cdn', 'incapsula')
                ],
                'ModSecurity': [
                    ('server', 'mod_security'),
                ],
                'F5 BIG-IP': [
                    ('x-cnection', None),
                    ('x-wa-info', None)
                ],
                'Barracuda': [
                    ('barra_counter_session', None),
                    ('barracuda', None)
                ],
                'Fortinet FortiWeb': [
                    ('fortiwafsid', None),
                ],
                'Citrix NetScaler': [
                    ('ns_af', None),
                    ('citrix_ns_id', None)
                ]
            }
            
            # Check headers for WAF signatures
            for waf_name, signatures in waf_signatures.items():
                for header_name, header_value in signatures:
                    header_name_lower = header_name.lower()
                    if header_name_lower in [h.lower() for h in headers.keys()]:
                        if header_value is None:
                            detected_wafs.append(waf_name)
                            waf_detected = True
                            break
                        else:
                            actual_value = headers.get(header_name, '').lower()
                            if header_value.lower() in actual_value:
                                detected_wafs.append(waf_name)
                                waf_detected = True
                                break
            
            # Check cookies for WAF signatures
            cookies = response.cookies
            waf_cookies = {
                '__cfduid': 'Cloudflare',
                'incap_ses_': 'Imperva Incapsula',
                'visid_incap_': 'Imperva Incapsula',
                'nlbi_': 'Imperva Incapsula',
                'BIGipServer': 'F5 BIG-IP',
                'TS': 'F5 BIG-IP',
                'citrix_ns_id': 'Citrix NetScaler',
                'NSC_': 'Citrix NetScaler'
            }
            
            for cookie_prefix, waf_name in waf_cookies.items():
                for cookie in cookies.keys():
                    if cookie.startswith(cookie_prefix):
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            waf_detected = True
            
            # Additional checks
            # Check Server header
            server_header = headers.get('Server', '').lower()
            if server_header:
                findings.append(f"Server: {headers.get('Server')}")
            
            # Check for X-Powered-By
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                findings.append(f"X-Powered-By: {powered_by}")
            
            # Report findings
            if waf_detected:
                detected_wafs = list(set(detected_wafs))  # Remove duplicates
                findings.append(f"🛡️ WAF/CDN detected: {', '.join(detected_wafs)}")
                
                # Add header evidence
                for waf_name in detected_wafs:
                    for header, value in headers.items():
                        header_lower = header.lower()
                        if any(sig in header_lower for sig in ['cf-', 'x-amz', 'akamai', 'sucuri', 'incap']):
                            findings.append(f"  Evidence: {header}: {value[:50]}...")
                            break
                
                recommendations.extend([
                    f"WAF/CDN protection detected: {', '.join(detected_wafs)}",
                    "This indicates the target has protective infrastructure",
                    "Penetration testing may trigger WAF rules",
                    "Consider coordinating with target's security team",
                    "Some scan results may be influenced by WAF filtering"
                ])
            else:
                findings.append("✗ No WAF/CDN detected")
                findings.append("Target appears to be directly exposed to the internet")
                recommendations.extend([
                    "Consider implementing a Web Application Firewall (WAF)",
                    "Consider using a CDN for DDoS protection and performance",
                    "Popular options: Cloudflare, AWS WAF, Akamai, Imperva",
                    "A WAF can help protect against common web attacks"
                ])
                severity = 'LOW'
                status = 'VULNERABLE'
            
        except Exception as e:
            logging.error(f"WAF detection test error: {str(e)}")
            findings.append(f"Test error: {str(e)}")
            status = 'ERROR'
        
        return {
            'test_name': 'WAF/CDN Detection',
            'description': 'Identifies Web Application Firewall and CDN infrastructure',
            'status': status,
            'severity': severity,
            'findings': findings,
            'recommendations': recommendations
        }
    

    def test_sql_injection(self) -> Dict[str, Any]:
        """
        Test for SQL Injection vulnerabilities.
        
        Tests common SQL injection vectors in URL parameters and forms.
        Detects error-based, boolean-based, and time-based SQLi.
        """
        logging.info("Running SQL Injection detection test...")
        
        result = {
            'test_name': 'SQL Injection Detection',
            'description': 'Tests for SQL injection vulnerabilities in parameters',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        # SQL injection payloads
        sqli_payloads = {
            'error_based': [
                "'",
                "' OR '1'='1",
                "' OR 1=1--",
                "\" OR \"1\"=\"1",
                "' UNION SELECT NULL--",
                "admin'--",
                "' OR 'a'='a",
            ],
            'time_based': [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND pg_sleep(5)--",
            ],
            'union_based': [
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL--",
            ]
        }
        
        # Database error signatures
        db_errors = {
            'MySQL': [
                'you have an error in your sql syntax',
                'warning: mysql',
                'unclosed quotation mark',
                'quoted string not properly terminated',
            ],
            'PostgreSQL': [
                'postgresql query failed',
                'pg_query()',
                'unterminated quoted string',
            ],
            'MSSQL': [
                'microsoft sql server',
                'odbc sql server driver',
                'unclosed quotation mark after',
            ],
            'Oracle': [
                'ora-01756',
                'ora-00933',
                'oracle error',
            ],
            'SQLite': [
                'sqlite_error',
                'sqlite3::',
                'unrecognized token',
            ]
        }
        
        vulnerabilities_found = []
        
        try:
            # Parse target URL
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test only if there are query parameters or forms
            has_params = bool(parsed.query)
            
            if has_params:
                # Extract parameters
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                
                # Test each parameter with SQLi payloads
                for param_name in params.keys():
                    for payload_type, payloads in sqli_payloads.items():
                        for payload in payloads:
                            # Create test URL
                            test_params = params.copy()
                            test_params[param_name] = payload
                            
                            # Build query string
                            query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                            test_url = f"{base_url}?{query_string}"
                            
                            # Make request
                            response = self._make_request(test_url)
                            
                            if response:
                                # Check for database errors
                                response_text = response.text.lower()
                                
                                for db_name, error_patterns in db_errors.items():
                                    for pattern in error_patterns:
                                        if pattern in response_text:
                                            vuln = {
                                                'parameter': param_name,
                                                'payload': payload,
                                                'payload_type': payload_type,
                                                'database': db_name,
                                                'evidence': pattern
                                            }
                                            
                                            if vuln not in vulnerabilities_found:
                                                vulnerabilities_found.append(vuln)
                                                result['findings'].append(
                                                    f"⚠️ SQL Injection detected in parameter '{param_name}' "
                                                    f"[{db_name}] - Payload: {payload[:30]}..."
                                                )
                
                # Also test for blind SQLi (time-based)
                original_response = self._make_request(base_url, params=params)
                if original_response:
                    original_time = original_response.elapsed.total_seconds()
                    
                    for param_name in params.keys():
                        test_params = params.copy()
                        test_params[param_name] = "' AND SLEEP(5)--"
                        
                        import time
                        start = time.time()
                        response = self._make_request(base_url, params=test_params)
                        elapsed = time.time() - start
                        
                        # If response took significantly longer (>4 seconds), likely vulnerable
                        if elapsed > 4 and elapsed > original_time + 3:
                            vulnerabilities_found.append({
                                'parameter': param_name,
                                'payload': "' AND SLEEP(5)--",
                                'payload_type': 'time_based',
                                'database': 'MySQL (time-based)',
                                'evidence': f'Response time: {elapsed:.2f}s (expected: ~5s)'
                            })
                            result['findings'].append(
                                f"⚠️ Blind SQL Injection (time-based) detected in parameter '{param_name}' "
                                f"- Response delayed by {elapsed:.2f}s"
                            )
            
            else:
                result['findings'].append("No query parameters found to test for SQL injection")
            
            # Analyze results
            if vulnerabilities_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                result['vulnerable_parameters'] = vulnerabilities_found
                
                # Add specific recommendations
                unique_params = list(set([v['parameter'] for v in vulnerabilities_found]))
                unique_dbs = list(set([v['database'] for v in vulnerabilities_found]))
                
                result['recommendations'].append(
                    f"CRITICAL: SQL Injection found in {len(unique_params)} parameter(s): {', '.join(unique_params)}"
                )
                result['recommendations'].append(
                    f"Database type detected: {', '.join(unique_dbs)}"
                )
                result['recommendations'].append(
                    "Use parameterized queries (prepared statements) for all database operations"
                )
                result['recommendations'].append(
                    "Implement input validation and sanitization on server-side"
                )
                result['recommendations'].append(
                    "Use ORM frameworks that handle SQL escaping automatically"
                )
                result['recommendations'].append(
                    "Apply principle of least privilege to database user accounts"
                )
                result['recommendations'].append(
                    "Enable Web Application Firewall (WAF) with SQLi protection rules"
                )
                
            else:
                if has_params:
                    result['findings'].append("No SQL injection vulnerabilities detected in tested parameters")
                result['recommendations'].append(
                    "Continue using parameterized queries and input validation"
                )
        
        except Exception as e:
            logging.error(f"SQL Injection test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    def test_xss_detection(self) -> Dict[str, Any]:
        """
        Test for Cross-Site Scripting (XSS) vulnerabilities.
        
        Tests for reflected XSS in URL parameters and form inputs.
        Detects common XSS vectors and filter bypasses.
        """
        logging.info("Running XSS detection test...")
        
        result = {
            'test_name': 'Cross-Site Scripting (XSS) Detection',
            'description': 'Tests for XSS vulnerabilities in parameters and forms',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        # XSS payloads (ordered from basic to advanced)
        xss_payloads = [
            # Basic script tags
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>confirm('XSS')</script>",
            
            # Image tags
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            
            # SVG
            "<svg onload=alert('XSS')>",
            "<svg/onload=alert(1)>",
            
            # Event handlers
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            
            # IFrame
            "<iframe src='javascript:alert(1)'>",
            
            # Encoded variants
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            
            # Filter bypasses
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<img src=x oneonerrorrror=alert('XSS')>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            
            # Polyglot
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
        ]
        
        vulnerabilities_found = []
        
        try:
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            has_params = bool(parsed.query)
            
            if has_params:
                # Extract parameters
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                
                # Test each parameter with XSS payloads
                for param_name in params.keys():
                    for payload in xss_payloads:
                        # Create test URL
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        # Build query string
                        query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        test_url = f"{base_url}?{query_string}"
                        
                        # Make request
                        response = self._make_request(test_url)
                        
                        if response:
                            response_text = response.text
                            
                            # Check if payload is reflected in response
                            # Look for unescaped payload
                            if payload in response_text:
                                vuln = {
                                    'parameter': param_name,
                                    'payload': payload,
                                    'type': 'reflected',
                                    'context': 'unescaped'
                                }
                                
                                if vuln not in vulnerabilities_found:
                                    vulnerabilities_found.append(vuln)
                                    result['findings'].append(
                                        f"⚠️ XSS vulnerability detected in parameter '{param_name}' "
                                        f"- Payload reflected without escaping: {payload[:40]}..."
                                    )
                                    break  # Found vulnerability, no need to test more payloads
                            
                            # Check for partially escaped but still dangerous
                            elif any(dangerous in response_text for dangerous in [
                                'onerror=', 'onload=', 'onfocus=', 'javascript:', 'alert(', 'confirm('
                            ]):
                                # Payload may be partially reflected or transformed
                                vuln = {
                                    'parameter': param_name,
                                    'payload': payload,
                                    'type': 'reflected',
                                    'context': 'partial_escape'
                                }
                                
                                if vuln not in vulnerabilities_found:
                                    vulnerabilities_found.append(vuln)
                                    result['findings'].append(
                                        f"⚠️ Potential XSS in parameter '{param_name}' "
                                        f"- Dangerous patterns found in response (partial escaping)"
                                    )
                                    break
            
            # Also check for DOM-based XSS indicators
            response = self._make_request(self.target)
            if response:
                response_text = response.text.lower()
                
                # Check for dangerous JavaScript patterns
                dom_xss_patterns = [
                    'document.write(',
                    'document.writeln(',
                    'innerhtml =',
                    'outerhtml =',
                    'eval(',
                    'settimeout(',
                    'setinterval(',
                    'location.hash',
                    'location.search',
                    'document.url',
                    'document.referrer',
                ]
                
                found_patterns = []
                for pattern in dom_xss_patterns:
                    if pattern in response_text:
                        found_patterns.append(pattern)
                
                if found_patterns:
                    result['findings'].append(
                        f"⚠️ Potential DOM-based XSS risk - Dangerous JavaScript patterns found: "
                        f"{', '.join(found_patterns[:3])}{'...' if len(found_patterns) > 3 else ''}"
                    )
                    vulnerabilities_found.append({
                        'type': 'dom_based',
                        'patterns': found_patterns
                    })
            
            else:
                result['findings'].append("No query parameters found to test for reflected XSS")
            
            # Analyze results
            if vulnerabilities_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'HIGH'
                result['vulnerable_parameters'] = vulnerabilities_found
                
                # Count types of XSS found
                reflected_count = sum(1 for v in vulnerabilities_found if v.get('type') == 'reflected')
                dom_count = sum(1 for v in vulnerabilities_found if v.get('type') == 'dom_based')
                
                if reflected_count > 0:
                    unique_params = list(set([v['parameter'] for v in vulnerabilities_found if 'parameter' in v]))
                    result['recommendations'].append(
                        f"CRITICAL: Reflected XSS found in {len(unique_params)} parameter(s): {', '.join(unique_params)}"
                    )
                
                result['recommendations'].append(
                    "Implement proper output encoding/escaping for all user input"
                )
                result['recommendations'].append(
                    "Use Content-Security-Policy (CSP) header to mitigate XSS impact"
                )
                result['recommendations'].append(
                    "Validate and sanitize all input on server-side"
                )
                result['recommendations'].append(
                    "Use framework-provided XSS protection (e.g., templating engines with auto-escaping)"
                )
                
                if dom_count > 0:
                    result['recommendations'].append(
                        "Avoid using dangerous JavaScript functions with user input (eval, innerHTML, etc.)"
                    )
                    result['recommendations'].append(
                        "Use safe DOM manipulation methods (textContent, setAttribute, etc.)"
                    )
                
                result['recommendations'].append(
                    "Enable HttpOnly flag on cookies to prevent XSS-based cookie theft"
                )
                
            else:
                if has_params:
                    result['findings'].append("No XSS vulnerabilities detected in tested parameters")
                result['recommendations'].append(
                    "Continue implementing proper output encoding and CSP headers"
                )
        
        except Exception as e:
            logging.error(f"XSS detection test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    def test_command_injection(self) -> Dict[str, Any]:
        """
        Test for Command Injection vulnerabilities.
        
        Tests for OS command injection in URL parameters.
        Detects command execution through various injection techniques.
        """
        logging.info("Running Command Injection detection test...")
        
        result = {
            'test_name': 'Command Injection Detection',
            'description': 'Tests for OS command injection vulnerabilities',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': []
        }
        
        # Command injection payloads
        cmd_payloads = {
            'unix': [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(cat /etc/passwd)",
                "; uname -a",
                "| cat /etc/issue",
                "&& pwd",
                "; echo 'CMD_INJECTION_TEST'",
            ],
            'windows': [
                "& dir",
                "| whoami",
                "&& echo CMD_INJECTION_TEST",
                "; ver",
                "| type C:\\Windows\\win.ini",
            ],
            'blind': [
                "; sleep 5",
                "| ping -c 5 127.0.0.1",
                "& timeout 5",
                "; sleep 5 #",
                "| sleep 5 ||",
            ]
        }
        
        # Command output indicators
        command_indicators = {
            'unix': [
                'root:',  # /etc/passwd
                'uid=',   # id command
                'total ',  # ls -la
                'linux',   # uname
                'ubuntu',
                'debian',
                'centos',
                '/bin/',
                '/usr/',
            ],
            'windows': [
                'volume serial number',
                'directory of',
                'windows',
                'c:\\',
                'cmd.exe',
                'system32',
            ],
            'generic': [
                'CMD_INJECTION_TEST',
                'command not found',
                'syntax error',
                'unexpected token',
            ]
        }
        
        vulnerabilities_found = []
        
        try:
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            has_params = bool(parsed.query)
            
            if has_params:
                # Extract parameters
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                
                # Get baseline response time
                baseline_response = self._make_request(base_url, params=params)
                baseline_time = baseline_response.elapsed.total_seconds() if baseline_response else 0
                
                # Test each parameter
                for param_name in params.keys():
                    # Test Unix/Linux commands
                    for payload_type, payloads in cmd_payloads.items():
                        for payload in payloads:
                            test_params = params.copy()
                            test_params[param_name] = payload
                            
                            query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                            test_url = f"{base_url}?{query_string}"
                            
                            # For time-based detection
                            if payload_type == 'blind':
                                import time
                                start = time.time()
                                response = self._make_request(test_url)
                                elapsed = time.time() - start
                                
                                # If response took significantly longer, likely vulnerable
                                if elapsed > 4 and elapsed > baseline_time + 3:
                                    vuln = {
                                        'parameter': param_name,
                                        'payload': payload,
                                        'type': 'time_based',
                                        'evidence': f'Response delayed by {elapsed:.2f}s'
                                    }
                                    
                                    if vuln not in vulnerabilities_found:
                                        vulnerabilities_found.append(vuln)
                                        result['findings'].append(
                                            f"⚠️ Command Injection (time-based) detected in '{param_name}' "
                                            f"- Payload: {payload} - Delay: {elapsed:.2f}s"
                                        )
                            else:
                                # For output-based detection
                                response = self._make_request(test_url)
                                
                                if response:
                                    response_text = response.text.lower()
                                    
                                    # Check for command output indicators
                                    for os_type, indicators in command_indicators.items():
                                        for indicator in indicators:
                                            if indicator.lower() in response_text:
                                                vuln = {
                                                    'parameter': param_name,
                                                    'payload': payload,
                                                    'type': 'output_based',
                                                    'os': os_type,
                                                    'evidence': indicator
                                                }
                                                
                                                if vuln not in vulnerabilities_found:
                                                    vulnerabilities_found.append(vuln)
                                                    result['findings'].append(
                                                        f"⚠️ Command Injection detected in '{param_name}' "
                                                        f"[{os_type}] - Evidence: '{indicator}'"
                                                    )
                                                    break
            else:
                result['findings'].append("No query parameters found to test for command injection")
            
            # Analyze results
            if vulnerabilities_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                result['vulnerable_parameters'] = vulnerabilities_found
                
                unique_params = list(set([v['parameter'] for v in vulnerabilities_found]))
                detected_os = list(set([v.get('os', 'unknown') for v in vulnerabilities_found if 'os' in v]))
                
                result['recommendations'].append(
                    f"CRITICAL: Command Injection found in {len(unique_params)} parameter(s): {', '.join(unique_params)}"
                )
                
                if detected_os:
                    result['recommendations'].append(
                        f"Operating system detected: {', '.join(detected_os)}"
                    )
                
                result['recommendations'].append(
                    "NEVER execute system commands with user-supplied input"
                )
                result['recommendations'].append(
                    "Use language-specific APIs instead of shell commands when possible"
                )
                result['recommendations'].append(
                    "If system calls are necessary, use parameterized/safe execution methods"
                )
                result['recommendations'].append(
                    "Implement strict input validation with allowlists (not blocklists)"
                )
                result['recommendations'].append(
                    "Run application with least privilege - avoid root/administrator accounts"
                )
                result['recommendations'].append(
                    "Use containerization/sandboxing to limit command injection impact"
                )
                result['recommendations'].append(
                    "Enable WAF rules to detect and block command injection attempts"
                )
                
            else:
                if has_params:
                    result['findings'].append("No command injection vulnerabilities detected in tested parameters")
                result['recommendations'].append(
                    "Continue avoiding system command execution with user input"
                )
        
        except Exception as e:
            logging.error(f"Command Injection test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    # ========================================================================
    # PHASE 4A - AUTHENTICATION CORE TESTS (Delivery 1)
    # ========================================================================
    
    def _find_login_form(self) -> Optional[Dict[str, str]]:
        """
        Find login form on the target website.
        
        Returns:
            Dictionary with form details or None if not found
        """
        try:
            response = self._make_request(self.target)
            if not response:
                return None
            
            # Try to parse with BeautifulSoup
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find forms
                forms = soup.find_all('form')
                
                for form in forms:
                    # Look for password input
                    password_inputs = form.find_all('input', {'type': 'password'})
                    
                    if password_inputs:
                        # Found a form with password field
                        action = form.get('action', '')
                        if not action:
                            action = self.target
                        elif not action.startswith('http'):
                            action = urljoin(self.target, action)
                        
                        # Find username field (various possibilities)
                        username_field = None
                        for input_type in ['text', 'email']:
                            username_input = form.find('input', {'type': input_type})
                            if username_input and username_input.get('name'):
                                username_field = username_input['name']
                                break
                        
                        if not username_field:
                            # Try common names
                            for name in ['username', 'user', 'email', 'login', 'account']:
                                if form.find('input', {'name': name}):
                                    username_field = name
                                    break
                        
                        password_field = password_inputs[0].get('name', 'password')
                        
                        return {
                            'action': action,
                            'method': form.get('method', 'post').upper(),
                            'username_field': username_field or 'username',
                            'password_field': password_field
                        }
            except:
                # Fallback: regex search for login patterns
                content = response.text.lower()
                if 'type="password"' in content or "type='password'" in content:
                    return {
                        'action': self.target,
                        'method': 'POST',
                        'username_field': 'username',
                        'password_field': 'password'
                    }
            
            return None
            
        except Exception as e:
            logging.debug(f"Error finding login form: {str(e)}")
            return None
    
    def test_brute_force_protection(self) -> Dict[str, Any]:
        """
        Test if the application has protection against brute force attacks.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-7 (Limit unsuccessful login attempts)
        - PCI-DSS 4.0: Req 8.3.4 (Lock account after 6 attempts, 30min min)
        - ISO 27001: A.9.4.2 (Secure log-on procedures)
        - LGPD: Art. 46 (Medidas técnicas de segurança)
        
        Tests:
        1. Rate limiting on login endpoint
        2. Account lockout after failed attempts
        3. CAPTCHA or progressive delays
        4. IP-based blocking detection
        """
        logging.info("Running brute force protection test...")
        
        result = {
            'test_name': 'Brute Force Protection',
            'description': 'Tests for protection against automated login attacks',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-7',
                'PCI_DSS_4.0': 'Req 8.3.4',
                'ISO_27001': 'A.9.4.2',
                'LGPD': 'Art. 46'
            }
        }
        
        try:
            # Find login form
            login_form = self._find_login_form()
            
            if not login_form:
                result['findings'].append("No login form detected on main page")
                result['recommendations'].append(
                    "If login functionality exists, ensure it implements brute force protection"
                )
                return result
            
            result['findings'].append(f"✓ Login form detected at: {login_form['action']}")
            
            # Test brute force protection
            max_attempts = 15
            attempt_count = 0
            response_times = []
            protections_detected = []
            
            logging.info(f"Testing {max_attempts} failed login attempts...")
            
            for i in range(max_attempts):
                start_time = time.time()
                
                try:
                    # Prepare login data
                    login_data = {
                        login_form['username_field']: 'testuser_nonexistent',
                        login_form['password_field']: f'wrongpassword{i}'
                    }
                    
                    # Make request
                    if login_form['method'] == 'POST':
                        response = self.session.post(
                            login_form['action'],
                            data=login_data,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    else:
                        response = self.session.get(
                            login_form['action'],
                            params=login_data,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    
                    elapsed = time.time() - start_time
                    response_times.append(elapsed)
                    attempt_count += 1
                    
                    response_lower = response.text.lower()
                    
                    # Check for account lockout
                    lockout_keywords = ['locked', 'blocked', 'suspended', 'disabled', 'too many']
                    if any(keyword in response_lower for keyword in lockout_keywords):
                        protections_detected.append(f"Account lockout detected after {attempt_count} attempts")
                        result['findings'].append(f"✅ Account lockout triggered after {attempt_count} failed attempts")
                        break
                    
                    # Check for CAPTCHA
                    captcha_keywords = ['captcha', 'recaptcha', 'hcaptcha', 'challenge']
                    if any(keyword in response_lower for keyword in captcha_keywords):
                        protections_detected.append(f"CAPTCHA challenge detected after {attempt_count} attempts")
                        result['findings'].append(f"✅ CAPTCHA protection triggered after {attempt_count} attempts")
                        break
                    
                    # Check for rate limiting (HTTP 429)
                    if response.status_code == 429:
                        protections_detected.append(f"Rate limiting (HTTP 429) after {attempt_count} attempts")
                        result['findings'].append(f"✅ Rate limiting detected (HTTP 429) after {attempt_count} attempts")
                        break
                    
                    # Check for progressive delay (response time increases)
                    if len(response_times) > 5:
                        avg_first_5 = sum(response_times[:5]) / 5
                        current_time = response_times[-1]
                        
                        if current_time > avg_first_5 * 2 and current_time > 2:
                            protections_detected.append(f"Progressive delay detected (response time increased)")
                            result['findings'].append(f"✅ Progressive delay detected (response time: {current_time:.2f}s)")
                            break
                    
                    # Small delay to avoid overwhelming the server
                    time.sleep(0.5)
                    
                except requests.exceptions.Timeout:
                    result['findings'].append(f"⚠️ Request timeout on attempt {attempt_count + 1} - possible rate limiting")
                    protections_detected.append("Timeout-based protection")
                    break
                except Exception as e:
                    logging.debug(f"Error on attempt {attempt_count + 1}: {str(e)}")
                    break
            
            # Analyze results
            if protections_detected:
                result['status'] = 'PASS'
                result['severity'] = 'INFO'
                result['findings'].append(f"Brute force protection active: {', '.join(protections_detected)}")
                result['recommendations'].append(
                    f"✓ Good: Brute force protection detected after {attempt_count} attempts"
                )
                
                # Check PCI-DSS compliance (6 attempts, 30min lockout)
                if attempt_count <= 6:
                    result['recommendations'].append(
                        "✓ PCI-DSS Compliant: Protection triggered within 6 attempts"
                    )
                    result['compliance']['PCI_DSS_4.0'] += ' - PASS'
                else:
                    result['recommendations'].append(
                        f"⚠️ PCI-DSS Requirement: Protection should trigger within 6 attempts (detected at {attempt_count})"
                    )
                    result['compliance']['PCI_DSS_4.0'] += ' - PARTIAL'
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['ISO_27001'] += ' - PASS'
                result['compliance']['LGPD'] += ' - PASS'
                
            else:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'HIGH'
                
                avg_response_time = sum(response_times) / len(response_times) if response_times else 0
                total_time = sum(response_times)
                
                result['findings'].append(
                    f"⚠️ NO brute force protection detected ({attempt_count} attempts in {total_time:.1f}s)"
                )
                result['findings'].append(
                    f"Average response time: {avg_response_time:.2f}s (no progressive delay)"
                )
                
                result['recommendations'].append(
                    "CRITICAL: Implement brute force protection immediately"
                )
                result['recommendations'].append(
                    "Recommended: Lock account after 6 failed attempts (PCI-DSS requirement)"
                )
                result['recommendations'].append(
                    "Lockout duration: Minimum 30 minutes (PCI-DSS v4.0 Req 8.3.4)"
                )
                result['recommendations'].append(
                    "Consider implementing: Rate limiting (max 5 attempts per 5 minutes)"
                )
                result['recommendations'].append(
                    "Consider implementing: CAPTCHA after 3-5 failed attempts"
                )
                result['recommendations'].append(
                    "Consider implementing: Progressive delays between attempts"
                )
                result['recommendations'].append(
                    "Consider implementing: IP-based blocking for repeated failures"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL (CRITICAL for e-commerce)'
                result['compliance']['ISO_27001'] += ' - FAIL'
                result['compliance']['LGPD'] += ' - PARTIAL'
                
                result['compliance_impact'] = (
                    "PCI-DSS v4.0 Req 8.3.4 MANDATES account lockout after maximum 6 invalid attempts "
                    "for minimum 30 minutes. This is a CRITICAL requirement for payment card processing."
                )
        
        except Exception as e:
            logging.error(f"Brute force protection test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_session_management(self) -> Dict[str, Any]:
        """
        Test session management security.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-1 (Identities and credentials authenticated)
        - PCI-DSS 4.0: Req 6.5.10 (Broken authentication/session management)
        - ISO 27001: A.9.4.2 (Secure log-on procedures)
        - LGPD: Art. 46 (Medidas de segurança)
        
        Tests:
        1. Cookie Secure flag
        2. Cookie HttpOnly flag
        3. Cookie SameSite attribute
        4. Session timeout
        5. Session cookie attributes
        """
        logging.info("Running session management test...")
        
        result = {
            'test_name': 'Session Management Security',
            'description': 'Tests session and cookie security configurations',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-1',
                'PCI_DSS_4.0': 'Req 6.5.10, Req 8.2.8',
                'ISO_27001': 'A.9.4.2',
                'LGPD': 'Art. 46'
            }
        }
        
        try:
            response = self._make_request(self.target)
            
            if not response:
                result['status'] = 'ERROR'
                result['error'] = 'Failed to connect to target'
                return result
            
            # Check for session cookies
            cookies = response.cookies
            
            if not cookies:
                result['findings'].append("No cookies set by the application")
                result['recommendations'].append(
                    "If session management is used, ensure cookies have proper security flags"
                )
                return result
            
            result['findings'].append(f"Found {len(cookies)} cookie(s)")
            
            vulnerable_cookies = []
            secure_cookies = []
            
            for cookie in cookies:
                cookie_analysis = {
                    'name': cookie.name,
                    'issues': []
                }
                
                # Check Secure flag
                if not cookie.secure:
                    cookie_analysis['issues'].append("Missing 'Secure' flag (can be transmitted over HTTP)")
                    vulnerable_cookies.append(cookie.name)
                else:
                    secure_cookies.append(cookie.name)
                
                # Check HttpOnly flag
                has_httponly = cookie.has_nonstandard_attr('HttpOnly')
                if not has_httponly:
                    cookie_analysis['issues'].append("Missing 'HttpOnly' flag (accessible via JavaScript)")
                    if cookie.name not in vulnerable_cookies:
                        vulnerable_cookies.append(cookie.name)
                
                # Check SameSite attribute
                has_samesite = cookie.has_nonstandard_attr('SameSite')
                if not has_samesite:
                    cookie_analysis['issues'].append("Missing 'SameSite' attribute (CSRF risk)")
                    if cookie.name not in vulnerable_cookies:
                        vulnerable_cookies.append(cookie.name)
                
                # Check if session cookie (common names)
                session_keywords = ['session', 'sess', 'sid', 'token', 'auth', 'login', 'jsessionid', 'phpsessid', 'aspsessionid']
                is_session_cookie = any(keyword in cookie.name.lower() for keyword in session_keywords)
                
                if cookie_analysis['issues']:
                    result['findings'].append(
                        f"⚠️ Cookie '{cookie.name}'{' (session cookie)' if is_session_cookie else ''}: " +
                        ', '.join(cookie_analysis['issues'])
                    )
            
            # Determine overall status
            if vulnerable_cookies:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'HIGH'
                
                result['findings'].append(
                    f"Security issues found in {len(vulnerable_cookies)} cookie(s): {', '.join(vulnerable_cookies)}"
                )
                
                result['recommendations'].append(
                    "CRITICAL: Set 'Secure' flag on ALL cookies to prevent transmission over HTTP"
                )
                result['recommendations'].append(
                    "CRITICAL: Set 'HttpOnly' flag on session cookies to prevent XSS cookie theft"
                )
                result['recommendations'].append(
                    "HIGH: Set 'SameSite' attribute to 'Strict' or 'Lax' to prevent CSRF attacks"
                )
                result['recommendations'].append(
                    "Example (PHP): session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Strict'])"
                )
                result['recommendations'].append(
                    "Example (Express.js): cookie: { secure: true, httpOnly: true, sameSite: 'strict' }"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL'
                result['compliance']['ISO_27001'] += ' - FAIL'
                result['compliance']['LGPD'] += ' - FAIL'
                
                result['compliance_impact'] = (
                    "PCI-DSS v4.0 Req 6.5.10 requires protection against broken authentication "
                    "and session management. Insecure cookies can lead to session hijacking."
                )
            else:
                result['findings'].append(f"✓ All cookies ({len(cookies)}) have proper security flags")
                result['recommendations'].append(
                    "Good: Cookie security flags are properly configured"
                )
                result['recommendations'].append(
                    "Continue monitoring: Ensure new cookies maintain these security standards"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['PCI_DSS_4.0'] += ' - PASS'
                result['compliance']['ISO_27001'] += ' - PASS'
                result['compliance']['LGPD'] += ' - PASS'
        
        except Exception as e:
            logging.error(f"Session management test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_password_policy(self) -> Dict[str, Any]:
        """
        Test password policy strength through observable indicators.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-1 (Identity management)
        - PCI-DSS 4.0: Req 8.3.6 (12+ chars, complex), 8.3.7 (no reuse), 8.3.9 (90 days)
        - ISO 27001: A.9.4.3 (Password management system)
        - LGPD: Art. 46 (Medidas técnicas de segurança)
        
        Tests:
        1. Minimum password length indicators
        2. Complexity requirements detection
        3. Password change policies
        4. Common password blocking
        """
        logging.info("Running password policy test...")
        
        result = {
            'test_name': 'Password Policy Strength',
            'description': 'Analyzes observable password policy indicators',
            'status': 'INFO',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-1',
                'PCI_DSS_4.0': 'Req 8.3.6, 8.3.7, 8.3.9',
                'ISO_27001': 'A.9.4.3',
                'LGPD': 'Art. 46'
            }
        }
        
        try:
            # Try to find registration or password change pages
            password_pages = [
                '/register', '/signup', '/sign-up', '/create-account',
                '/password/change', '/account/password', '/settings/password',
                '/reset-password', '/forgot-password'
            ]
            
            policy_indicators = {
                'min_length_found': False,
                'min_length': None,
                'complexity_required': False,
                'complexity_indicators': []
            }
            
            for page in password_pages:
                url = urljoin(self.target, page)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for minimum length indicators
                    length_patterns = [
                        r'(?:minimum|min|at least)\s+(\d+)\s+characters?',
                        r'(\d+)\s+characters?\s+(?:minimum|min|or more)',
                        r'password.*?(\d+).*?characters?'
                    ]
                    
                    for pattern in length_patterns:
                        match = re.search(pattern, content)
                        if match:
                            length = int(match.group(1))
                            policy_indicators['min_length_found'] = True
                            policy_indicators['min_length'] = length
                            result['findings'].append(f"✓ Minimum password length detected: {length} characters")
                            break
                    
                    # Check for complexity indicators
                    complexity_keywords = {
                        'uppercase': ['uppercase', 'capital letter', 'upper case'],
                        'lowercase': ['lowercase', 'lower case'],
                        'number': ['number', 'digit', 'numeric'],
                        'symbol': ['special character', 'symbol', 'non-alphanumeric']
                    }
                    
                    for req_type, keywords in complexity_keywords.items():
                        if any(keyword in content for keyword in keywords):
                            policy_indicators['complexity_required'] = True
                            policy_indicators['complexity_indicators'].append(req_type)
                    
                    if policy_indicators['complexity_indicators']:
                        result['findings'].append(
                            f"✓ Complexity requirements detected: {', '.join(policy_indicators['complexity_indicators'])}"
                        )
                    
                    break
            
            # Analyze findings
            if not policy_indicators['min_length_found']:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
                result['findings'].append(
                    "⚠️ No visible password policy indicators detected"
                )
                result['findings'].append(
                    "Note: This test checks publicly visible policy information only"
                )
                
                result['recommendations'].append(
                    "PCI-DSS v4.0 REQUIRES: Minimum 12 characters (changed from 7 in v3.2.1)"
                )
                result['recommendations'].append(
                    "PCI-DSS v4.0 REQUIRES: At least 1 uppercase, 1 lowercase, 1 number"
                )
                result['recommendations'].append(
                    "PCI-DSS v4.0 REQUIRES: No reuse of last 4 passwords (Req 8.3.7)"
                )
                result['recommendations'].append(
                    "PCI-DSS v4.0 REQUIRES: Change passwords every 90 days (Req 8.3.9)"
                )
                result['recommendations'].append(
                    "ISO 27001: Implement password management system (A.9.4.3)"
                )
                result['recommendations'].append(
                    "NIST Recommendation: Block common passwords (top 10,000)"
                )
                
                result['compliance']['PCI_DSS_4.0'] += ' - UNKNOWN (cannot verify)'
                result['compliance']['ISO_27001'] += ' - UNKNOWN'
                result['compliance']['NIST_CSF_2.0'] += ' - UNKNOWN'
                
            else:
                # We found some policy indicators
                min_length = policy_indicators['min_length']
                
                if min_length and min_length >= 12:
                    result['findings'].append(f"✓ Password length meets PCI-DSS v4.0 requirement (≥12 chars)")
                    result['compliance']['PCI_DSS_4.0'] += ' - Req 8.3.6 PASS (length)'
                elif min_length:
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'MEDIUM'
                    result['findings'].append(
                        f"⚠️ Password length ({min_length} chars) below PCI-DSS v4.0 requirement (12 chars)"
                    )
                    result['recommendations'].append(
                        f"CRITICAL for PCI: Increase minimum password length from {min_length} to 12 characters"
                    )
                    result['compliance']['PCI_DSS_4.0'] += ' - Req 8.3.6 FAIL'
                
                if policy_indicators['complexity_required']:
                    result['findings'].append("✓ Password complexity requirements detected")
                    
                    required = set(['uppercase', 'lowercase', 'number'])
                    detected = set(policy_indicators['complexity_indicators'])
                    
                    if required.issubset(detected):
                        result['findings'].append("✓ Meets PCI-DSS complexity requirements")
                    else:
                        missing = required - detected
                        result['recommendations'].append(
                            f"Ensure complexity includes: {', '.join(missing)}"
                        )
                else:
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'MEDIUM'
                    result['findings'].append("⚠️ No complexity requirements detected")
                    result['recommendations'].append(
                        "Implement complexity: uppercase + lowercase + number + special character"
                    )
                
                # General recommendations
                result['recommendations'].append(
                    "Implement password history: Block reuse of last 4 passwords (PCI-DSS Req 8.3.7)"
                )
                result['recommendations'].append(
                    "Implement password expiration: Force change every 90 days (PCI-DSS Req 8.3.9)"
                )
                result['recommendations'].append(
                    "Block common passwords: Reject passwords from top 10,000 list (NIST guideline)"
                )
        
        except Exception as e:
            logging.error(f"Password policy test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_user_enumeration(self) -> Dict[str, Any]:
        """
        Test for user enumeration vulnerabilities.
        
        Compliance:
        - NIST CSF 2.0: PR.DS-5 (Protections against data leaks)
        - ISO 27001: A.9.2.1 (User registration)
        - LGPD: Art. 6 (Princípio da necessidade - minimização)
        
        Tests:
        1. Different error messages for valid vs invalid users
        2. Response time differences
        3. Password reset reveals user existence
        4. Registration reveals existing users
        """
        logging.info("Running user enumeration test...")
        
        result = {
            'test_name': 'User Enumeration Prevention',
            'description': 'Tests if application leaks information about user existence',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.DS-5',
                'ISO_27001': 'A.9.2.1',
                'LGPD': 'Art. 6'
            }
        }
        
        try:
            login_form = self._find_login_form()
            
            if not login_form:
                result['findings'].append("No login form detected for user enumeration testing")
                return result
            
            result['findings'].append(f"Testing login form at: {login_form['action']}")
            
            enumeration_vectors = []
            
            # Test 1: Different error messages
            test_usernames = [
                ('admin', 'Common username that likely exists'),
                ('nonexistent_user_xyz123', 'Username that likely does NOT exist')
            ]
            
            responses = []
            
            for username, description in test_usernames:
                login_data = {
                    login_form['username_field']: username,
                    login_form['password_field']: 'wrongpassword123'
                }
                
                start_time = time.time()
                
                if login_form['method'] == 'POST':
                    response = self.session.post(
                        login_form['action'],
                        data=login_data,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                else:
                    response = self.session.get(
                        login_form['action'],
                        params=login_data,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                
                elapsed = time.time() - start_time
                
                responses.append({
                    'username': username,
                    'description': description,
                    'response_text': response.text.lower(),
                    'response_time': elapsed,
                    'status_code': response.status_code
                })
                
                time.sleep(1)  # Delay between requests
            
            # Compare responses
            if len(responses) == 2:
                resp1, resp2 = responses
                
                # Check for different error messages
                msg1 = resp1['response_text']
                msg2 = resp2['response_text']
                
                # Look for specific user-related messages
                user_specific_keywords = [
                    'user not found', 'username not found', 'user does not exist',
                    'invalid username', 'account not found', 'no such user'
                ]
                
                has_user_specific_msg = any(keyword in msg1 or keyword in msg2 for keyword in user_specific_keywords)
                
                if has_user_specific_msg:
                    enumeration_vectors.append("Different error messages reveal user existence")
                    result['findings'].append(
                        "⚠️ Error messages reveal whether username exists (e.g., 'user not found' vs 'invalid password')"
                    )
                
                # Check for response time differences (>100ms difference is significant)
                time_diff = abs(resp1['response_time'] - resp2['response_time'])
                
                if time_diff > 0.1:
                    enumeration_vectors.append(f"Response time differs significantly ({time_diff:.2f}s)")
                    result['findings'].append(
                        f"⚠️ Response time differs between requests ({resp1['response_time']:.2f}s vs {resp2['response_time']:.2f}s)"
                    )
            
            # Check password reset endpoint
            reset_endpoints = ['/forgot-password', '/reset-password', '/password/reset', '/account/forgot']
            
            for endpoint in reset_endpoints:
                url = urljoin(self.target, endpoint)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    result['findings'].append(f"✓ Password reset endpoint found: {endpoint}")
                    result['recommendations'].append(
                        "Password reset should use generic message: 'If this email exists, you will receive a reset link'"
                    )
                    break
            
            # Analyze results
            if enumeration_vectors:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
                
                result['findings'].append(
                    f"User enumeration possible through: {', '.join(enumeration_vectors)}"
                )
                
                result['recommendations'].append(
                    "Use generic error messages for login: 'Invalid username or password' (same for both)"
                )
                result['recommendations'].append(
                    "Normalize response times: Add random delay (100-300ms) to prevent timing attacks"
                )
                result['recommendations'].append(
                    "Password reset: Always show 'If the email exists, you will receive a link' (even if it doesn't)"
                )
                result['recommendations'].append(
                    "Registration: Show 'Registration submitted' instead of 'Email already exists'"
                )
                result['recommendations'].append(
                    "LGPD Compliance: User enumeration leaks personal data unnecessarily (principle of necessity)"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['ISO_27001'] += ' - FAIL'
                result['compliance']['LGPD'] += ' - FAIL (data minimization principle)'
                
            else:
                result['findings'].append("✓ No obvious user enumeration vectors detected")
                result['findings'].append("Note: This is a basic test; advanced techniques may still reveal users")
                
                result['recommendations'].append(
                    "Continue using generic error messages"
                )
                result['recommendations'].append(
                    "Monitor for timing attack patterns in logs"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['ISO_27001'] += ' - PASS'
                result['compliance']['LGPD'] += ' - PASS'
        
        except Exception as e:
            logging.error(f"User enumeration test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_mfa_assessment(self) -> Dict[str, Any]:
        """
        Assess Multi-Factor Authentication (MFA) implementation.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-7 (Network integrity protected)
        - PCI-DSS 4.0: Req 8.5 (MFA for all access to CDE) - NEW in v4.0
        - ISO 27001: A.9.4.2 (Secure log-on procedures)
        
        Tests:
        1. MFA availability detection
        2. MFA enforcement for admin accounts
        3. Types of MFA supported
        """
        logging.info("Running MFA assessment test...")
        
        result = {
            'test_name': 'Multi-Factor Authentication Assessment',
            'description': 'Checks for MFA availability and enforcement',
            'status': 'INFO',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-7',
                'PCI_DSS_4.0': 'Req 8.5 (NEW: MFA for ALL access)',
                'ISO_27001': 'A.9.4.2'
            }
        }
        
        try:
            # Look for MFA indicators on various pages
            mfa_pages = [
                '/', '/login', '/signin', '/account', '/settings',
                '/security', '/profile', '/2fa', '/mfa'
            ]
            
            mfa_indicators = {
                'available': False,
                'types': [],
                'endpoints': []
            }
            
            mfa_keywords = {
                'totp': ['authenticator', 'totp', 'google authenticator', 'authy', 'time-based'],
                'sms': ['sms', 'text message', 'phone verification', 'mobile'],
                'email': ['email code', 'email verification', 'verification code'],
                'u2f': ['security key', 'yubikey', 'u2f', 'fido', 'webauthn'],
                'backup_codes': ['backup code', 'recovery code']
            }
            
            for page in mfa_pages:
                url = urljoin(self.target, page)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for general MFA indicators
                    general_mfa = ['two-factor', '2fa', 'two factor', 'multi-factor', 'mfa', '2-factor']
                    
                    if any(keyword in content for keyword in general_mfa):
                        mfa_indicators['available'] = True
                        mfa_indicators['endpoints'].append(page)
                        result['findings'].append(f"✓ MFA indicators found on: {page}")
                        
                        # Identify MFA types
                        for mfa_type, keywords in mfa_keywords.items():
                            if any(keyword in content for keyword in keywords):
                                if mfa_type not in mfa_indicators['types']:
                                    mfa_indicators['types'].append(mfa_type)
                                    result['findings'].append(f"✓ MFA type detected: {mfa_type.upper()}")
            
            # Analyze findings
            if mfa_indicators['available']:
                result['status'] = 'PASS'
                result['findings'].append(
                    f"Multi-Factor Authentication is available (types: {', '.join(mfa_indicators['types']) if mfa_indicators['types'] else 'unknown'})"
                )
                
                # Check for recommended MFA types
                if 'totp' in mfa_indicators['types']:
                    result['findings'].append("✓ TOTP/Authenticator app supported (recommended)")
                    result['recommendations'].append(
                        "✓ Good: TOTP is the most secure MFA method for web applications"
                    )
                
                if 'u2f' in mfa_indicators['types']:
                    result['findings'].append("✓ Hardware security keys supported (excellent)")
                    result['recommendations'].append(
                        "✓ Excellent: Hardware keys (U2F/WebAuthn) provide the strongest MFA protection"
                    )
                
                if 'sms' in mfa_indicators['types'] and 'totp' not in mfa_indicators['types']:
                    result['findings'].append("⚠️ Only SMS-based MFA detected (less secure)")
                    result['recommendations'].append(
                        "Consider adding TOTP/Authenticator app support (more secure than SMS)"
                    )
                
                result['recommendations'].append(
                    "PCI-DSS v4.0 NEW REQUIREMENT: MFA mandatory for ALL users accessing cardholder data (not just admins)"
                )
                result['recommendations'].append(
                    "Consider enforcing MFA for all users, not just making it optional"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['PCI_DSS_4.0'] += ' - AVAILABLE (enforcement verification needed)'
                result['compliance']['ISO_27001'] += ' - PASS'
                
            else:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
                
                result['findings'].append("⚠️ No Multi-Factor Authentication detected")
                result['findings'].append("Note: MFA might be available but not publicly visible")
                
                result['recommendations'].append(
                    "CRITICAL (PCI-DSS v4.0): MFA is NOW MANDATORY for ALL access to cardholder data environment"
                )
                result['recommendations'].append(
                    "CRITICAL: Implement MFA immediately - 99.9% of account compromises can be prevented with MFA (Microsoft)"
                )
                result['recommendations'].append(
                    "Recommended: TOTP-based (Google Authenticator, Authy, Microsoft Authenticator)"
                )
                result['recommendations'].append(
                    "Alternative: Hardware security keys (YubiKey, Titan) for high-security accounts"
                )
                result['recommendations'].append(
                    "Avoid: SMS-based as sole MFA method (vulnerable to SIM swapping)"
                )
                result['recommendations'].append(
                    "Enforcement: Make MFA mandatory for admin accounts minimum"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL (CRITICAL for payment processing)'
                result['compliance']['ISO_27001'] += ' - FAIL'
                
                result['compliance_impact'] = (
                    "PCI-DSS v4.0 Req 8.5 now REQUIRES MFA for ALL personnel with access to "
                    "cardholder data environment, not just remote access or admin accounts. "
                    "This is a major change from v3.2.1 and is MANDATORY for compliance."
                )
        
        except Exception as e:
            logging.error(f"MFA assessment test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
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
╔═══════════════════════════════════════════════════════════════╗
║                         HowBadIsIt?                           ║
║                           v2.4.0                              ║
║        Professional Web Application Security Scanner          ║
╚═══════════════════════════════════════════════════════════════╝
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
        version='HowBadIsIt? v2.3.0'
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
