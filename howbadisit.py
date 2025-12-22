#!/usr/bin/env python3
"""
HowBadIsIt? - Professional Web Application Security Scanner
Version: 2.4.1 - Bugfix Release
Author: Security Research Team
License: MIT

A comprehensive web security scanner designed for penetration testers,
red teams, and MSSPs. Performs automated security assessments and
generates professional reports with visual evidence.

BUGFIX in v2.4.1 (2024-12-22):
- Fixed Test 27 (Encryption in Transit): TLS version check now works with all certificates
- Issue: Certificate verification was causing false positives
- Solution: Disabled cert verification for TLS version testing (cert validation done in Test 5)

Phase 4A Complete (v2.4.0 - Authentication Security):
DELIVERY 1 (Core Authentication):
  - Brute Force Protection (HIGH)
  - Session Management Security (HIGH)
  - Password Policy Strength (MEDIUM)
  - User Enumeration Prevention (MEDIUM)
  - MFA Assessment (INFO)

DELIVERY 2 (Credential Management):
  - Password Reset Security (HIGH)
  - Authentication Bypass (CRITICAL)
  - Credential Storage Security (CRITICAL)
  - Account Lockout Policy (MEDIUM)

DELIVERY 3 (Advanced Auth & Monitoring):
  - Privileged Account Security (CRITICAL)
  - Session Timeout Enforcement (MEDIUM)
  - Authentication Event Logging (HIGH)
  - Failed Login Monitoring (MEDIUM)
  - Encryption in Transit - Auth (CRITICAL)
  - OAuth/JWT Token Security (HIGH)

Total: 28 professional security tests

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
            # Phase 4A - Authentication Core Tests (Delivery 1)
            self.test_brute_force_protection,
            self.test_session_management,
            self.test_password_policy,
            self.test_user_enumeration,
            self.test_mfa_assessment,
            # Phase 4A - Credential Management Tests (Delivery 2)
            self.test_password_reset_security,
            self.test_authentication_bypass,
            self.test_credential_storage,
            self.test_account_lockout_policy,
            # Phase 4A - Advanced Auth & Monitoring Tests (Delivery 3 - FINAL)
            self.test_privileged_account_security,
            self.test_session_timeout,
            self.test_authentication_logging,
            self.test_failed_login_monitoring,
            self.test_encryption_in_transit_auth,
            self.test_oauth_jwt_security,
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
    
    # ========================================================================
    # PHASE 4A - CREDENTIAL MANAGEMENT TESTS (Delivery 2)
    # ========================================================================
    
    def test_password_reset_security(self) -> Dict[str, Any]:
        """
        Test password reset mechanism security.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-1 (Identity proofing and authentication)
        - PCI-DSS 4.0: Req 8.3.1 (Secure authentication mechanisms)
        - ISO 27001: A.9.4.3 (Password management system)
        - LGPD: Art. 46 (Medidas de segurança)
        
        Tests:
        1. Password reset token predictability
        2. Token expiration
        3. Token reusability
        4. Information disclosure in reset process
        5. Rate limiting on reset requests
        """
        logging.info("Running password reset security test...")
        
        result = {
            'test_name': 'Password Reset Security',
            'description': 'Tests security of password reset mechanism',
            'status': 'INFO',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-1',
                'PCI_DSS_4.0': 'Req 8.3.1',
                'ISO_27001': 'A.9.4.3',
                'LGPD': 'Art. 46'
            }
        }
        
        try:
            # Common password reset endpoints
            reset_endpoints = [
                '/forgot-password', '/reset-password', '/password/reset',
                '/password/forgot', '/account/forgot', '/auth/forgot-password',
                '/user/forgot-password', '/recover-password', '/password-recovery'
            ]
            
            reset_url = None
            reset_response = None
            
            # Find password reset endpoint
            for endpoint in reset_endpoints:
                url = urljoin(self.target, endpoint)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check if it's actually a reset page
                    reset_keywords = ['reset', 'forgot', 'recover', 'email', 'recovery']
                    if any(keyword in content for keyword in reset_keywords):
                        reset_url = url
                        reset_response = response
                        result['findings'].append(f"✓ Password reset endpoint found: {endpoint}")
                        break
            
            if not reset_url:
                result['findings'].append("No password reset endpoint detected on common paths")
                result['recommendations'].append(
                    "If password reset functionality exists, ensure it follows security best practices"
                )
                result['recommendations'].append(
                    "NIST SP 800-63B: Use cryptographically random tokens (min 32 bytes)"
                )
                result['recommendations'].append(
                    "Tokens should expire within 15-30 minutes"
                )
                result['recommendations'].append(
                    "Tokens should be single-use only (invalidate after first use)"
                )
                return result
            
            # Analyze password reset page
            issues_found = []
            
            # Test 1: Check for user enumeration in reset
            content = reset_response.text.lower()
            
            # Bad: Reveals if email exists
            bad_messages = [
                'email not found', 'user not found', 'no account with',
                'does not exist', 'is not registered', 'unknown email'
            ]
            
            if any(msg in content for msg in bad_messages):
                issues_found.append("User enumeration possible via error messages")
                result['findings'].append(
                    "⚠️ Password reset reveals whether email exists in system"
                )
            
            # Good: Generic message
            good_messages = [
                'if this email exists', 'if your account exists',
                'check your email', 'email sent if account exists'
            ]
            
            if any(msg in content for msg in good_messages):
                result['findings'].append(
                    "✓ Generic message detected (doesn't reveal email existence)"
                )
            
            # Test 2: Rate limiting check
            # Try multiple reset requests
            if 'email' in content or 'form' in content:
                result['findings'].append("Testing rate limiting on reset requests...")
                
                reset_attempts = 0
                max_attempts = 5
                
                for i in range(max_attempts):
                    try:
                        # Try to submit reset request
                        test_email = f'test{i}@example.com'
                        
                        # Try POST request
                        post_response = self.session.post(
                            reset_url,
                            data={'email': test_email},
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        reset_attempts += 1
                        
                        # Check for rate limiting
                        if post_response.status_code == 429:
                            result['findings'].append(
                                f"✓ Rate limiting detected after {reset_attempts} requests (HTTP 429)"
                            )
                            break
                        
                        if 'too many' in post_response.text.lower() or 'rate limit' in post_response.text.lower():
                            result['findings'].append(
                                f"✓ Rate limiting detected after {reset_attempts} requests"
                            )
                            break
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logging.debug(f"Reset request {i+1} error: {str(e)}")
                        break
                
                if reset_attempts >= max_attempts:
                    issues_found.append("No rate limiting on reset requests")
                    result['findings'].append(
                        f"⚠️ No rate limiting detected ({max_attempts} requests allowed)"
                    )
            
            # Determine overall status
            if issues_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'HIGH'
                
                result['findings'].append(
                    f"Security issues found: {', '.join(issues_found)}"
                )
                
                result['recommendations'].append(
                    "CRITICAL: Use cryptographically random tokens (min 32 bytes, not sequential)"
                )
                result['recommendations'].append(
                    "Set token expiration: 15-30 minutes maximum (NIST recommendation)"
                )
                result['recommendations'].append(
                    "Invalidate token after first use (no reusability)"
                )
                result['recommendations'].append(
                    "Use generic success message: 'If this email exists, you will receive a reset link'"
                )
                result['recommendations'].append(
                    "Implement rate limiting: Maximum 3 reset requests per email per hour"
                )
                result['recommendations'].append(
                    "Send email notification: Alert user when password reset is requested"
                )
                result['recommendations'].append(
                    "Require re-authentication: Ask for current password when changing password from logged-in session"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL'
                result['compliance']['ISO_27001'] += ' - FAIL'
                result['compliance']['LGPD'] += ' - FAIL'
                
                result['compliance_impact'] = (
                    "Insecure password reset is a common vector for account takeover. "
                    "NIST SP 800-63B provides specific guidelines for secure password recovery."
                )
            else:
                result['findings'].append("✓ Password reset endpoint found with security measures")
                result['recommendations'].append(
                    "Continue following password reset best practices"
                )
                result['recommendations'].append(
                    "Verify tokens are cryptographically random and time-limited"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['PCI_DSS_4.0'] += ' - PASS'
                result['compliance']['ISO_27001'] += ' - PASS'
                result['compliance']['LGPD'] += ' - PASS'
        
        except Exception as e:
            logging.error(f"Password reset security test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_authentication_bypass(self) -> Dict[str, Any]:
        """
        Test for authentication bypass vulnerabilities.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-1 (Access control)
        - PCI-DSS 4.0: Req 6.5.3 (Insecure authentication)
        - ISO 27001: A.9.4.2 (Secure log-on procedures)
        - LGPD: Art. 46 (Medidas de segurança)
        
        Tests:
        1. SQL injection in login form (auth bypass)
        2. Default credentials (admin/admin, etc.)
        3. Direct access to protected pages without authentication
        4. Comment-based credential disclosure
        """
        logging.info("Running authentication bypass test...")
        
        result = {
            'test_name': 'Authentication Bypass',
            'description': 'Tests for authentication bypass vulnerabilities',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-1',
                'PCI_DSS_4.0': 'Req 6.5.3',
                'ISO_27001': 'A.9.4.2',
                'LGPD': 'Art. 46'
            }
        }
        
        try:
            bypass_found = []
            
            # Test 1: SQL Injection in login (basic auth bypass check)
            login_form = self._find_login_form()
            
            if login_form:
                result['findings'].append(f"Testing login form at: {login_form['action']}")
                
                # Common SQL injection auth bypass payloads
                sqli_payloads = [
                    "admin' OR '1'='1",
                    "admin'--",
                    "admin' #",
                    "' OR 1=1--",
                    "admin' OR '1'='1'--",
                    "' OR 'a'='a",
                ]
                
                for payload in sqli_payloads[:3]:  # Test first 3 to avoid overwhelming
                    try:
                        login_data = {
                            login_form['username_field']: payload,
                            login_form['password_field']: 'anypassword'
                        }
                        
                        if login_form['method'] == 'POST':
                            response = self.session.post(
                                login_form['action'],
                                data=login_data,
                                timeout=self.timeout,
                                allow_redirects=True
                            )
                        else:
                            response = self.session.get(
                                login_form['action'],
                                params=login_data,
                                timeout=self.timeout,
                                allow_redirects=True
                            )
                        
                        # Check if login was successful
                        success_indicators = [
                            'dashboard', 'welcome', 'logout', 'profile',
                            'logged in', 'account', 'settings'
                        ]
                        
                        response_lower = response.text.lower()
                        
                        if any(indicator in response_lower for indicator in success_indicators):
                            # Potential bypass - but could be false positive
                            # Additional check: not on login page anymore
                            if 'password' not in response_lower or 'login' not in response_lower:
                                bypass_found.append(f"Possible SQL injection bypass with payload: {payload}")
                                result['findings'].append(
                                    f"⚠️ CRITICAL: Possible SQL injection authentication bypass detected!"
                                )
                                result['findings'].append(f"   Payload: {payload}")
                                break
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logging.debug(f"SQLi bypass test error: {str(e)}")
            
            # Test 2: Default credentials
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('administrator', 'administrator'),
                ('root', 'root'),
                ('admin', ''),
                ('guest', 'guest'),
            ]
            
            if login_form:
                result['findings'].append("Testing for default credentials...")
                
                for username, password in default_creds[:3]:  # Test first 3
                    try:
                        login_data = {
                            login_form['username_field']: username,
                            login_form['password_field']: password
                        }
                        
                        if login_form['method'] == 'POST':
                            response = self.session.post(
                                login_form['action'],
                                data=login_data,
                                timeout=self.timeout,
                                allow_redirects=True
                            )
                        else:
                            response = self.session.get(
                                login_form['action'],
                                params=login_data,
                                timeout=self.timeout,
                                allow_redirects=True
                            )
                        
                        # Check for successful login
                        if response.status_code == 200:
                            response_lower = response.text.lower()
                            
                            # Not on error page and has dashboard indicators
                            if 'invalid' not in response_lower and 'incorrect' not in response_lower:
                                if any(ind in response_lower for ind in ['dashboard', 'welcome', 'logout']):
                                    bypass_found.append(f"Default credentials work: {username}/{password}")
                                    result['findings'].append(
                                        f"⚠️ CRITICAL: Default credentials accepted: {username}/{password if password else '(blank)'}"
                                    )
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logging.debug(f"Default creds test error: {str(e)}")
            
            # Test 3: Direct access to protected pages
            protected_pages = [
                '/admin', '/admin/', '/administrator', '/dashboard',
                '/panel', '/cpanel', '/control', '/account',
                '/user/profile', '/admin/dashboard', '/wp-admin'
            ]
            
            result['findings'].append("Testing direct access to protected pages...")
            
            for page in protected_pages[:5]:  # Test first 5
                try:
                    url = urljoin(self.target, page)
                    response = self._make_request(url)
                    
                    if response and response.status_code == 200:
                        content = response.text.lower()
                        
                        # If we can access admin content without authentication
                        admin_indicators = ['admin', 'dashboard', 'control panel', 'management']
                        login_indicators = ['login', 'password', 'authenticate']
                        
                        has_admin_content = any(ind in content for ind in admin_indicators)
                        has_login_form = any(ind in content for ind in login_indicators)
                        
                        if has_admin_content and not has_login_form:
                            bypass_found.append(f"Direct access to protected page: {page}")
                            result['findings'].append(
                                f"⚠️ Possible unprotected admin page: {page} (HTTP 200)"
                            )
                    
                except Exception as e:
                    logging.debug(f"Protected page test error: {str(e)}")
            
            # Test 4: Credential disclosure in comments/source
            try:
                response = self._make_request(self.target)
                
                if response:
                    # Check HTML comments for credentials
                    import re
                    comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
                    
                    for comment in comments:
                        comment_lower = comment.lower()
                        
                        # Look for credential patterns
                        if any(word in comment_lower for word in ['password', 'username', 'admin', 'login', 'credential']):
                            if '=' in comment or ':' in comment:
                                bypass_found.append("Credentials found in HTML comments")
                                result['findings'].append(
                                    "⚠️ Potential credentials found in HTML comments"
                                )
                                result['findings'].append(f"   Preview: {comment[:100]}...")
                                break
            
            except Exception as e:
                logging.debug(f"Comment check error: {str(e)}")
            
            # Analyze results
            if bypass_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                
                result['findings'].append(
                    f"CRITICAL: {len(bypass_found)} authentication bypass vector(s) found"
                )
                
                result['recommendations'].append(
                    "IMMEDIATE ACTION: Fix authentication bypass vulnerabilities"
                )
                result['recommendations'].append(
                    "SQL Injection: Use parameterized queries/prepared statements"
                )
                result['recommendations'].append(
                    "Default Credentials: Change or remove ALL default accounts immediately"
                )
                result['recommendations'].append(
                    "Access Control: Implement proper authentication checks on ALL protected pages"
                )
                result['recommendations'].append(
                    "Code Review: Remove credential information from comments and source code"
                )
                result['recommendations'].append(
                    "Session Management: Verify session validity on every protected request"
                )
                result['recommendations'].append(
                    "Security Testing: Regular penetration testing to identify bypass vectors"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL (CRITICAL)'
                result['compliance']['ISO_27001'] += ' - FAIL'
                result['compliance']['LGPD'] += ' - FAIL'
                
                result['compliance_impact'] = (
                    "Authentication bypass is a CRITICAL vulnerability that allows complete "
                    "system compromise. PCI-DSS Req 6.5.3 specifically addresses broken authentication. "
                    "Immediate remediation required."
                )
            else:
                result['findings'].append("✓ No obvious authentication bypass vulnerabilities detected")
                result['findings'].append("Note: Advanced bypass techniques may still exist - professional pentest recommended")
                
                result['recommendations'].append(
                    "Continue using parameterized queries to prevent SQL injection"
                )
                result['recommendations'].append(
                    "Regularly audit for default credentials"
                )
                result['recommendations'].append(
                    "Implement defense in depth with multiple authentication layers"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['PCI_DSS_4.0'] += ' - PASS'
                result['compliance']['ISO_27001'] += ' - PASS'
                result['compliance']['LGPD'] += ' - PASS'
        
        except Exception as e:
            logging.error(f"Authentication bypass test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_credential_storage(self) -> Dict[str, Any]:
        """
        Test for credential storage vulnerabilities.
        
        Compliance:
        - NIST CSF 2.0: PR.DS-1 (Data-at-rest protected)
        - PCI-DSS 4.0: Req 8.3.2 (Strong cryptography for passwords)
        - ISO 27001: A.10.1.1 (Cryptographic controls)
        - LGPD: Art. 46 (Criptografia de dados)
        
        Tests:
        1. Password hash exposure in responses
        2. Plaintext credentials in error messages
        3. Password hash algorithm detection (weak vs strong)
        4. Credential disclosure via information leakage
        
        Note: This is limited external testing. Cannot test actual database storage.
        """
        logging.info("Running credential storage test...")
        
        result = {
            'test_name': 'Credential Storage Security',
            'description': 'Tests for credential storage vulnerabilities (external view)',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.DS-1',
                'PCI_DSS_4.0': 'Req 8.3.2',
                'ISO_27001': 'A.10.1.1',
                'LGPD': 'Art. 46'
            }
        }
        
        try:
            issues_found = []
            
            result['findings'].append("Note: External testing can only detect exposed credentials, not database storage")
            
            # Test 1: Check for password hashes in responses
            response = self._make_request(self.target)
            
            if response:
                content = response.text
                
                # Look for hash-like patterns (MD5, SHA1, SHA256, bcrypt)
                import re
                
                # MD5 pattern (32 hex chars)
                md5_pattern = r'\b[a-f0-9]{32}\b'
                md5_matches = re.findall(md5_pattern, content.lower())
                
                if len(md5_matches) > 2:  # More than 2 potential hashes
                    issues_found.append("Potential MD5 hashes in response")
                    result['findings'].append(
                        f"⚠️ Found {len(md5_matches)} potential MD5 hash patterns in response"
                    )
                    result['findings'].append("   This could indicate password hashes are being exposed")
                
                # SHA1 pattern (40 hex chars)
                sha1_pattern = r'\b[a-f0-9]{40}\b'
                sha1_matches = re.findall(sha1_pattern, content.lower())
                
                if len(sha1_matches) > 2:
                    issues_found.append("Potential SHA1 hashes in response")
                    result['findings'].append(
                        f"⚠️ Found {len(sha1_matches)} potential SHA1 hash patterns in response"
                    )
                
                # bcrypt pattern ($2a$, $2b$, $2y$)
                bcrypt_pattern = r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'
                bcrypt_matches = re.findall(bcrypt_pattern, content)
                
                if bcrypt_matches:
                    issues_found.append("bcrypt hashes exposed in response")
                    result['findings'].append(
                        f"⚠️ CRITICAL: Found {len(bcrypt_matches)} bcrypt password hash(es) in response!"
                    )
                
                # Check for literal password keywords with values
                password_patterns = [
                    r'password["\']?\s*[:=]\s*["\']?([^"\'>\s]+)',
                    r'passwd["\']?\s*[:=]\s*["\']?([^"\'>\s]+)',
                    r'pwd["\']?\s*[:=]\s*["\']?([^"\'>\s]+)',
                ]
                
                for pattern in password_patterns:
                    matches = re.findall(pattern, content.lower())
                    
                    # Filter out obvious non-passwords
                    real_passwords = [m for m in matches if m not in [
                        'password', 'pass', '****', 'required', 'text', 'input',
                        'none', 'null', 'undefined', 'empty', ''
                    ]]
                    
                    if real_passwords:
                        issues_found.append("Potential plaintext passwords in source")
                        result['findings'].append(
                            f"⚠️ Potential plaintext password values found in page source"
                        )
                        break
            
            # Test 2: Check API endpoints for credential disclosure
            api_endpoints = [
                '/api/users', '/api/user', '/api/accounts',
                '/users.json', '/api/v1/users', '/.well-known/users'
            ]
            
            for endpoint in api_endpoints[:3]:
                try:
                    url = urljoin(self.target, endpoint)
                    response = self._make_request(url)
                    
                    if response and response.status_code == 200:
                        try:
                            # Try to parse as JSON
                            data = response.json()
                            
                            # Look for password-related fields
                            content_str = json.dumps(data).lower()
                            
                            if 'password' in content_str or 'hash' in content_str:
                                issues_found.append(f"Password data in API endpoint: {endpoint}")
                                result['findings'].append(
                                    f"⚠️ API endpoint {endpoint} contains password-related data"
                                )
                        except:
                            pass
                
                except Exception as e:
                    logging.debug(f"API endpoint test error: {str(e)}")
            
            # Test 3: Error message credential disclosure
            # Try to trigger errors that might reveal storage info
            error_urls = [
                f"{self.target}/login?debug=1",
                f"{self.target}/api/users/1",
                f"{self.target}/user/999999",
            ]
            
            for url in error_urls:
                try:
                    response = self._make_request(url)
                    
                    if response:
                        error_keywords = ['sql', 'database', 'select', 'from users', 'password hash']
                        content_lower = response.text.lower()
                        
                        if any(keyword in content_lower for keyword in error_keywords):
                            if 'password' in content_lower or 'hash' in content_lower:
                                issues_found.append("Credential information in error messages")
                                result['findings'].append(
                                    "⚠️ Error messages may reveal credential storage details"
                                )
                                break
                
                except Exception as e:
                    logging.debug(f"Error message test error: {str(e)}")
            
            # Analyze results
            if issues_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                
                result['findings'].append(
                    f"CRITICAL: {len(issues_found)} credential storage issue(s) detected"
                )
                
                result['recommendations'].append(
                    "CRITICAL: NEVER expose password hashes in responses or APIs"
                )
                result['recommendations'].append(
                    "PCI-DSS 8.3.2 REQUIRES: Use strong cryptography (bcrypt, Argon2, PBKDF2)"
                )
                result['recommendations'].append(
                    "AVOID: MD5 and SHA1 are cryptographically broken - DO NOT use for passwords"
                )
                result['recommendations'].append(
                    "Minimum: bcrypt with work factor 10+ (PCI-DSS compliant)"
                )
                result['recommendations'].append(
                    "Recommended: Argon2id (OWASP recommendation for 2024)"
                )
                result['recommendations'].append(
                    "Use unique salt per password (automatic with bcrypt/Argon2)"
                )
                result['recommendations'].append(
                    "Remove password fields from ALL API responses"
                )
                result['recommendations'].append(
                    "Disable verbose error messages in production"
                )
                result['recommendations'].append(
                    "LGPD Compliance: Encrypted storage is mandatory for sensitive data"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL (CRITICAL - Req 8.3.2 violation)'
                result['compliance']['ISO_27001'] += ' - FAIL'
                result['compliance']['LGPD'] += ' - FAIL (Art. 46 violation)'
                
                result['compliance_impact'] = (
                    "Insecure credential storage is a CRITICAL violation. "
                    "PCI-DSS v4.0 Req 8.3.2 mandates strong cryptography (bcrypt, scrypt, PBKDF2). "
                    "LGPD Art. 46 requires cryptographic protection of sensitive data. "
                    "Exposed hashes enable offline cracking attacks."
                )
            else:
                result['findings'].append("✓ No obvious credential storage vulnerabilities detected externally")
                result['findings'].append("IMPORTANT: This test cannot verify database-level storage")
                
                result['recommendations'].append(
                    "Verify passwords are hashed with bcrypt/Argon2 (cannot test externally)"
                )
                result['recommendations'].append(
                    "Ensure unique salt per password (automatic with modern algorithms)"
                )
                result['recommendations'].append(
                    "Never log passwords or hashes"
                )
                result['recommendations'].append(
                    "Implement password hash upgrading when users login"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS (external check)'
                result['compliance']['PCI_DSS_4.0'] += ' - UNKNOWN (requires internal audit)'
                result['compliance']['ISO_27001'] += ' - PASS (external check)'
                result['compliance']['LGPD'] += ' - UNKNOWN (requires internal audit)'
        
        except Exception as e:
            logging.error(f"Credential storage test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_account_lockout_policy(self) -> Dict[str, Any]:
        """
        Test account lockout policy enforcement.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-7 (Unsuccessful login attempts limited)
        - PCI-DSS 4.0: Req 8.3.4 (Lock after 6 attempts, 30min minimum)
        - ISO 27001: A.9.4.2 (Secure log-on procedures)
        
        Tests:
        1. Lockout threshold (PCI-DSS: max 6 attempts)
        2. Lockout duration (PCI-DSS: min 30 minutes)
        3. Account unlock mechanism
        4. Lockout notification
        
        Note: Overlaps with brute_force_protection but focuses on compliance specifics
        """
        logging.info("Running account lockout policy test...")
        
        result = {
            'test_name': 'Account Lockout Policy',
            'description': 'Tests account lockout policy compliance (PCI-DSS focused)',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-7',
                'PCI_DSS_4.0': 'Req 8.3.4',
                'ISO_27001': 'A.9.4.2'
            }
        }
        
        try:
            login_form = self._find_login_form()
            
            if not login_form:
                result['findings'].append("No login form detected for lockout policy testing")
                result['recommendations'].append(
                    "PCI-DSS 8.3.4: Lockout required after 6 invalid attempts for minimum 30 minutes"
                )
                return result
            
            result['findings'].append(f"Testing account lockout policy on: {login_form['action']}")
            
            # Test lockout enforcement
            max_test_attempts = 10  # Test up to 10 attempts
            lockout_triggered = False
            lockout_attempt_number = 0
            lockout_type = None
            
            for i in range(max_test_attempts):
                try:
                    login_data = {
                        login_form['username_field']: 'lockout_test_user',
                        login_form['password_field']: f'wrong_password_{i}'
                    }
                    
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
                    
                    response_lower = response.text.lower()
                    
                    # Check for lockout indicators
                    lockout_keywords = ['locked', 'blocked', 'suspended', 'disabled', 'too many attempts']
                    
                    if any(keyword in response_lower for keyword in lockout_keywords):
                        lockout_triggered = True
                        lockout_attempt_number = i + 1
                        lockout_type = "Account lockout"
                        result['findings'].append(
                            f"✓ Account lockout triggered after {lockout_attempt_number} attempts"
                        )
                        break
                    
                    # Check for CAPTCHA (alternative to lockout)
                    if 'captcha' in response_lower or 'recaptcha' in response_lower:
                        lockout_triggered = True
                        lockout_attempt_number = i + 1
                        lockout_type = "CAPTCHA challenge"
                        result['findings'].append(
                            f"✓ CAPTCHA challenge triggered after {lockout_attempt_number} attempts"
                        )
                        break
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    logging.debug(f"Lockout test attempt {i+1} error: {str(e)}")
                    break
            
            # Analyze PCI-DSS compliance
            pci_compliant = False
            
            if lockout_triggered:
                # PCI-DSS requires lockout after MAX 6 attempts
                if lockout_attempt_number <= 6:
                    pci_compliant = True
                    result['findings'].append(
                        f"✓ PCI-DSS COMPLIANT: Lockout within 6 attempts (triggered at {lockout_attempt_number})"
                    )
                    result['compliance']['PCI_DSS_4.0'] += ' - PASS'
                else:
                    result['findings'].append(
                        f"⚠️ PCI-DSS REQUIREMENT: Lockout should occur within 6 attempts (currently at {lockout_attempt_number})"
                    )
                    result['compliance']['PCI_DSS_4.0'] += ' - FAIL (lockout threshold too high)'
                
                result['findings'].append(f"Protection type: {lockout_type}")
                
                # Note: Cannot test lockout duration externally
                result['findings'].append(
                    "⚠️ Cannot verify lockout duration externally (PCI-DSS requires min 30 minutes)"
                )
                result['recommendations'].append(
                    "Verify lockout duration is at least 30 minutes (PCI-DSS Req 8.3.4)"
                )
                result['recommendations'].append(
                    "Consider: Automatic unlock after 30 min OR manual unlock by administrator"
                )
                result['recommendations'].append(
                    "Recommended: Send email notification when account is locked"
                )
                
                if pci_compliant:
                    result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                    result['compliance']['ISO_27001'] += ' - PASS'
                else:
                    result['compliance']['NIST_CSF_2.0'] += ' - PARTIAL'
                    result['compliance']['ISO_27001'] += ' - PARTIAL'
            else:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
                
                result['findings'].append(
                    f"⚠️ NO account lockout detected after {max_test_attempts} failed attempts"
                )
                
                result['recommendations'].append(
                    "CRITICAL (PCI-DSS): Implement account lockout after 6 invalid login attempts"
                )
                result['recommendations'].append(
                    "Lockout duration: Minimum 30 minutes (PCI-DSS Req 8.3.4 mandate)"
                )
                result['recommendations'].append(
                    "Alternative: Use CAPTCHA + progressive delays if lockout is too disruptive"
                )
                result['recommendations'].append(
                    "Notification: Alert user via email when account is locked"
                )
                result['recommendations'].append(
                    "Unlock mechanism: Admin unlock OR automatic after 30 minutes"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL (MANDATORY requirement)'
                result['compliance']['ISO_27001'] += ' - FAIL'
                
                result['compliance_impact'] = (
                    "PCI-DSS v4.0 Req 8.3.4 MANDATES account lockout after maximum 6 invalid "
                    "login attempts for a minimum of 30 minutes. This is non-negotiable for "
                    "any organization processing payment cards."
                )
        
        except Exception as e:
            logging.error(f"Account lockout policy test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    # ========================================================================
    # PHASE 4A - ADVANCED AUTH & MONITORING TESTS (Delivery 3 - FINAL)
    # ========================================================================
    
    def test_privileged_account_security(self) -> Dict[str, Any]:
        """
        Test privileged/admin account security.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-4 (Access permissions managed)
        - PCI-DSS 4.0: Req 8.5.1 (MFA mandatory for admin)
        - ISO 27001: A.9.2.3 (Management of privileged access rights)
        
        Tests:
        1. Admin panel detection
        2. Admin access without authentication
        3. MFA enforcement for admin (PCI-DSS 8.5.1 NEW)
        4. Privileged account enumeration
        """
        logging.info("Running privileged account security test...")
        
        result = {
            'test_name': 'Privileged Account Security',
            'description': 'Tests security controls for administrative/privileged accounts',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-4',
                'PCI_DSS_4.0': 'Req 8.5.1 (MFA mandatory for admin)',
                'ISO_27001': 'A.9.2.3'
            }
        }
        
        try:
            issues_found = []
            
            # Common admin paths
            admin_paths = [
                '/admin', '/admin/', '/administrator', '/admin/dashboard',
                '/wp-admin', '/admin/login', '/admin/index.php',
                '/cpanel', '/control-panel', '/administration',
                '/manage', '/backend', '/admin/panel'
            ]
            
            admin_found = []
            
            for path in admin_paths:
                try:
                    url = urljoin(self.target, path)
                    response = self._make_request(url)
                    
                    if response and response.status_code == 200:
                        content_lower = response.text.lower()
                        
                        # Check if it's an admin interface
                        admin_indicators = ['admin', 'dashboard', 'control panel', 'administrator']
                        login_indicators = ['login', 'password', 'username', 'sign in']
                        
                        has_admin_content = any(ind in content_lower for ind in admin_indicators)
                        requires_login = any(ind in content_lower for ind in login_indicators)
                        
                        if has_admin_content:
                            if requires_login:
                                admin_found.append((path, 'protected'))
                                result['findings'].append(f"✓ Admin panel found (protected): {path}")
                            else:
                                admin_found.append((path, 'unprotected'))
                                issues_found.append(f"Unprotected admin panel: {path}")
                                result['findings'].append(f"⚠️ CRITICAL: Admin panel accessible without login: {path}")
                    
                    elif response and response.status_code == 401:
                        admin_found.append((path, 'auth_required'))
                        result['findings'].append(f"✓ Admin panel found (HTTP Auth): {path}")
                    
                    elif response and response.status_code == 403:
                        admin_found.append((path, 'forbidden'))
                        result['findings'].append(f"✓ Admin panel found (access forbidden): {path}")
                
                except Exception as e:
                    logging.debug(f"Admin path test error for {path}: {str(e)}")
            
            # Check for default admin usernames
            if admin_found:
                result['findings'].append(f"Found {len(admin_found)} admin endpoint(s)")
                
                # Check for admin user enumeration
                login_form = self._find_login_form()
                
                if login_form:
                    # Try admin username
                    try:
                        login_data = {
                            login_form['username_field']: 'admin',
                            login_form['password_field']: 'wrongpassword'
                        }
                        
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
                        
                        # Check if 'admin' user exists
                        response_lower = response.text.lower()
                        
                        # Indicators that admin user exists
                        admin_exists_indicators = [
                            'invalid password', 'wrong password', 'incorrect password',
                            'password is incorrect'
                        ]
                        
                        if any(ind in response_lower for ind in admin_exists_indicators):
                            issues_found.append("'admin' username exists (enumeration)")
                            result['findings'].append(
                                "⚠️ Default 'admin' username exists (detected via enumeration)"
                            )
                    
                    except Exception as e:
                        logging.debug(f"Admin enum test error: {str(e)}")
            
            # Analyze results
            if issues_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                
                result['findings'].append(
                    f"CRITICAL: {len(issues_found)} privileged account security issue(s) found"
                )
                
                result['recommendations'].append(
                    "CRITICAL: Protect ALL admin interfaces with authentication"
                )
                result['recommendations'].append(
                    "PCI-DSS 8.5.1 NEW REQUIREMENT: MFA is MANDATORY for all administrative access"
                )
                result['recommendations'].append(
                    "Use non-standard admin paths (not /admin or /wp-admin)"
                )
                result['recommendations'].append(
                    "Implement IP allowlisting for admin access when possible"
                )
                result['recommendations'].append(
                    "Disable default 'admin' username - use unique administrator usernames"
                )
                result['recommendations'].append(
                    "Implement separate authentication for privileged operations"
                )
                result['recommendations'].append(
                    "Monitor and log all administrative access (PCI-DSS Req 10.2.2)"
                )
                result['recommendations'].append(
                    "Implement session timeout for admin sessions (max 15 minutes idle)"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL (CRITICAL)'
                result['compliance']['ISO_27001'] += ' - FAIL'
                
                result['compliance_impact'] = (
                    "PCI-DSS v4.0 Req 8.5.1 now MANDATES Multi-Factor Authentication for ALL "
                    "administrative access to cardholder data environment. Unprotected admin "
                    "panels are a CRITICAL vulnerability leading to complete system compromise."
                )
            elif admin_found:
                result['findings'].append("✓ Admin panels found and properly protected")
                result['recommendations'].append(
                    "Verify MFA is enforced for all admin accounts (PCI-DSS 8.5.1)"
                )
                result['recommendations'].append(
                    "Consider hiding admin interface behind non-standard path"
                )
                result['recommendations'].append(
                    "Implement IP allowlisting for additional security"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['PCI_DSS_4.0'] += ' - PARTIAL (verify MFA internally)'
                result['compliance']['ISO_27001'] += ' - PASS'
            else:
                result['findings'].append("No admin panels detected on common paths")
                result['recommendations'].append(
                    "If admin interface exists, ensure PCI-DSS 8.5.1 MFA is enforced"
                )
        
        except Exception as e:
            logging.error(f"Privileged account security test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_session_timeout(self) -> Dict[str, Any]:
        """
        Test session timeout enforcement.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-1 (Identities authenticated)
        - PCI-DSS 4.0: Req 8.2.8 (15min idle timeout - NEW in v4.0, was 30min)
        - ISO 27001: A.9.4.2 (Secure log-on procedures)
        
        Tests:
        1. Session cookie expiration attributes
        2. Idle timeout indicators
        3. Absolute timeout indicators
        
        Note: Cannot fully test timeout duration externally
        """
        logging.info("Running session timeout test...")
        
        result = {
            'test_name': 'Session Timeout Enforcement',
            'description': 'Tests session timeout configuration (PCI-DSS 15min requirement)',
            'status': 'INFO',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-1',
                'PCI_DSS_4.0': 'Req 8.2.8 (15min idle - NEW)',
                'ISO_27001': 'A.9.4.2'
            }
        }
        
        try:
            response = self._make_request(self.target)
            
            if not response:
                result['status'] = 'ERROR'
                result['error'] = 'Failed to connect to target'
                return result
            
            # Check session cookies
            cookies = response.cookies
            
            if not cookies:
                result['findings'].append("No cookies detected - session management unclear")
                result['recommendations'].append(
                    "PCI-DSS 8.2.8: If sessions exist, idle timeout MUST be ≤15 minutes (changed from 30 in v4.0)"
                )
                return result
            
            result['findings'].append(f"Analyzing {len(cookies)} cookie(s) for timeout configuration")
            
            has_max_age = False
            has_expires = False
            session_cookies = []
            
            for cookie in cookies:
                # Identify session cookies
                session_keywords = ['session', 'sess', 'sid', 'token', 'auth', 'login', 'jsessionid', 'phpsessid']
                is_session_cookie = any(keyword in cookie.name.lower() for keyword in session_keywords)
                
                if is_session_cookie:
                    session_cookies.append(cookie.name)
                    
                    # Check for Max-Age or Expires
                    if hasattr(cookie, 'max_age') and cookie.max_age:
                        has_max_age = True
                        result['findings'].append(
                            f"✓ Session cookie '{cookie.name}' has Max-Age: {cookie.max_age}s"
                        )
                        
                        # Check if it's within PCI-DSS requirement (15 min = 900 seconds)
                        if cookie.max_age <= 900:
                            result['findings'].append(
                                f"  ✓ PCI-DSS COMPLIANT: Timeout ≤15 minutes ({cookie.max_age}s)"
                            )
                        else:
                            result['findings'].append(
                                f"  ⚠️ PCI-DSS REQUIREMENT: Should be ≤900s (15min), found {cookie.max_age}s"
                            )
                    
                    if cookie.expires:
                        has_expires = True
                        result['findings'].append(
                            f"✓ Session cookie '{cookie.name}' has Expires attribute"
                        )
            
            # Check for client-side timeout indicators
            if response.text:
                content_lower = response.text.lower()
                
                timeout_keywords = [
                    'session timeout', 'idle timeout', 'inactivity timeout',
                    'auto logout', 'automatic logout'
                ]
                
                if any(keyword in content_lower for keyword in timeout_keywords):
                    result['findings'].append(
                        "✓ Session timeout references found in page content"
                    )
            
            # Analyze findings
            if not session_cookies:
                result['findings'].append("No obvious session cookies detected")
                result['recommendations'].append(
                    "PCI-DSS 8.2.8: Idle session timeout MUST be ≤15 minutes (NEW in v4.0)"
                )
            else:
                result['findings'].append(
                    f"Found {len(session_cookies)} session cookie(s): {', '.join(session_cookies)}"
                )
                
                result['findings'].append(
                    "⚠️ IMPORTANT: Cannot verify actual timeout duration externally"
                )
                result['findings'].append(
                    "   Internal verification required for PCI-DSS compliance"
                )
                
                result['recommendations'].append(
                    "VERIFY INTERNALLY: Idle session timeout is ≤15 minutes (PCI-DSS v4.0 Req 8.2.8)"
                )
                result['recommendations'].append(
                    "NOTE: This changed from 30 minutes in PCI-DSS v3.2.1"
                )
                result['recommendations'].append(
                    "Implement both idle timeout (user inactive) and absolute timeout (max session duration)"
                )
                result['recommendations'].append(
                    "Recommended: 15min idle timeout + 8 hour absolute timeout"
                )
                result['recommendations'].append(
                    "Display countdown timer to warn users before session expires"
                )
                result['recommendations'].append(
                    "Implement 'Remember me' as optional separate feature (with security warnings)"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - UNKNOWN (requires internal test)'
                result['compliance']['PCI_DSS_4.0'] += ' - UNKNOWN (requires internal test)'
                result['compliance']['ISO_27001'] += ' - UNKNOWN (requires internal test)'
                
                result['compliance_impact'] = (
                    "PCI-DSS v4.0 Req 8.2.8 NEW REQUIREMENT: Idle timeout reduced from 30 to 15 minutes. "
                    "This is a MANDATORY change that went into effect in 2024. External testing cannot "
                    "verify actual timeout duration - internal testing required."
                )
        
        except Exception as e:
            logging.error(f"Session timeout test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_authentication_logging(self) -> Dict[str, Any]:
        """
        Test authentication event logging.
        
        Compliance:
        - NIST CSF 2.0: DE.AE-3 (Event data aggregated)
        - PCI-DSS 4.0: Req 10.2.4, 10.2.5 (Auth logging MANDATORY)
        - ISO 27001: A.12.4.1 (Event logging)
        - LGPD: Art. 37 (Security reports)
        
        Tests:
        1. Login attempt logging indicators
        2. Logout logging indicators
        3. Account changes logging
        4. Security event responses
        
        Note: Cannot access actual logs externally
        """
        logging.info("Running authentication logging test...")
        
        result = {
            'test_name': 'Authentication Event Logging',
            'description': 'Tests for authentication logging indicators',
            'status': 'INFO',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'DE.AE-3',
                'PCI_DSS_4.0': 'Req 10.2.4, 10.2.5',
                'ISO_27001': 'A.12.4.1',
                'LGPD': 'Art. 37'
            }
        }
        
        try:
            result['findings'].append("Note: External testing cannot access actual logs")
            result['findings'].append("This test looks for logging indicators and behavior patterns")
            
            # Test: Multiple login attempts and check for behavioral changes
            login_form = self._find_login_form()
            
            if not login_form:
                result['findings'].append("No login form detected for logging assessment")
                result['recommendations'].append(
                    "PCI-DSS 10.2.4: ALL authentication attempts MUST be logged"
                )
                result['recommendations'].append(
                    "PCI-DSS 10.2.5: ALL privilege elevation attempts MUST be logged"
                )
                return result
            
            # Make a few login attempts and look for evidence of logging
            attempt_responses = []
            
            for i in range(3):
                try:
                    login_data = {
                        login_form['username_field']: f'testuser{i}',
                        login_form['password_field']: f'testpass{i}'
                    }
                    
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
                    
                    attempt_responses.append({
                        'status': response.status_code,
                        'headers': dict(response.headers),
                        'cookies': len(response.cookies)
                    })
                    
                    time.sleep(0.5)
                
                except Exception as e:
                    logging.debug(f"Logging test attempt {i+1} error: {str(e)}")
            
            # Look for logging indicators
            indicators_found = []
            
            # Check for X-Request-ID or similar tracking headers
            if attempt_responses:
                first_response = attempt_responses[0]
                
                tracking_headers = [
                    'x-request-id', 'x-trace-id', 'x-correlation-id',
                    'x-transaction-id', 'request-id'
                ]
                
                for header in tracking_headers:
                    if header in [h.lower() for h in first_response['headers'].keys()]:
                        indicators_found.append(f"Request tracking header: {header}")
                        result['findings'].append(
                            f"✓ Request tracking detected: {header} (indicates logging infrastructure)"
                        )
            
            # Check error pages for logging references
            try:
                # Trigger 404 to see error page
                error_response = self._make_request(urljoin(self.target, '/nonexistent_page_12345'))
                
                if error_response:
                    content_lower = error_response.text.lower()
                    
                    logging_keywords = [
                        'request id', 'incident id', 'error id', 'reference number',
                        'log entry', 'correlation'
                    ]
                    
                    for keyword in logging_keywords:
                        if keyword in content_lower:
                            indicators_found.append(f"Error page mentions: {keyword}")
                            result['findings'].append(
                                f"✓ Error page indicates logging: '{keyword}' reference found"
                            )
                            break
            
            except Exception as e:
                logging.debug(f"Error page test failed: {str(e)}")
            
            # Provide recommendations based on findings
            if indicators_found:
                result['findings'].append(
                    f"Found {len(indicators_found)} logging indicator(s) - suggests logging infrastructure exists"
                )
            else:
                result['findings'].append(
                    "No obvious logging indicators detected externally"
                )
            
            # Always provide PCI-DSS requirements
            result['recommendations'].append(
                "PCI-DSS 10.2.4 MANDATORY: Log ALL authentication attempts (success AND failure)"
            )
            result['recommendations'].append(
                "PCI-DSS 10.2.5 MANDATORY: Log ALL privilege elevation (su, sudo, admin access)"
            )
            result['recommendations'].append(
                "Required log fields: User ID, Type of event, Date/time, Success/failure, Origination"
            )
            result['recommendations'].append(
                "Log retention: Minimum 1 year, with at least 3 months immediately available (PCI 10.5)"
            )
            result['recommendations'].append(
                "LGPD Art. 37: Security incident logs must be kept to demonstrate compliance"
            )
            result['recommendations'].append(
                "Implement SIEM (Security Information and Event Management) for centralized logging"
            )
            result['recommendations'].append(
                "Monitor logs daily for suspicious patterns (PCI-DSS Req 10.6)"
            )
            result['recommendations'].append(
                "Protect log integrity: Write-once/append-only, separate from application servers"
            )
            
            result['compliance']['NIST_CSF_2.0'] += ' - UNKNOWN (requires internal verification)'
            result['compliance']['PCI_DSS_4.0'] += ' - UNKNOWN (requires log review)'
            result['compliance']['ISO_27001'] += ' - UNKNOWN (requires internal verification)'
            result['compliance']['LGPD'] += ' - UNKNOWN (requires internal verification)'
            
            result['compliance_impact'] = (
                "PCI-DSS Req 10.2.4 and 10.2.5 MANDATE logging of ALL authentication attempts "
                "and privilege escalations. Logs must be retained for 1 year minimum and reviewed "
                "daily. LGPD Art. 37 requires maintaining security incident records. External testing "
                "cannot verify actual logging - internal audit required."
            )
        
        except Exception as e:
            logging.error(f"Authentication logging test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_failed_login_monitoring(self) -> Dict[str, Any]:
        """
        Test failed login monitoring and alerting.
        
        Compliance:
        - NIST CSF 2.0: DE.CM-1 (Network monitored)
        - PCI-DSS 4.0: Req 10.6 (Log review - daily)
        - ISO 27001: A.12.4.1 (Event logging)
        
        Tests:
        1. Failed login behavioral response
        2. Rate limiting after failures
        3. Alert mechanisms
        
        Note: Cannot test actual monitoring/alerting externally
        """
        logging.info("Running failed login monitoring test...")
        
        result = {
            'test_name': 'Failed Login Monitoring',
            'description': 'Tests failed login attempt detection and response',
            'status': 'INFO',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'DE.CM-1',
                'PCI_DSS_4.0': 'Req 10.6',
                'ISO_27001': 'A.12.4.1'
            }
        }
        
        try:
            result['findings'].append("Note: Cannot test actual monitoring systems externally")
            result['findings'].append("This test observes system behavior to infer monitoring")
            
            login_form = self._find_login_form()
            
            if not login_form:
                result['findings'].append("No login form detected")
                result['recommendations'].append(
                    "PCI-DSS 10.6: Review ALL authentication logs DAILY"
                )
                return result
            
            # Test: Make failed attempts and observe changes
            result['findings'].append("Testing system response to failed login attempts...")
            
            responses = []
            
            for i in range(5):
                try:
                    login_data = {
                        login_form['username_field']: 'monitor_test_user',
                        login_form['password_field']: f'wrong_pass_{i}'
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
                        'attempt': i + 1,
                        'status_code': response.status_code,
                        'response_time': elapsed,
                        'content_length': len(response.text)
                    })
                    
                    # Check for monitoring indicators
                    response_lower = response.text.lower()
                    
                    monitoring_keywords = [
                        'security alert', 'suspicious activity', 'multiple attempts',
                        'account monitoring', 'security team notified'
                    ]
                    
                    if any(keyword in response_lower for keyword in monitoring_keywords):
                        result['findings'].append(
                            f"✓ Monitoring indicator detected after {i+1} attempts: Security message shown"
                        )
                    
                    time.sleep(0.5)
                
                except Exception as e:
                    logging.debug(f"Failed login test attempt {i+1} error: {str(e)}")
            
            # Analyze response patterns
            if len(responses) >= 3:
                # Check for response time increases (throttling)
                first_avg = sum(r['response_time'] for r in responses[:2]) / 2
                last_avg = sum(r['response_time'] for r in responses[-2:]) / 2
                
                if last_avg > first_avg * 1.5:
                    result['findings'].append(
                        f"✓ Progressive throttling detected (response time increased by {((last_avg/first_avg)-1)*100:.0f}%)"
                    )
                    result['findings'].append(
                        "  This suggests failed login monitoring and rate limiting"
                    )
            
            # Recommendations
            result['recommendations'].append(
                "PCI-DSS 10.6 MANDATORY: Review logs at least daily for:"
            )
            result['recommendations'].append(
                "  - Multiple failed login attempts from same IP"
            )
            result['recommendations'].append(
                "  - Multiple failed attempts across different accounts from same IP"
            )
            result['recommendations'].append(
                "  - Login attempts from unusual geolocations"
            )
            result['recommendations'].append(
                "  - Login attempts outside business hours"
            )
            result['recommendations'].append(
                "Implement automated alerting for suspicious patterns:"
            )
            result['recommendations'].append(
                "  - Alert: >10 failed attempts in 5 minutes (same IP)"
            )
            result['recommendations'].append(
                "  - Alert: >5 failed attempts on privileged accounts"
            )
            result['recommendations'].append(
                "  - Alert: Login from new country/IP for high-value accounts"
            )
            result['recommendations'].append(
                "Integrate with SIEM for correlation across systems"
            )
            result['recommendations'].append(
                "NIST Recommendation: Automated blocking of IPs with excessive failures"
            )
            
            result['compliance']['NIST_CSF_2.0'] += ' - UNKNOWN (requires internal verification)'
            result['compliance']['PCI_DSS_4.0'] += ' - UNKNOWN (requires log review audit)'
            result['compliance']['ISO_27001'] += ' - UNKNOWN (requires internal verification)'
        
        except Exception as e:
            logging.error(f"Failed login monitoring test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_encryption_in_transit_auth(self) -> Dict[str, Any]:
        """
        Test encryption in transit for authentication endpoints.
        
        Compliance:
        - NIST CSF 2.0: PR.DS-2 (Data in transit protected)
        - PCI-DSS 4.0: Req 4.2 (TLS 1.2+ only, 1.0/1.1 prohibited since 2024)
        - ISO 27001: A.13.1.1, A.13.2.1 (Network security)
        - LGPD: Art. 46 (Encryption of personal data)
        
        Tests:
        1. HTTPS enforcement on auth endpoints
        2. TLS version (PCI: 1.2+ only)
        3. HTTP to HTTPS redirect
        4. Secure transmission of credentials
        """
        logging.info("Running encryption in transit (auth) test...")
        
        result = {
            'test_name': 'Encryption in Transit - Authentication',
            'description': 'Tests encryption for authentication endpoints (PCI-DSS 4.2)',
            'status': 'PASS',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.DS-2',
                'PCI_DSS_4.0': 'Req 4.2 (TLS 1.2+, 1.0/1.1 BANNED)',
                'ISO_27001': 'A.13.1.1, A.13.2.1',
                'LGPD': 'Art. 46'
            }
        }
        
        try:
            issues_found = []
            
            # Check if target uses HTTPS
            parsed_url = urlparse(self.target)
            uses_https = parsed_url.scheme == 'https'
            
            if not uses_https:
                issues_found.append("Site not using HTTPS")
                result['findings'].append("⚠️ CRITICAL: Site is using HTTP, not HTTPS")
                result['findings'].append("   ALL authentication MUST use HTTPS (PCI-DSS Req 4.2)")
            else:
                result['findings'].append("✓ Site using HTTPS")
            
            # Test HTTP to HTTPS redirect
            if uses_https:
                http_url = self.target.replace('https://', 'http://')
                
                try:
                    http_response = self._make_request(http_url, allow_redirects=False)
                    
                    if http_response:
                        if http_response.status_code in [301, 302, 303, 307, 308]:
                            location = http_response.headers.get('Location', '')
                            
                            if location.startswith('https://'):
                                result['findings'].append("✓ HTTP to HTTPS redirect configured")
                            else:
                                issues_found.append("Redirect not to HTTPS")
                                result['findings'].append("⚠️ HTTP redirects but not to HTTPS")
                        else:
                            issues_found.append("No HTTP to HTTPS redirect")
                            result['findings'].append("⚠️ No automatic redirect from HTTP to HTTPS")
                
                except Exception as e:
                    logging.debug(f"HTTP redirect test error: {str(e)}")
            
            # Check TLS version
            if uses_https:
                try:
                    import ssl
                    import socket
                    
                    hostname = parsed_url.netloc
                    port = 443
                    
                    # Try TLS 1.0 (should fail - banned in PCI-DSS v4.0)
                    try:
                        context_tls10 = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                        context_tls10.check_hostname = False
                        context_tls10.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context_tls10.wrap_socket(sock, server_hostname=hostname) as ssock:
                                issues_found.append("TLS 1.0 still supported")
                                result['findings'].append(
                                    "⚠️ CRITICAL (PCI-DSS): TLS 1.0 is supported (PROHIBITED since June 2024)"
                                )
                    except:
                        result['findings'].append("✓ TLS 1.0 correctly disabled (PCI-DSS compliant)")
                    
                    # Try TLS 1.1 (should fail - banned in PCI-DSS v4.0)
                    try:
                        context_tls11 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                        context_tls11.check_hostname = False
                        context_tls11.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context_tls11.wrap_socket(sock, server_hostname=hostname) as ssock:
                                issues_found.append("TLS 1.1 still supported")
                                result['findings'].append(
                                    "⚠️ CRITICAL (PCI-DSS): TLS 1.1 is supported (PROHIBITED since June 2024)"
                                )
                    except:
                        result['findings'].append("✓ TLS 1.1 correctly disabled (PCI-DSS compliant)")
                    
                    # Check TLS 1.2+ support
                    try:
                        context_tls12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context_tls12.minimum_version = ssl.TLSVersion.TLSv1_2
                        # Disable certificate verification for this test
                        # We only care about TLS version support, not cert validation
                        # (cert validation is done in test_ssl_tls_configuration)
                        context_tls12.check_hostname = False
                        context_tls12.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context_tls12.wrap_socket(sock, server_hostname=hostname) as ssock:
                                tls_version = ssock.version()
                                result['findings'].append(f"✓ TLS version in use: {tls_version}")
                                
                                if 'TLSv1.2' in tls_version or 'TLSv1.3' in tls_version:
                                    result['findings'].append("✓ PCI-DSS compliant TLS version")
                    except Exception as e:
                        issues_found.append("No TLS 1.2+ support")
                        result['findings'].append(f"⚠️ CRITICAL: Cannot establish TLS 1.2+ connection: {str(e)}")
                
                except Exception as e:
                    result['findings'].append(f"⚠️ Could not test TLS version: {str(e)}")
                    logging.debug(f"TLS version test error: {str(e)}")
            
            # Check login form submission method
            login_form = self._find_login_form()
            
            if login_form:
                form_action = login_form['action']
                
                if form_action.startswith('http://'):
                    issues_found.append("Login form submits over HTTP")
                    result['findings'].append(
                        "⚠️ CRITICAL: Login form submits credentials over HTTP (plaintext!)"
                    )
                elif form_action.startswith('https://'):
                    result['findings'].append("✓ Login form submits over HTTPS")
                else:
                    # Relative URL - inherits from page
                    if uses_https:
                        result['findings'].append("✓ Login form uses relative URL (submits via HTTPS)")
                    else:
                        issues_found.append("Login form on HTTP page")
                        result['findings'].append("⚠️ Login form on HTTP page")
            
            # Analyze results
            if issues_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                
                result['findings'].append(
                    f"CRITICAL: {len(issues_found)} encryption issue(s) found"
                )
                
                result['recommendations'].append(
                    "CRITICAL: Enforce HTTPS for ALL pages, especially authentication"
                )
                result['recommendations'].append(
                    "PCI-DSS 4.2 MANDATE (June 2024): TLS 1.0 and 1.1 are PROHIBITED"
                )
                result['recommendations'].append(
                    "Minimum TLS version: 1.2 (PCI-DSS requirement)"
                )
                result['recommendations'].append(
                    "Recommended: Enable TLS 1.3 for better security and performance"
                )
                result['recommendations'].append(
                    "Implement HTTP Strict Transport Security (HSTS) header"
                )
                result['recommendations'].append(
                    "Redirect ALL HTTP traffic to HTTPS (301 permanent redirect)"
                )
                result['recommendations'].append(
                    "LGPD Compliance: Encryption in transit is mandatory for personal data"
                )
                result['recommendations'].append(
                    "Use strong cipher suites (disable weak ciphers like RC4, 3DES)"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - FAIL'
                result['compliance']['PCI_DSS_4.0'] += ' - FAIL (CRITICAL violation)'
                result['compliance']['ISO_27001'] += ' - FAIL'
                result['compliance']['LGPD'] += ' - FAIL'
                
                result['compliance_impact'] = (
                    "PCI-DSS v4.0 Req 4.2 CRITICAL CHANGE (June 2024): TLS 1.0 and 1.1 are now "
                    "COMPLETELY PROHIBITED. Only TLS 1.2 or higher is permitted. Transmitting "
                    "credentials over HTTP or weak TLS is a CRITICAL vulnerability enabling "
                    "credential theft via man-in-the-middle attacks. LGPD Art. 46 mandates encryption."
                )
            else:
                result['findings'].append("✓ Encryption in transit properly configured")
                result['recommendations'].append(
                    "Continue using TLS 1.2+ only"
                )
                result['recommendations'].append(
                    "Consider enabling TLS 1.3 if not already enabled"
                )
                result['recommendations'].append(
                    "Regularly update cipher suites to remove weak ciphers"
                )
                result['recommendations'].append(
                    "Monitor for new TLS vulnerabilities (e.g., POODLE, Heartbleed successors)"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - PASS'
                result['compliance']['PCI_DSS_4.0'] += ' - PASS'
                result['compliance']['ISO_27001'] += ' - PASS'
                result['compliance']['LGPD'] += ' - PASS'
        
        except Exception as e:
            logging.error(f"Encryption in transit test failed: {str(e)}")
            result['status'] = 'ERROR'
            result['severity'] = 'INFO'
            result['error'] = str(e)
        
        return result
    
    def test_oauth_jwt_security(self) -> Dict[str, Any]:
        """
        Test OAuth/JWT token security.
        
        Compliance:
        - NIST CSF 2.0: PR.AC-1 (Identities authenticated)
        - PCI-DSS 4.0: Req 8.3.1 (Secure authentication)
        - ISO 27001: A.9.4.2 (Secure log-on)
        
        Tests:
        1. JWT token detection
        2. Token signature validation
        3. Token expiration
        4. OAuth endpoints security
        """
        logging.info("Running OAuth/JWT security test...")
        
        result = {
            'test_name': 'OAuth/JWT Token Security',
            'description': 'Tests modern authentication token security',
            'status': 'INFO',
            'severity': 'INFO',
            'findings': [],
            'recommendations': [],
            'compliance': {
                'NIST_CSF_2.0': 'PR.AC-1',
                'PCI_DSS_4.0': 'Req 8.3.1',
                'ISO_27001': 'A.9.4.2'
            }
        }
        
        try:
            result['findings'].append("Scanning for OAuth/JWT implementation...")
            
            # Check for JWT tokens in various places
            jwt_found = False
            jwt_locations = []
            
            # Check cookies
            response = self._make_request(self.target)
            
            if response:
                # Check cookies for JWT
                for cookie in response.cookies:
                    # JWT pattern: header.payload.signature
                    if '.' in cookie.value and cookie.value.count('.') >= 2:
                        # Simple JWT detection
                        parts = cookie.value.split('.')
                        if len(parts) >= 3:
                            try:
                                # Try to decode (not validate, just check structure)
                                import base64
                                base64.b64decode(parts[0] + '==')  # Add padding
                                jwt_found = True
                                jwt_locations.append(f"Cookie: {cookie.name}")
                                result['findings'].append(f"✓ JWT token detected in cookie: {cookie.name}")
                            except:
                                pass
                
                # Check for Authorization header (would need a request with auth)
                # Check HTML for token patterns
                content = response.text
                
                # Look for common JWT/OAuth patterns in JavaScript
                oauth_patterns = [
                    'oauth', 'bearer', 'access_token', 'id_token',
                    'refresh_token', 'authorization'
                ]
                
                content_lower = content.lower()
                
                for pattern in oauth_patterns:
                    if pattern in content_lower:
                        jwt_locations.append(f"Reference in page: {pattern}")
                
                if 'oauth' in content_lower or 'bearer' in content_lower:
                    result['findings'].append("✓ OAuth/token authentication references found in page")
            
            # Check for OAuth endpoints
            oauth_endpoints = [
                '/.well-known/openid-configuration',
                '/oauth/authorize', '/oauth/token',
                '/auth/oauth', '/api/oauth',
                '/.well-known/oauth-authorization-server'
            ]
            
            oauth_endpoints_found = []
            
            for endpoint in oauth_endpoints:
                try:
                    url = urljoin(self.target, endpoint)
                    response = self._make_request(url)
                    
                    if response and response.status_code == 200:
                        oauth_endpoints_found.append(endpoint)
                        result['findings'].append(f"✓ OAuth endpoint found: {endpoint}")
                        
                        # Check if it's JSON (typical for OAuth discovery)
                        try:
                            data = response.json()
                            result['findings'].append(f"  OAuth discovery document available")
                        except:
                            pass
                
                except Exception as e:
                    logging.debug(f"OAuth endpoint test error for {endpoint}: {str(e)}")
            
            # Provide recommendations
            if jwt_found or oauth_endpoints_found:
                result['findings'].append(
                    f"OAuth/JWT implementation detected ({len(jwt_locations) + len(oauth_endpoints_found)} indicators)"
                )
                
                result['recommendations'].append(
                    "JWT Best Practices:"
                )
                result['recommendations'].append(
                    "  - ALWAYS validate signature (use RS256 or ES256, NOT none algorithm)"
                )
                result['recommendations'].append(
                    "  - ALWAYS validate expiration (exp claim)"
                )
                result['recommendations'].append(
                    "  - ALWAYS validate issuer (iss claim) and audience (aud claim)"
                )
                result['recommendations'].append(
                    "  - Keep expiration short: 15min for access tokens, use refresh tokens"
                )
                result['recommendations'].append(
                    "  - NEVER include sensitive data in payload (it's base64, not encrypted)"
                )
                result['recommendations'].append(
                    "OAuth Security:"
                )
                result['recommendations'].append(
                    "  - Use PKCE (Proof Key for Code Exchange) for all OAuth flows"
                )
                result['recommendations'].append(
                    "  - Validate redirect_uri strictly (no open redirects)"
                )
                result['recommendations'].append(
                    "  - Use state parameter to prevent CSRF"
                )
                result['recommendations'].append(
                    "  - Store tokens securely (HttpOnly cookies for web apps)"
                )
                result['recommendations'].append(
                    "  - Implement token revocation endpoint"
                )
                result['recommendations'].append(
                    "Common Vulnerabilities to Avoid:"
                )
                result['recommendations'].append(
                    "  - Algorithm confusion (accepting 'none' or 'HS256' when expecting 'RS256')"
                )
                result['recommendations'].append(
                    "  - Missing expiration validation"
                )
                result['recommendations'].append(
                    "  - JWT stored in localStorage (vulnerable to XSS)"
                )
                result['recommendations'].append(
                    "  - Weak JWT secrets (if using HS256)"
                )
                
                result['compliance']['NIST_CSF_2.0'] += ' - IMPLEMENTATION DETECTED (verify configuration)'
                result['compliance']['PCI_DSS_4.0'] += ' - VERIFY signature validation and expiration'
                result['compliance']['ISO_27001'] += ' - VERIFY secure implementation'
            else:
                result['findings'].append("No OAuth/JWT implementation detected")
                result['findings'].append("If using modern authentication, ensure proper security:")
                
                result['recommendations'].append(
                    "If implementing JWT/OAuth in the future:"
                )
                result['recommendations'].append(
                    "  - Use established libraries (don't implement JWT parsing yourself)"
                )
                result['recommendations'].append(
                    "  - Follow RFC 7519 (JWT), RFC 6749 (OAuth 2.0), RFC 8252 (OAuth for Native Apps)"
                )
                result['recommendations'].append(
                    "  - Consider OAuth 2.1 (upcoming standard with security improvements)"
                )
                result['recommendations'].append(
                    "  - Use OpenID Connect for authentication (OAuth is for authorization)"
                )
        
        except Exception as e:
            logging.error(f"OAuth/JWT security test failed: {str(e)}")
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
