"""
HTML Report Generator v2.3.0 - WITH RECOMMENDED ACTIONS
Maintains approved v2.1.2 layout + adds intelligent recommendations
"""

import json
from datetime import datetime
from pathlib import Path


def generate_recommended_actions(results, summary):
    """Generate intelligent, contextual recommended actions using same card style as findings"""
    
    critical = summary.get('critical', 0)
    high = summary.get('high', 0)
    medium = summary.get('medium', 0)
    low = summary.get('low', 0)
    
    vulnerable = [r for r in results if r.get('status') == 'VULNERABLE']
    recommendations = []
    
    # CRITICAL
    if critical > 0:
        critical_tests = [r['test_name'] for r in vulnerable if r.get('severity') == 'CRITICAL']
        recommendations.append({
            'priority': 'CRITICAL',
            'text': f"Immediate action required: {critical} critical {'vulnerability' if critical == 1 else 'vulnerabilities'} detected ({', '.join(critical_tests[:2])}{'...' if len(critical_tests) > 2 else ''}). These represent severe security risks that could lead to complete system compromise, data breaches, or unauthorized access. Address these within 24-48 hours."
        })
    
    # HIGH
    if high > 0:
        high_tests = [r['test_name'] for r in vulnerable if r.get('severity') == 'HIGH']
        has_info_disclosure = any('information disclosure' in t.lower() for t in high_tests)
        
        if has_info_disclosure:
            recommendations.append({
                'priority': 'HIGH',
                'text': "Information disclosure vulnerabilities were detected, potentially exposing sensitive data such as credentials, configuration files, or database backups. While not immediately exploitable remotely, this creates significant risk if attackers gain initial access. Remediation is straightforward (removing exposed files) and should be completed within one week to reduce your attack surface."
            })
        else:
            recommendations.append({
                'priority': 'HIGH',
                'text': f"{high} high-severity {'issue' if high == 1 else 'issues'} detected. These vulnerabilities could enable attackers to compromise user accounts, steal data, or perform unauthorized actions. Schedule remediation within 1-2 weeks to prevent potential exploitation."
            })
    
    # MEDIUM - contextual
    if medium > 0:
        medium_tests = [r['test_name'] for r in vulnerable if r.get('severity') == 'MEDIUM']
        has_ssl = any('ssl' in t.lower() or 'tls' in t.lower() for t in medium_tests)
        has_headers = any('header' in t.lower() for t in medium_tests)
        has_csrf = any('csrf' in t.lower() or 'form' in t.lower() for t in medium_tests)
        
        if has_ssl:
            recommendations.append({
                'priority': 'MEDIUM',
                'text': "SSL/TLS certificate issues detected (expiring soon or misconfiguration). While current encryption remains strong, certificate expiration would cause service disruption and security warnings for users. Schedule certificate renewal within the next 2-4 weeks to ensure continuous secure connectivity."
            })
        
        if has_headers:
            recommendations.append({
                'priority': 'MEDIUM',
                'text': "Missing security headers identified. While not critical vulnerabilities on their own, these headers provide defense-in-depth protection against common attacks like XSS, clickjacking, and information leakage. It's not a critical vulnerability, but it is an unnecessary and inexpensive risk to fix — addressing these headers now reduces exposure, improves compliance, and helps prevent bigger problems later."
            })
        
        if has_csrf:
            recommendations.append({
                'priority': 'MEDIUM',
                'text': "Forms without CSRF protection detected. This could allow attackers to trick authenticated users into performing unwanted actions. Implementation typically requires 4-8 hours of development work and significantly improves application security posture. Plan remediation within the current sprint or next maintenance window."
            })
        
        if not (has_ssl or has_headers or has_csrf):
            recommendations.append({
                'priority': 'MEDIUM',
                'text': f"{medium} medium-severity findings require attention. While not immediately critical, these issues weaken your security posture and could be chained with other vulnerabilities in sophisticated attacks. Address within 30 days as part of regular security maintenance."
            })
    
    # LOW
    if low > 0:
        low_tests = [r['test_name'] for r in vulnerable if r.get('severity') == 'LOW']
        has_waf = any('waf' in t.lower() or 'cdn' in t.lower() for t in low_tests)
        has_tech_disclosure = any('technology' in t.lower() for t in low_tests)
        
        if has_waf:
            recommendations.append({
                'priority': 'LOW',
                'text': "No Web Application Firewall (WAF) detected. While not a vulnerability itself, implementing a WAF (such as Cloudflare, AWS WAF, or similar) provides an additional security layer that can block common attacks, provide DDoS protection, and improve overall resilience. Consider this for the next infrastructure upgrade cycle."
            })
        
        if has_tech_disclosure:
            recommendations.append({
                'priority': 'INFO',
                'text': "Server technology information is being exposed in HTTP headers. While this doesn't create an immediate vulnerability, it provides attackers with reconnaissance information. Consider obfuscating or removing server banners as a best practice to reduce information leakage."
            })
    
    # POSITIVE
    if critical == 0 and high == 0:
        if medium > 0:
            recommendations.append({
                'priority': 'POSITIVE',
                'text': f"Good security posture overall — no critical or high-severity vulnerabilities detected. The {medium} medium-severity findings and {low} low-severity findings represent opportunities for security hardening rather than immediate threats. Continue with planned remediation schedule and maintain current security practices."
            })
        elif medium == 0 and low > 0:
            recommendations.append({
                'priority': 'POSITIVE',
                'text': f"Excellent security posture — only {low} low-severity findings detected, primarily related to best practices and defense-in-depth measures. Your application demonstrates strong security fundamentals. Address these items as time permits to achieve even stronger hardening."
            })
        elif medium == 0 and low == 0:
            recommendations.append({
                'priority': 'POSITIVE',
                'text': "Outstanding security posture — all tests passed successfully with no vulnerabilities detected. Your application demonstrates excellent security practices. Continue regular security assessments and maintain current security standards to ensure ongoing protection."
            })
    
    # Build HTML - NO TITLE, just badge and text
    html = '<section id="recommended-actions" class="page-break">\n'
    html += '    <h2 class="mb-2">Recommended Actions</h2>\n'
    
    for rec in recommendations:
        priority = rec['priority']
        text = rec['text']
        
        # Map priority to severity classes
        severity_class = priority.lower()
        if priority == 'POSITIVE':
            severity_class = 'info'
            badge_class = 'pass'
            badge_text = 'POSITIVE'
        elif priority == 'INFO':
            severity_class = 'info'
            badge_class = 'info'
            badge_text = 'INFO'
        else:
            badge_class = priority.lower()
            badge_text = priority.upper()
        
        # NO finding-title, just badge in header and text in details
        html += f'''    <div class="card finding {severity_class}">
        <div class="finding-header">
            <div></div>
            <div>
                <span class="badge badge-{badge_class}">{badge_text}</span>
            </div>
        </div>
        
        <div class="finding-details">
            <p style="margin: 0; line-height: 1.7;">{text}</p>
        </div>
    </div>\n'''
    
    html += '</section>\n'
    
    return html



def generate_html_report(json_file, output_file=None):
    """Generate HTML report from JSON - NO TEMPLATE PARSING!"""
    
    # Load data
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    # Extract data
    target = data.get('target', 'Unknown')
    scan_date = data.get('scan_date', datetime.now().isoformat())
    security_score = round(data.get('security_score', 0), 1)
    scanner_version = data.get('scanner_version', '2.1.0')
    summary = data.get('summary', {})
    results = data.get('results', [])
    
    # Format date
    try:
        dt = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
        formatted_date = dt.strftime('%B %d, %Y at %H:%M:%S')
    except:
        formatted_date = scan_date
    
    # Build findings HTML
    findings_html = ""
    
    # Group findings by severity for navigation
    severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
    
    for result in results:
        test_name = result.get('test_name', 'Unknown')
        severity = result.get('severity', 'INFO').lower()
        status = result.get('status', 'UNKNOWN')
        description = result.get('description', '')
        findings = result.get('findings', [])
        recommendations = result.get('recommendations', [])
        
        safe_id = test_name.replace(' ', '-').replace('/', '-').lower()
        badge_class = 'pass' if status == 'PASS' else 'info'
        
        # Track severity groups
        if severity in severity_groups and status != 'PASS':
            severity_groups[severity].append(safe_id)
        
        findings_list = ""
        if findings:
            findings_items = ''.join([f"<li>{f}</li>\n" for f in findings])
            findings_list = f"""
                    <div class="detail-section">
                        <div class="detail-title">Findings</div>
                        <ul class="finding-list">
                            {findings_items}
                        </ul>
                    </div>"""
        
        recommendations_box = ""
        if recommendations:
            rec_items = ''.join([f"<li>{r}</li>\n" for r in recommendations])
            recommendations_box = f"""
                    <div class="recommendations">
                        <div class="recommendations-title">💡 Recommendations</div>
                        <ul>
                            {rec_items}
                        </ul>
                    </div>"""
        
        findings_html += f"""
            <div class="card finding {severity}" id="{safe_id}" data-severity="{severity}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{test_name}</div>
                        <div class="finding-description">{description}</div>
                    </div>
                    <div>
                        <span class="badge badge-{severity}">{severity.upper()}</span>
                        <span class="badge badge-{badge_class}">{status}</span>
                    </div>
                </div>
                
                <div class="finding-details">
                    {findings_list}
                    {recommendations_box}
                </div>
            </div>
"""
    
    # Build severity links (scroll to first finding of that severity)
    severity_links = ""
    for sev, count_key in [('critical', 'critical'), ('high', 'high'), ('medium', 'medium'), ('low', 'low')]:
        count = summary.get(count_key, 0)
        if count > 0 and severity_groups[sev]:
            # Link to first finding of this severity
            first_id = severity_groups[sev][0]
            severity_links += f'<li class="nav-item"><a href="#{first_id}" class="nav-link">{sev.title()} ({count})</a></li>\n'
    
    # Score items
    score_items_html = f"""
                    <div class="score-item">
                        <div class="score-item-value">{summary.get('total_tests', 0)}</div>
                        <div class="score-item-label">Tests Run</div>
                    </div>"""
    
    if summary.get('critical', 0) > 0:
        score_items_html += f"""
                    <div class="score-item">
                        <div class="score-item-value severity-critical">{summary.get('critical', 0)}</div>
                        <div class="score-item-label">Critical</div>
                    </div>"""
    
    if summary.get('high', 0) > 0:
        score_items_html += f"""
                    <div class="score-item">
                        <div class="score-item-value severity-high">{summary.get('high', 0)}</div>
                        <div class="score-item-label">High</div>
                    </div>"""
    
    if summary.get('medium', 0) > 0:
        score_items_html += f"""
                    <div class="score-item">
                        <div class="score-item-value severity-medium">{summary.get('medium', 0)}</div>
                        <div class="score-item-label">Medium</div>
                    </div>"""
    
    if summary.get('low', 0) > 0:
        score_items_html += f"""
                    <div class="score-item">
                        <div class="score-item-value severity-low">{summary.get('low', 0)}</div>
                        <div class="score-item-label">Low</div>
                    </div>"""
    
    score_items_html += f"""
                    <div class="score-item">
                        <div class="score-item-value" style="color: var(--success)">{summary.get('passed', 0)}</div>
                        <div class="score-item-label">Passed</div>
                    </div>"""
    
    # Score color
    if security_score >= 80:
        score_color = 'var(--success)'
    elif security_score >= 60:
        score_color = 'var(--warning)'
    else:
        score_color = 'var(--danger)'
    
    # Progress circle
    progress = (security_score / 100) * 502.4
    
    # Critical/high warning
    critical_high_total = summary.get('critical', 0) + summary.get('high', 0)
    if critical_high_total > 0:
        warning_box = f"""
                <div class="recommendations mt-2">
                    <div class="recommendations-title">⚠️ Immediate Action Required</div>
                    <p>This assessment identified <strong>{critical_high_total}</strong> critical/high severity issues that require immediate attention. These vulnerabilities could be exploited by attackers to compromise the application or its data.</p>
                </div>"""
    else:
        warning_box = """
                <div style="background: #d1fae5; border: 1px solid #6ee7b7; border-radius: 8px; padding: 1rem; margin-top: 1rem;">
                    <div style="font-weight: 600; margin-bottom: 0.5rem; color: #065f46;">✓ Good Security Posture</div>
                    <p style="color: #065f46; margin: 0;">No critical or high severity vulnerabilities were identified during this assessment.</p>
                </div>"""
    
    # Load CSS from template
    with open('templates/report.html', 'r') as f:
        template_content = f.read()
    
    # Extract CSS
    css_start = template_content.find('<style>')
    css_end = template_content.find('</style>') + len('</style>')
    css_block = template_content[css_start:css_end]
    
    # Generate full HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {target}</title>
    {css_block}
</head>
<body>
    <div class="sidebar no-print">
        <div class="nav-title">Report Sections</div>
        <ul class="nav-list">
            <li class="nav-item"><a href="#executive-summary" class="nav-link">Executive Summary</a></li>
            <li class="nav-item"><a href="#recommended-actions" class="nav-link">Recommended Actions</a></li>
            <li class="nav-item"><a href="#findings" class="nav-link">Detailed Findings</a></li>
        </ul>
        
        <div class="nav-title" style="margin-top: 2rem;">Findings by Severity</div>
        <ul class="nav-list">
            {severity_links}
        </ul>
    </div>
    
    <div class="main-content">
        <section id="executive-summary" class="page-break">
            <h2 class="mb-2">Executive Summary</h2>
            
            <div class="score-section">
                <div class="score-circle">
                    <svg width="180" height="180">
                        <circle class="bg-circle" cx="90" cy="90" r="80"></circle>
                        <circle class="progress-circle" cx="90" cy="90" r="80" 
                                stroke-dasharray="{progress:.2f} 502.4"
                                stroke-dashoffset="0"
                                style="stroke: {score_color}"></circle>
                    </svg>
                    <div class="score-text">
                        <div class="score-number" style="color: {score_color}">{security_score}</div>
                        <div class="score-label">Security Score</div>
                    </div>
                </div>
                
                <div class="score-details">
                    {score_items_html}
                </div>
            </div>
            
            <div class="card">
                <h3 class="mb-2">Assessment Overview</h3>
                <p>This report presents the findings of a comprehensive security assessment conducted on <strong>{target}</strong> on {formatted_date}. The assessment included {summary.get('total_tests', 0)} security tests covering common web application vulnerabilities and misconfigurations.</p>
                {warning_box}
            </div>
        </section>
        
        <!-- Recommended Actions Section - Outside card like Executive Summary -->
        {generate_recommended_actions(results, summary)}
        
        <section id="findings" class="page-break">
            <h2 class="mb-2">Detailed Findings</h2>
            {findings_html}
        </section>
        
        <div class="card no-print" style="text-align: center; margin-top: 3rem;">
            <p style="color: var(--text-secondary);">
                Copyright © 2026 Winfra. All rights reserved.
            </p>
        </div>
    </div>
    
    <script>
        // Smooth scroll navigation
        document.querySelectorAll('.nav-link').forEach(link => {{
            link.addEventListener('click', function(e) {{
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                this.classList.add('active');
            }});
        }});
    </script>
</body>
</html>"""
    
    # Save
    if not output_file:
        output_file = Path(json_file).parent / f"{Path(json_file).stem}.html"
    
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[✓] HTML report saved to: {output_file}")
    return output_file


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python html_report_generator_SIMPLE.py <json_file> [output_file]")
        sys.exit(1)
    
    try:
        result = generate_html_report(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
        print(f"✓ HTML report generated: {result}")
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
