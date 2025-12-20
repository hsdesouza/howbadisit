"""
HTML Report Generator - ULTRA SIMPLE VERSION
No template parsing - just build HTML directly
"""

import json
from datetime import datetime
from pathlib import Path


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
    for result in results:
        test_name = result.get('test_name', 'Unknown')
        severity = result.get('severity', 'INFO').lower()
        status = result.get('status', 'UNKNOWN')
        description = result.get('description', '')
        findings = result.get('findings', [])
        recommendations = result.get('recommendations', [])
        
        safe_id = test_name.replace(' ', '-').lower()
        badge_class = 'pass' if status == 'PASS' else 'info'
        
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
            <div class="card finding {severity}" id="{safe_id}">
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
    
    # Build severity links
    severity_links = ""
    for sev, count_key in [('critical', 'critical'), ('high', 'high'), ('medium', 'medium'), ('low', 'low')]:
        count = summary.get(count_key, 0)
        if count > 0:
            severity_links += f'<li class="nav-item"><a href="#{sev}" class="nav-link">{sev.title()} ({count})</a></li>\n'
    
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
    <title>Security Assessment Report - {target}</title>
    {css_block}
</head>
<body>
    <div class="sidebar no-print">
        <div class="toggle-container">
            <button class="toggle-btn" onclick="toggleDarkMode()">
                <span>🌓 Dark Mode</span>
                <span id="mode-indicator">Off</span>
            </button>
        </div>
        
        <div class="nav-title">Report Sections</div>
        <ul class="nav-list">
            <li class="nav-item"><a href="#executive-summary" class="nav-link">Executive Summary</a></li>
            <li class="nav-item"><a href="#findings" class="nav-link">Detailed Findings</a></li>
        </ul>
        
        <div class="nav-title" style="margin-top: 2rem;">Findings by Severity</div>
        <ul class="nav-list">
            {severity_links}
        </ul>
    </div>
    
    <div class="main-content">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="subtitle">Professional Web Application Security Analysis</div>
            
            <div class="header-meta">
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div class="meta-value">{target}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Date</div>
                    <div class="meta-value">{formatted_date}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scanner</div>
                    <div class="meta-value">HowBadIsIt? v{scanner_version}</div>
                </div>
            </div>
        </div>
        
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
        
        <section id="findings" class="page-break">
            <h2 class="mb-2">Detailed Findings</h2>
            {findings_html}
        </section>
        
        <div class="card no-print" style="text-align: center; margin-top: 3rem;">
            <p style="color: var(--text-secondary);">
                Report generated by <strong>HowBadIsIt? v{scanner_version}</strong><br>
                Professional Web Application Security Scanner<br>
                <a href="https://github.com/hsdesouza/howbadisit" target="_blank" style="color: var(--primary);">github.com/hsdesouza/howbadisit</a>
            </p>
            <p style="color: var(--danger); margin-top: 1rem; font-size: 0.875rem;">
                ⚠️ This report contains confidential security information. Handle with care.
            </p>
        </div>
    </div>
    
    <script>
        function toggleDarkMode() {{
            document.body.classList.toggle('dark-mode');
            const indicator = document.getElementById('mode-indicator');
            indicator.textContent = document.body.classList.contains('dark-mode') ? 'On' : 'Off';
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        }}
        
        if (localStorage.getItem('darkMode') === 'true') {{
            document.body.classList.add('dark-mode');
            document.getElementById('mode-indicator').textContent = 'On';
        }}
        
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
