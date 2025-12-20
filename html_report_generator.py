"""
HTML Report Generator for HowBadIsIt?
Generates professional HTML reports from scan results
"""

import json
import os
from datetime import datetime
from pathlib import Path
from string import Template


class HTMLReportGenerator:
    """Generates professional HTML security assessment reports."""
    
    def __init__(self, template_dir="templates"):
        """
        Initialize the HTML report generator.
        
        Args:
            template_dir: Directory containing HTML templates
        """
        self.template_dir = Path(template_dir)
        self.template_path = self.template_dir / "report.html"
        
        if not self.template_path.exists():
            raise FileNotFoundError(f"Template not found: {self.template_path}")
    
    def generate(self, scan_data, output_path=None):
        """
        Generate HTML report from scan data.
        
        Args:
            scan_data: Dictionary containing scan results
            output_path: Path to save HTML report (optional)
            
        Returns:
            HTML content as string
        """
        # Load template
        with open(self.template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        # Prepare data for template
        template_data = self._prepare_template_data(scan_data)
        
        # Simple template rendering (Jinja2-style but using Python string methods)
        html_content = self._render_template(template_content, template_data)
        
        # Save to file if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[✓] HTML report saved to: {output_file}")
        
        return html_content
    
    def _prepare_template_data(self, scan_data):
        """Prepare scan data for template rendering."""
        # Extract basic info
        target = scan_data.get('target', 'Unknown')
        scan_date = scan_data.get('scan_date', datetime.now().isoformat())
        security_score = scan_data.get('security_score', 0)
        scanner_version = scan_data.get('scanner_version', '2.1.0')
        summary = scan_data.get('summary', {})
        results = scan_data.get('results', [])
        
        # Format scan date
        try:
            dt = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
            formatted_date = dt.strftime('%B %d, %Y at %H:%M:%S')
        except:
            formatted_date = scan_date
        
        return {
            'target': target,
            'scan_date': formatted_date,
            'security_score': round(security_score, 1),
            'scanner_version': scanner_version,
            'summary': summary,
            'results': results
        }
    
    def _render_template(self, template, data):
        """
        Simple template rendering without Jinja2.
        Handles basic {{ variable }} and {% if/for %} syntax.
        """
        html = template
        
        # Replace simple variables
        html = html.replace('{{ target }}', str(data['target']))
        html = html.replace('{{ scan_date }}', str(data['scan_date']))
        html = html.replace('{{ security_score }}', str(data['security_score']))
        html = html.replace('{{ scanner_version }}', str(data['scanner_version']))
        
        # Summary variables
        summary = data['summary']
        html = html.replace('{{ summary.total_tests }}', str(summary.get('total_tests', 0)))
        html = html.replace('{{ summary.critical }}', str(summary.get('critical', 0)))
        html = html.replace('{{ summary.high }}', str(summary.get('high', 0)))
        html = html.replace('{{ summary.medium }}', str(summary.get('medium', 0)))
        html = html.replace('{{ summary.low }}', str(summary.get('low', 0)))
        html = html.replace('{{ summary.passed }}', str(summary.get('passed', 0)))
        
        # Conditional rendering for summary counts
        html = self._render_conditionals(html, data)
        
        # Render results loop
        html = self._render_results_loop(html, data['results'])
        
        # Calculate progress circle
        score = data['security_score']
        circumference = 502.4  # 2 * π * 80
        progress = (score / 100) * circumference
        html = html.replace(
            '{{ (security_score / 100 * 502.4) }}',
            str(round(progress, 2))
        )
        
        return html
    
    def _render_conditionals(self, html, data):
        """Render if conditionals."""
        summary = data['summary']
        
        # {% if summary.critical > 0 %}
        if summary.get('critical', 0) > 0:
            html = html.replace('{% if summary.critical > 0 %}', '')
            html = html.replace('{% endif %}', '', 1)
        else:
            # Remove the block
            start = html.find('{% if summary.critical > 0 %}')
            if start != -1:
                end = html.find('{% endif %}', start)
                if end != -1:
                    html = html[:start] + html[end + len('{% endif %}'):]
        
        # Similar for high, medium, low
        for severity in ['high', 'medium', 'low']:
            marker_start = f'{{% if summary.{severity} > 0 %}}'
            marker_end = '{% endif %}'
            
            while marker_start in html:
                if summary.get(severity, 0) > 0:
                    html = html.replace(marker_start, '', 1)
                    html = html.replace(marker_end, '', 1)
                else:
                    start = html.find(marker_start)
                    if start != -1:
                        end = html.find(marker_end, start)
                        if end != -1:
                            html = html[:start] + html[end + len(marker_end):]
                        else:
                            break
                    else:
                        break
        
        # Critical/high check
        critical_high_total = summary.get('critical', 0) + summary.get('high', 0)
        marker_start = '{% if summary.critical > 0 or summary.high > 0 %}'
        marker_end = '{% else %}'
        marker_endif = '{% endif %}'
        
        if marker_start in html:
            start = html.find(marker_start)
            else_pos = html.find(marker_end, start)
            endif_pos = html.find(marker_endif, else_pos)
            
            if critical_high_total > 0:
                # Keep if block, remove else block
                if_block_start = start + len(marker_start)
                if_block_content = html[if_block_start:else_pos]
                html = html[:start] + if_block_content + html[endif_pos + len(marker_endif):]
            else:
                # Keep else block, remove if block
                else_block_start = else_pos + len(marker_end)
                else_block_content = html[else_block_start:endif_pos]
                html = html[:start] + else_block_content + html[endif_pos + len(marker_endif):]
        
        return html
    
    def _render_results_loop(self, html, results):
        """Render the results for loop."""
        marker_start = '{% for result in results %}'
        marker_end = '{% endfor %}'
        
        loop_start = html.find(marker_start)
        loop_end = html.find(marker_end)
        
        if loop_start == -1 or loop_end == -1:
            return html
        
        # Extract loop template
        template_start = loop_start + len(marker_start)
        loop_template = html[template_start:loop_end]
        
        # Render each result
        rendered_results = []
        for result in results:
            rendered = self._render_result(loop_template, result)
            rendered_results.append(rendered)
        
        # Replace loop with rendered content
        html = html[:loop_start] + ''.join(rendered_results) + html[loop_end + len(marker_end):]
        
        return html
    
    def _render_result(self, template, result):
        """Render a single result."""
        html = template
        
        # Basic replacements
        test_name = result.get('test_name', 'Unknown Test')
        html = html.replace('{{ result.test_name }}', test_name)
        html = html.replace('{{ result.description }}', result.get('description', ''))
        html = html.replace('{{ result.severity }}', result.get('severity', 'INFO'))
        html = html.replace('{{ result.status }}', result.get('status', 'UNKNOWN'))
        
        # Lowercase filters
        html = html.replace('{{ result.severity|lower }}', result.get('severity', 'INFO').lower())
        
        # Replace filter
        safe_id = test_name.replace(' ', '-').lower()
        html = html.replace("{{ result.test_name|replace(' ', '-')|lower }}", safe_id)
        
        # Findings loop
        findings = result.get('findings', [])
        if findings:
            findings_marker_start = '{% if result.findings %}'
            findings_marker_end = '{% endif %}'
            
            findings_start = html.find(findings_marker_start)
            findings_end = html.find(findings_marker_end, findings_start)
            
            if findings_start != -1 and findings_end != -1:
                findings_content = html[findings_start + len(findings_marker_start):findings_end]
                
                # Render findings list
                findings_html = self._render_list(findings_content, findings, 'finding')
                html = html[:findings_start] + findings_html + html[findings_end + len(findings_marker_end):]
        else:
            # Remove findings block
            findings_marker_start = '{% if result.findings %}'
            findings_marker_end = '{% endif %}'
            start = html.find(findings_marker_start)
            if start != -1:
                end = html.find(findings_marker_end, start)
                if end != -1:
                    html = html[:start] + html[end + len(findings_marker_end):]
        
        # Recommendations loop
        recommendations = result.get('recommendations', [])
        if recommendations:
            rec_marker_start = '{% if result.recommendations %}'
            rec_marker_end = '{% endif %}'
            
            rec_start = html.find(rec_marker_start)
            rec_end = html.find(rec_marker_end, rec_start)
            
            if rec_start != -1 and rec_end != -1:
                rec_content = html[rec_start + len(rec_marker_start):rec_end]
                
                # Render recommendations list
                rec_html = self._render_list(rec_content, recommendations, 'rec')
                html = html[:rec_start] + rec_html + html[rec_end + len(rec_marker_end):]
        else:
            # Remove recommendations block
            rec_marker_start = '{% if result.recommendations %}'
            rec_marker_end = '{% endif %}'
            start = html.find(rec_marker_start)
            if start != -1:
                end = html.find(rec_marker_end, start)
                if end != -1:
                    html = html[:start] + html[end + len(rec_marker_end):]
        
        return html
    
    def _render_list(self, template, items, item_var):
        """Render a list of items."""
        loop_marker_start = f'{{% for {item_var} in '
        loop_marker_end = '{% endfor %}'
        
        loop_start = template.find(loop_marker_start)
        if loop_start == -1:
            return template
        
        # Find end of for tag
        for_tag_end = template.find('%}', loop_start)
        loop_end = template.find(loop_marker_end, for_tag_end)
        
        if loop_end == -1:
            return template
        
        # Extract item template
        item_template = template[for_tag_end + 2:loop_end]
        
        # Render items
        rendered_items = []
        for item in items:
            rendered = item_template.replace(f'{{{{ {item_var} }}}}', str(item))
            rendered_items.append(rendered)
        
        # Replace loop
        result = template[:loop_start] + ''.join(rendered_items) + template[loop_end + len(loop_marker_end):]
        
        return result


def generate_html_report(json_file, output_file=None):
    """
    Convenience function to generate HTML report from JSON file.
    
    Args:
        json_file: Path to JSON scan results
        output_file: Path to save HTML report (optional, auto-generated if None)
    
    Returns:
        Path to generated HTML report
    """
    # Load JSON data
    with open(json_file, 'r') as f:
        scan_data = json.load(f)
    
    # Auto-generate output filename if not provided
    if not output_file:
        json_path = Path(json_file)
        output_file = json_path.parent / f"{json_path.stem}.html"
    
    # Generate report
    generator = HTMLReportGenerator()
    generator.generate(scan_data, output_file)
    
    return output_file


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python html_report_generator.py <json_file> [output_file]")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        result = generate_html_report(json_file, output_file)
        print(f"✓ HTML report generated: {result}")
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
