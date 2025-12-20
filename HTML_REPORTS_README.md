# HTML Report Generator - HowBadIsIt? v2.1

## 📄 Professional HTML Reports

Generate beautiful, professional HTML security assessment reports with a single command.

---

## ✨ Features

- ✅ **Modern Design** - Clean, professional look
- ✅ **Responsive** - Works on desktop, tablet, and mobile
- ✅ **Print-Ready** - Perfect A4 formatting for PDF export
- ✅ **Dark Mode** - Toggle between light and dark themes
- ✅ **Interactive** - Smooth scrolling navigation, collapsible sections
- ✅ **Standalone** - Single HTML file with embedded CSS/JS
- ✅ **Security Score** - Visual gauge showing overall security posture
- ✅ **Severity Badges** - Color-coded findings (Critical, High, Medium, Low)
- ✅ **Recommendations** - Actionable remediation steps for each finding

---

## 🚀 Quick Start

### Generate HTML Report

```bash
# Basic HTML report
./howbadisit.sh run -t example.com -o html -f /app/reports/report.html

# Or from existing JSON
cd /opt/howbadisit
python3 html_report_generator.py reports/scan_results.json reports/report.html
```

### Via Docker (Direct)

```bash
docker run --rm -v $(pwd)/reports:/app/reports howbadisit:2.1.0 \
  -t example.com -o html -f /app/reports/example_report.html
```

---

## 📊 Report Sections

### 1. Executive Summary
- **Security Score** (0-100) with visual gauge
- **Summary Statistics** (Critical, High, Medium, Low counts)
- **Assessment Overview** with immediate action callouts

### 2. Detailed Findings
Each finding includes:
- **Test Name** and description
- **Severity Badge** (color-coded)
- **Status** (Vulnerable, Pass, Error)
- **Findings List** (specific issues detected)
- **Recommendations** (step-by-step remediation)

### 3. Navigation
- **Sidebar Menu** for quick access to sections
- **Jump to Severity** links (Critical, High, etc.)
- **Smooth Scrolling** and active section highlighting

---

## 🎨 Customization

### Dark Mode
- Click the "🌓 Dark Mode" button in the sidebar
- Preference is saved in browser localStorage
- Print always uses light theme

### Print to PDF
1. Open HTML report in browser
2. **Ctrl+P** (or Cmd+P on Mac)
3. Select "Save as PDF"
4. Choose A4 paper size
5. **Result:** Professional PDF report with proper page breaks

---

## 📁 File Structure

```
/opt/howbadisit/
├── templates/
│   └── report.html          # Main HTML template
├── html_report_generator.py  # Python generator
└── howbadisit.py            # Scanner (HTML option integrated)
```

---

## 🔧 Usage Examples

### Example 1: Basic Scan with HTML Output

```bash
cd /opt/howbadisit
./howbadisit.sh run -t scanme.nmap.org -o html -f /app/reports/scan.html
```

**Output:**
```
[*] Starting security assessment of: scanme.nmap.org
[*] Running comprehensive security tests...
[✓] HTML report saved to: /app/reports/scan.html
```

**Access:** `file:///opt/howbadisit/reports/scan.html`

---

### Example 2: Convert Existing JSON to HTML

```bash
cd /opt/howbadisit
python3 html_report_generator.py \
  reports/report_example_com_20241219.json \
  reports/report_example_com_20241219.html
```

---

### Example 3: Batch Conversion

```bash
cd /opt/howbadisit/reports

# Convert all JSON reports to HTML
for json in *.json; do
    python3 ../html_report_generator.py "$json" "${json%.json}.html"
done
```

---

## 🌐 Viewing Reports

### Option 1: Local Browser
```bash
# Open in default browser
xdg-open /opt/howbadisit/reports/report.html  # Linux
open /opt/howbadisit/reports/report.html       # Mac
start /opt/howbadisit/reports/report.html      # Windows (WSL)
```

### Option 2: Copy to Windows (WSL)
```bash
cp /opt/howbadisit/reports/report.html /mnt/c/Users/YourUser/Downloads/
```

Then open from Windows Explorer.

### Option 3: Simple HTTP Server
```bash
cd /opt/howbadisit/reports
python3 -m http.server 8080

# Access: http://localhost:8080/report.html
```

---

## 📧 Sharing Reports

### Email Attachment
HTML reports are standalone - attach directly to emails.

**Size:** Typically 100-500 KB (no external dependencies)

### Cloud Storage
Upload to:
- Google Drive
- Dropbox
- OneDrive
- SharePoint

Recipients can view directly in browser (no software needed).

---

## 🔒 Security Considerations

### Sensitive Information
HTML reports contain:
- Target domain/IP
- Detailed vulnerability information
- Server versions and technologies
- Potential attack vectors

**⚠️ Always:**
- Mark reports as **CONFIDENTIAL**
- Use encrypted channels for sharing
- Apply access controls (private links only)
- Delete reports after remediation

### Sanitization
Reports do NOT include:
- Actual credentials or secrets
- Full request/response payloads
- Session tokens
- Personal data (PII)

---

## 💡 Pro Tips

### Tip 1: Automated Reporting
```bash
# Add to cron for weekly reports
0 2 * * 0 cd /opt/howbadisit && ./howbadisit.sh run \
  -t production.example.com -o html \
  -f /app/reports/weekly_$(date +\%Y\%m\%d).html
```

### Tip 2: Client-Specific Branding
Edit `templates/report.html`:
- Line 400: Change footer text
- Line 8: Update title format
- Logo: Add `<img>` in header section

### Tip 3: Archive Reports
```bash
# Create archive of all reports
cd /opt/howbadisit/reports
tar -czf reports_archive_$(date +%Y%m%d).tar.gz *.html
```

---

## 🐛 Troubleshooting

### Report Not Generating

**Issue:** "HTML report generator not found"
```bash
# Check file exists
ls -la /opt/howbadisit/html_report_generator.py

# Check template exists
ls -la /opt/howbadisit/templates/report.html
```

**Fix:** Rebuild Docker image
```bash
cd /opt/howbadisit
docker build -t howbadisit:2.1.0 .
```

### Report Opens as Text

**Issue:** Browser shows HTML code instead of rendering

**Fix:** Ensure file extension is `.html` not `.txt`
```bash
mv report.txt report.html
```

### Dark Mode Not Working

**Issue:** Dark mode toggle doesn't persist

**Fix:** Enable localStorage in browser (privacy settings)

---

## 📈 Roadmap

### v2.2 (Planned)
- [ ] Screenshot integration
- [ ] Evidence gallery
- [ ] Chart.js graphs (vulnerability trends)
- [ ] Executive summary PDF (1-page)
- [ ] White-label branding support

### v2.3 (Planned)
- [ ] Comparison reports (before/after remediation)
- [ ] Multi-target consolidated reports
- [ ] Compliance mapping (LGPD, PCI-DSS, ISO 27001)

---

## 📚 Technical Details

### Template Engine
- Custom lightweight renderer (no Jinja2 dependency)
- Supports: variables, conditionals, loops
- Performance: ~50ms for typical report

### Browser Compatibility
- ✅ Chrome/Edge 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Mobile browsers (iOS/Android)

### CSS Framework
- Custom CSS (no Bootstrap/Tailwind dependency)
- Pure CSS animations
- CSS Grid + Flexbox layout
- Print media queries

---

## 🤝 Contributing

Found a bug or want to suggest improvements?

1. Open an issue: https://github.com/hsdesouza/howbadisit/issues
2. Describe the problem or feature request
3. Include:
   - Browser version
   - Sample report (if relevant)
   - Expected vs actual behavior

---

## 📄 License

Same as HowBadIsIt? main project - MIT License

---

**Happy Reporting! 📊**

For questions: See main README.md or open an issue on GitHub.
