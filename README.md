# HowBadIsIt? v2.3.0

![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-green.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Professional web application security scanner for initial security assessments**

HowBadIsIt? is an ad-hoc security diagnostic tool designed for rapid initial assessments of websites and web applications. Perfect for security professionals, MSSPs, and development teams who need quick, actionable security insights.

---

## 🎯 **What is HowBadIsIt?**

HowBadIsIt? is a **professional security scanner** that performs automated security assessments on web applications and provides:

- ✅ **Comprehensive Security Testing** - 13 security tests covering OWASP Top 10
- ✅ **Executive-Friendly Reports** - Both technical and C-level summaries
- ✅ **Actionable Recommendations** - Specific remediation steps for each finding
- ✅ **Professional HTML Reports** - Beautiful, responsive reports ready to share
- ✅ **Fast Initial Assessment** - Complete scan in 2-5 minutes
- ✅ **Docker-Based** - Zero dependency issues, works everywhere

**Perfect for:**
- Initial security assessments
- Client onboarding (MSSP)
- Pre-deployment security checks
- Compliance audits (LGPD, GDPR, PCI-DSS)
- Security posture monitoring
- Pentest scoping

---

## 🚀 **Quick Start**

### **Installation (One Command)**

```bash
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
```

This will:
1. Install Docker (if needed)
2. Clone the repository to `/opt/howbadisit`
3. Build the Docker image
4. Configure shell aliases
5. Run validation tests

**Time:** ~5-10 minutes

---

### **First Scan**

```bash
cd /opt/howbadisit

# Interactive scan (easiest)
./howbadisit.sh scan

# Direct scan
./howbadisit.sh run -t example.com

# Generate HTML report
./howbadisit.sh run -t example.com -o html -f /app/reports/report.html
```

---

## 📊 **Security Tests (13 Total)**

HowBadIsIt? performs comprehensive security testing across multiple categories:

### **Critical Vulnerabilities (3 tests)**
1. **SQL Injection Detection** - Error-based, blind, and union-based SQLi
2. **Cross-Site Scripting (XSS)** - Reflected, DOM-based, and filter bypass detection
3. **Command Injection** - OS command injection in GET parameters

### **High-Severity Issues (4 tests)**
4. **Information Disclosure** - Exposed sensitive files (.env, backups, configs)
5. **Subdomain Enumeration** - Active subdomain discovery and takeover detection
6. **SSL/TLS Configuration** - Certificate validation, weak protocols, cipher analysis
7. **Form Security Analysis** - CSRF protection and input validation

### **Configuration & Hardening (6 tests)**
8. **Security Headers** - HSTS, CSP, X-Frame-Options, etc.
9. **CORS Misconfiguration** - Permissive CORS policies
10. **HTTP Methods Security** - Dangerous methods (PUT, DELETE, TRACE)
11. **Technology Detection** - Server versions and vulnerable components
12. **Port Scanning** - Exposed services and open ports
13. **WAF/CDN Detection** - Security infrastructure identification

---

## 📋 **Report Features**

### **HTML Reports (New in v2.3.0)**

Professional, responsive HTML reports with:

- **Executive Summary** 
  - Security score (0-100)
  - Risk overview dashboard
  - Immediate action items
  
- **Recommended Actions**
  - Contextual, actionable guidance
  - Business impact assessment
  - Estimated remediation time
  
- **Detailed Technical Findings**
  - Severity-based categorization
  - Specific vulnerabilities found
  - Step-by-step remediation

- **Professional Design**
  - Responsive (mobile-friendly)
  - Print-ready (PDF export)
  - Standalone (no external dependencies)
  - Winfra branding (customizable)

### **JSON Reports**

Machine-readable format for:
- CI/CD integration
- Automated processing
- Historical tracking
- API consumption

---

## 🎨 **Usage Examples**

### **Basic Scan**
```bash
./howbadisit.sh run -t scanme.nmap.org
```

### **HTML Report**
```bash
./howbadisit.sh run -t example.com -o html -f /app/reports/example.html
```

### **JSON Report**
```bash
./howbadisit.sh run -t example.com -o json -f /app/reports/example.json
```

### **Custom Options**
```bash
./howbadisit.sh run -t example.com --timeout 30 --threads 10 -v
```

### **Batch Scanning**
```bash
# Scan multiple targets
for target in site1.com site2.com site3.com; do
    ./howbadisit.sh run -t $target -o html -f /app/reports/${target}.html
done
```

---

## 🔧 **Advanced Features**

### **Shell Aliases**

After installation, use convenient aliases:

```bash
howbadisit -t example.com           # Quick scan
howbadisit-scan                     # Interactive scan
howbadisit-list                     # List reports
howbadisit-update                   # Update and rebuild
```

### **Docker Commands**

```bash
# Build/rebuild image
./howbadisit.sh build
./howbadisit.sh rebuild

# Interactive shell
./howbadisit.sh shell

# List saved reports
./howbadisit.sh list

# Clean reports
./howbadisit.sh clean
```

---

## 📚 **Documentation**

- **README.md** - This file (complete documentation)
- **CHANGELOG.md** - Version history and updates
- **LICENSE** - MIT License

---

## 🔒 **Security & Legal**

### ⚠️ **IMPORTANT - Legal Use Only**

This tool should **ONLY** be used with explicit permission from the target owner.

**Unauthorized use may:**
- Violate computer crime laws
- Result in civil and criminal prosecution
- Breach terms of service

### **Best Practices**

1. ✅ Get written authorization before testing
2. ✅ Inform stakeholders about potential disruptions
3. ✅ Test in staging environments first
4. ✅ Document all activities
5. ✅ Respect rate limits and robots.txt
6. ✅ Handle reports as confidential information

---

## 💼 **For MSSPs & Security Professionals**

### **Why HowBadIsIt?**

- **Fast Initial Assessments** - Complete scan in minutes, not hours
- **Client-Friendly Reports** - Executive summaries for C-level
- **Actionable Intelligence** - Specific, prioritized recommendations
- **Low False Positives** - High-confidence findings
- **Scalable** - Docker-based, consistent across environments
- **Professional Output** - Ready to deliver to clients

### **Workflow Integration**

```bash
# Morning: Scan all clients
for client in client1.com client2.com client3.com; do
    ./howbadisit.sh run -t $client -o html \
        -f /app/reports/${client}_$(date +%Y%m%d).html
done

# Afternoon: Review and send reports
# Evening: Follow up with remediation support
```

### **Automated Monitoring**

```bash
# Add to crontab for weekly scans
0 2 * * 0 cd /opt/howbadisit && ./howbadisit.sh run \
    -t client.com -o html -f /app/reports/weekly_$(date +\%Y\%m\%d).html
```

---

## 🛠️ **System Requirements**

- **OS:** Ubuntu 20.04+, Debian 11+, Kali Linux 2020+
- **Environment:** WSL2, VM, or bare metal
- **Docker:** 20.10+ (auto-installed by setup)
- **RAM:** 2GB minimum
- **Disk:** 5GB free space

---

## 📊 **Technical Specifications**

### **Platform**
- Fully containerized (Docker)
- Python 3.11 (stable and tested)
- Modular and extensible architecture
- Thread-safe concurrent execution

### **Performance**
- Typical scan time: 2-5 minutes
- Configurable timeout (default: 10s)
- Configurable threads (default: 5)
- Rate-limiting friendly

### **Output Formats**
- HTML (responsive, professional)
- JSON (machine-readable)
- Text (console output)

---

## 🔄 **Updating**

### **Update from Git**

```bash
cd /opt/howbadisit
git pull origin main
docker build --no-cache -t howbadisit:2.3.0 .

# Or use alias
howbadisit-update
```

---

## 📝 **Version History**

### **v2.3.0** (Current - 2024-12-21)
- ✅ Executive Summary with recommended actions
- ✅ Winfra custom branding
- ✅ Improved HTML reports (no dark mode)
- ✅ Consolidated codebase

### **v2.2.0** (2024-12-20)
- ✅ SQL Injection detection
- ✅ XSS detection
- ✅ Command Injection detection
- ✅ 13 total security tests

### **v2.1.0** (2024-12-19)
- ✅ Professional HTML reports
- ✅ English rebrand
- ✅ Simplified structure

### **v2.0.0** (2024-12-18)
- ✅ Full Docker automation
- ✅ 10 security tests
- ✅ Automated installation

See **CHANGELOG.md** for complete history.

---

## 🤝 **Contributing**

Issues and pull requests are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📜 **License**

MIT License - See **LICENSE** file for details.

---

## 🙏 **Credits**

Developed following best practices from:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST Cybersecurity Framework
- Docker Best Practices

---

## 📞 **Support**

- **Issues:** https://github.com/hsdesouza/howbadisit/issues
- **Documentation:** See README.md and CHANGELOG.md
- **Repository:** https://github.com/hsdesouza/howbadisit

---

## ⚡ **Quick Command Reference**

```bash
# Installation
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash

# Quick scan
cd /opt/howbadisit && ./howbadisit.sh scan

# HTML report
./howbadisit.sh run -t example.com -o html -f /app/reports/report.html

# List reports
./howbadisit.sh list

# Update
howbadisit-update

# Help
./howbadisit.sh help
```

---

**HowBadIsIt? v2.3.0** - Professional Web Application Security Scanner

**Repository:** https://github.com/hsdesouza/howbadisit  
**License:** MIT  
**Version:** 2.3.0  
**Release Date:** 2024-12-21

---

*"Fast, professional security assessments for modern web applications."*
