# Changelog

All notable changes to **HowBadIsIt?** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.3.0] - 2024-12-21

### 🎯 Major Release - Executive Reporting & Consolidation

**Focus:** Professional executive reporting and codebase consolidation

### Added
- ✅ **Executive Summary Section** - C-level friendly security overview
  - Security score visualization
  - Risk-level assessment
  - Business impact analysis
  
- ✅ **Recommended Actions** - Contextual, actionable guidance
  - Intelligent priority-based recommendations
  - Business impact assessment
  - Estimated remediation time
  - Contextual advice (e.g., "It's not a critical vulnerability, but it is an unnecessary and inexpensive risk to fix")
  
- ✅ **Winfra Custom Branding**
  - Custom footer (Copyright © 2026 Winfra. All rights reserved.)
  - Removed dark mode toggle
  - Streamlined header (no "Security Assessment Report" block)
  - Clean, professional appearance

### Changed
- 📝 **README.md** - Complete rewrite with professional description
- 📝 **Documentation** - Consolidated and simplified
- 🎨 **HTML Reports** - Standardized card design across all sections
- 📊 **Report Structure** - Executive Summary → Recommended Actions → Detailed Findings

### Removed
- ❌ Dark mode toggle (simplified UX)
- ❌ "Security Assessment Report" header block
- ❌ Card titles in Recommended Actions (only badges + text)
- ❌ Obsolete documentation files (FINAL_VERIFICATION.md, GITHUB_UPLOAD_INSTRUCTIONS.md, etc.)

### Fixed
- 🐛 Version inconsistencies across files
- 🐛 Banner version displays (all now show v2.3.0)
- 🐛 HTML report dark mode CSS (removed completely)

---

## [2.2.0] - 2024-12-20

### 🔒 Major Release - Injection Vulnerability Detection

**Focus:** Critical security vulnerability detection (OWASP Top 10)

### Added
- ✅ **SQL Injection Detection** (CRITICAL)
  - Error-based detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - Time-based blind SQLi detection
  - Union-based detection
  - 15+ test payloads
  - Database type identification

- ✅ **Cross-Site Scripting (XSS) Detection** (HIGH)
  - Reflected XSS in GET parameters
  - DOM-based XSS indicators
  - 15+ payloads including filter bypasses
  - Dangerous JavaScript pattern detection

- ✅ **Command Injection Detection** (CRITICAL)
  - OS command injection in GET parameters
  - Unix/Linux and Windows command testing
  - Time-based blind detection
  - Output-based detection
  - OS identification

### Changed
- 📊 **Test Count**: 10 → 13 tests (+30%)
- 📈 **OWASP Coverage**: 40% → 70% (+75%)
- 🔐 **Critical Tests**: 0 → 2 (SQL Injection, Command Injection)

### Technical
- Added `test_sql_injection.py` module
- Added `test_xss_detection.py` module
- Added `test_command_injection.py` module
- Integrated all tests into main scanner
- Updated JSON output format

---

## [2.1.0] - 2024-12-19

### 🌍 Major Release - English Rebrand & Global Readiness

**HowBadIsIt?** - The project has been renamed and internationalized for global audience.

### Added
- ✅ **Professional HTML Reports**
  - Responsive design (desktop/mobile)
  - Print-ready (A4 format)
  - Interactive navigation
  - Severity-based color coding
  - Dark mode toggle
  
- ✅ **Complete English Translation**
  - All code, comments, and documentation
  - User-facing messages
  - Error messages
  - Log outputs

- ✅ **New Project Name**: **HowBadIsIt?**
  - Memorable and professional
  - Global-friendly
  - Fun but credible

- ✅ **Streamlined Structure**
  - 12 core files (was 24 in v2.0)
  - Removed obsolete scripts
  - Simplified installation

### Changed
- **BREAKING**: Main scanner renamed: `howbadisit.py` (was `web_pentest_scanner.py`)
- **BREAKING**: CLI wrapper renamed: `howbadisit.sh` (was `docker_helper.sh`)
- **BREAKING**: Repository URL: `hsdesouza/howbadisit` (was `hsdesouza/pentest`)
- All Docker references abstracted from user-facing messages
- Installation banner completely in English

### Removed
- ❌ `install.sh` - Obsolete (Docker handles everything)
- ❌ `install_kali.sh` - Obsolete (Docker handles Python compatibility)
- ❌ `requirements.txt` - Obsolete (use `requirements_docker.txt`)
- ❌ `FIX_KALI_ERROR.txt` - No longer relevant
- ❌ `TROUBLESHOOTING_KALI.md` - Docker eliminates these issues
- ❌ `demo.sh` - Replaced by `howbadisit.sh`
- ❌ `EXAMPLES.sh` - Examples now in README.md
- ❌ `PROJECT_SUMMARY.txt` - Info migrated to README/CHANGELOG
- ❌ `DOCKER_GUIDE.md` - Users don't need Docker knowledge
- ❌ `DOCKER_README.md` - Simplified
- ❌ `QUICKSTART.md` - Integrated into README.md

---

## [2.0.0] - 2024-12-18

### 🚀 Major Release - Full Docker Automation

Complete rewrite with automated installation and 100% Docker-based execution.

### Added
- ✅ **Automated Installation** (`setup.sh`)
  - One-command installation
  - Auto-detects system environment
  - Installs Docker if needed
  - Configures shell aliases
  - Validation tests

- ✅ **Docker Containerization**
  - Zero dependency issues
  - Python 3.11 locked version
  - Multi-environment support (Ubuntu/Debian/Kali)
  - WSL/VM/Hardware compatibility

- ✅ **10 Security Tests**
  1. Technology Detection & Vulnerable Versions
  2. Subdomain Enumeration & Takeover Detection
  3. Information Disclosure (Sensitive Files)
  4. Port Scanning & Service Detection
  5. SSL/TLS Configuration Analysis
  6. Security Headers Analysis
  7. Form Analysis & Basic Injection Testing
  8. CORS Misconfiguration Detection
  9. HTTP Methods Testing
  10. WAF/CDN Detection

### Changed
- Installation standardized to `/opt/pentest` (later `/opt/howbadisit`)
- Professional MSSP-focused documentation
- JSON and text output formats

---

## [1.0.0] - 2024-12-17

### 🎉 Initial Release

First stable release of the web application security scanner.

### Added
- Core scanning engine
- JSON and text output formats
- Logging system
- Basic Docker support
- Portuguese documentation

---

## Version Comparison

| Feature | v1.0 | v2.0 | v2.1 | v2.2 | v2.3 |
|---------|------|------|------|------|------|
| **Language** | Portuguese | Portuguese | English | English | English |
| **Project Name** | Pentest | Pentest | HowBadIsIt? | HowBadIsIt? | HowBadIsIt? |
| **Tests** | 10 | 10 | 10 | 13 | 13 |
| **HTML Reports** | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Injection Tests** | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Executive Summary** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Custom Branding** | ❌ | ❌ | ❌ | ❌ | ✅ |

---

## Upgrade Path

### From v2.2.0 to v2.3.0
```bash
cd /opt/howbadisit
git pull origin main
docker build --no-cache -t howbadisit:2.3.0 .
```

### From v2.1.0 to v2.3.0
```bash
cd /opt/howbadisit
git pull origin main
docker build --no-cache -t howbadisit:2.3.0 .
```

### From v2.0.0 to v2.3.0
```bash
# Backup reports
cp -r /opt/pentest/reports /backup/

# Install v2.3.0
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash

# Restore reports
cp -r /backup/reports /opt/howbadisit/reports/
```

---

## Roadmap

### Planned Features (v2.4+)

#### Phase 3: Analytics & Reporting
- [ ] Scan history and comparisons
- [ ] Executive dashboard
- [ ] Scheduled scans and alerts
- [ ] Email notifications

#### Phase 4: Advanced Testing
- [ ] Authentication testing
- [ ] API security testing
- [ ] Advanced injection tests (LDAP, XML, NoSQL)
- [ ] Business logic testing

#### Phase 5: Automation & Integration
- [ ] CI/CD integration (GitHub Actions, GitLab CI/CD)
- [ ] REST API
- [ ] Webhooks
- [ ] Cloud integration (AWS, GCP)

#### Phase 6: UI/UX Enhancements
- [ ] Interactive reports with filters
- [ ] Web interface
- [ ] Multi-user support
- [ ] Custom themes

#### Phase 7: Enterprise Features
- [ ] Vulnerability database with CVE correlation
- [ ] Compliance reporting (LGPD, GDPR, PCI-DSS)
- [ ] Machine learning for false positive reduction
- [ ] Anomaly detection

---

## Contributing

See the main repository for contribution guidelines: https://github.com/hsdesouza/howbadisit

---

## License

MIT License - See LICENSE file for details.

---

**For detailed feature requests and bug reports:**  
https://github.com/hsdesouza/howbadisit/issues

**Installation:**  
```bash
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
```

---

Last Updated: 2024-12-21  
Current Version: 2.3.0
