# Changelog

All notable changes to HowBadIsIt? are documented in this file.

## [2.1.0] - 2024-12-19

### 🌍 Major Release - English Rebrand & Global Readiness

**HowBadIsIt?** - The project has been renamed and internationalized for global audience.

### Added
- ✅ Complete English translation of all code, comments, and documentation
- ✅ New project name: **HowBadIsIt?** (memorable, professional, fun)
- ✅ Streamlined structure (12 core files vs 24 in v2.0)
- ✅ Enhanced user experience (Docker abstraction - users don't see Docker mentions)
- ✅ Simplified installation (obsolete scripts removed)

### Changed
- **BREAKING**: Main scanner renamed: `howbadisit.py` (was `web_pentest_scanner.py`)
- **BREAKING**: CLI wrapper renamed: `howbadisit.sh` (was `docker_helper.sh`)
- **BREAKING**: Repository URL: `hsdesouza/howbadisit` (was `hsdesouza/pentest`)
- All log messages, error messages, and output now in English
- Installation banner and UI completely in English
- Docker references abstracted from user-facing messages

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

### Migration from v2.0
See `MIGRATION.md` for detailed upgrade instructions.

Quick migration:
```bash
# Backup reports
cp -r /opt/pentest/reports /backup/

# Install v2.1
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash

# Restore reports  
cp -r /backup/reports /opt/howbadisit/reports/
```

---

## [2.0.0] - 2024-12-18

### 🚀 Major Release - Full Docker Automation

Complete rewrite with automated installation and 100% Docker-based execution.

### Added
- Automated installation script (`setup.sh`)
- Docker containerization (zero dependency issues)
- Multi-environment support (Ubuntu/Debian/Kali, WSL/VM/Hardware)
- Shell aliases for convenience
- Auto-detection of system environment
- Validation tests post-installation

### Changed
- Installation now standardized to `/opt/pentest`
- Python 3.11 fixed in Docker (eliminates compatibility issues)
- Professional MSSP-focused documentation

### 10 Security Tests
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

---

## [1.0.0] - 2024-12-17

### Initial Release

First stable release of the web application security scanner.

- Core scanning engine
- JSON and text output formats
- Logging system
- Basic Docker support
- Portuguese documentation

---

## Version Comparison

| Feature | v1.0 | v2.0 | v2.1 |
|---------|------|------|------|
| **Language** | Portuguese | Portuguese | **English** ✅ |
| **Project Name** | Pentest Scanner | Pentest Scanner | **HowBadIsIt?** ✅ |
| **Installation** | Manual | Automated | Automated |
| **Docker** | Optional | Required | Required |
| **File Count** | ~15 | 24 | **12** ✅ |
| **Global Ready** | No | No | **Yes** ✅ |
| **User Experience** | Technical | Technical | **Simplified** ✅ |

---

## Upcoming Features (v2.2+)

### Phase 1 (Q1 2025)
- 📸 Automated screenshot evidence collection
- 📄 Professional HTML report generation
- 🚀 GitHub auto-push integration
- 🎨 White-label branding support

### Phase 2 (Q2 2025)
- 🔬 CVE correlation engine
- 🎯 Enhanced subdomain enumeration (OSINT sources)
- 📊 Executive dashboard (one-page summary)
- 🔔 Notification system (Slack/Teams/Email)

### Phase 3 (Q3 2025)
- 📋 Compliance framework mapping (LGPD, PCI-DSS, ISO 27001)
- 🔄 Scan comparison & trending
- 💡 AI-powered recommendations
- 🌐 Multi-language support

---

**For detailed feature requests and bug reports:**  
https://github.com/hsdesouza/howbadisit/issues

**Installation:**  
```bash
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
```

Last Updated: 2024-12-19
