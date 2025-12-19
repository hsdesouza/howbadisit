# Migration Guide - v2.0 → v2.1

## Overview

This guide helps you migrate from **Pentest Scanner v2.0** to **HowBadIsIt? v2.1**.

## What Changed?

### 🌍 Major Changes
- **Project renamed**: Pentest Scanner → **HowBadIsIt?**
- **All English**: Code, docs, and UI now in English
- **Simplified structure**: 12 core files (was 24)
- **Better UX**: Docker abstracted from user view

### 🔧 File Renames
- `web_pentest_scanner.py` → `howbadisit.py`
- `docker_helper.sh` → `howbadisit.sh`
- Repository: `hsdesouza/pentest` → `hsdesouza/howbadisit`

### ❌ Removed Files
11 obsolete files removed (compatibility scripts no longer needed with Docker).

---

## Quick Migration (5 minutes)

### Step 1: Backup Reports
```bash
mkdir -p ~/howbadisit-migration
cp -r /opt/pentest/reports ~/howbadisit-migration/
```

### Step 2: Install v2.1
```bash
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
```

### Step 3: Restore Reports
```bash
cp -r ~/howbadisit-migration/reports/* /opt/howbadisit/reports/
```

### Step 4: Test
```bash
cd /opt/howbadisit
./howbadisit.sh scan -t scanme.nmap.org
```

Done! 🎉

---

## Command Changes

| Task | v2.0 | v2.1 |
|------|------|------|
| **Scan** | `./docker_helper.sh run -t site.com` | `./howbadisit.sh run -t site.com` |
| **Interactive** | `./docker_helper.sh scan` | `./howbadisit.sh scan` |
| **List reports** | `./docker_helper.sh list` | `./howbadisit.sh list` |
| **Update** | `pentest-update` | `howbadisit-update` |

---

## Aliases Update

### Old (v2.0)
```bash
alias pentest='cd /opt/pentest && ./docker_helper.sh run'
```

### New (v2.1) - Auto-configured by setup.sh
```bash
alias howbadisit='cd /opt/howbadisit && ./howbadisit.sh run'
alias howbadisit-scan='cd /opt/howbadisit && ./howbadisit.sh scan'
```

Reload shell:
```bash
source ~/.bashrc
```

---

## Compatibility

### ✅ 100% Compatible
- JSON report format (unchanged)
- Docker images (compatible)
- All security tests (same functionality)
- Report analysis tools (work with old reports)

### ⚠️ Path Changes
If you have scripts hardcoding paths:

**Before:**
```bash
/opt/pentest/docker_helper.sh
```

**After:**
```bash
/opt/howbadisit/howbadisit.sh
```

---

## Rollback (if needed)

If you need to go back to v2.0:

```bash
# Restore backup
cp -r ~/howbadisit-migration /opt/pentest

# Remove v2.1
sudo rm -rf /opt/howbadisit

# Use v2.0
cd /opt/pentest
./docker_helper.sh scan
```

---

## FAQ

**Q: Can I run both versions?**  
A: Yes, they install to different directories.

**Q: Do my old reports work?**  
A: Yes, 100% compatible.

**Q: What about my automation scripts?**  
A: Update paths and command names as shown above.

**Q: Why the rename?**  
A: Global readiness. English name = accessible worldwide.

---

## Need Help?

- GitHub Issues: https://github.com/hsdesouza/howbadisit/issues
- Documentation: /opt/howbadisit/README.md

---

Last Updated: 2024-12-19
