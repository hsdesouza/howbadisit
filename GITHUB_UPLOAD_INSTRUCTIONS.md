# GitHub Upload Instructions - HowBadIsIt? v2.1

## Files to Upload (NEW/UPDATED)

Upload these files to your repository:

```
howbadisit.py           # Main scanner (RENAMED from web_pentest_scanner.py)
howbadisit.sh           # CLI wrapper (RENAMED from docker_helper.sh)  
setup.sh                # Installer (UPDATED to English)
Dockerfile              # Container def (UPDATED)
docker-compose.yml      # Orchestration (UPDATED)
requirements_docker.txt # Python deps (NO CHANGE)
.dockerignore          # Build optimization (NO CHANGE)
.gitignore             # Git exclusions (NO CHANGE)
README.md              # Main docs (COMPLETELY NEW in English)
CHANGELOG.md           # Version history (UPDATED)
MIGRATION.md           # v2.0 → v2.1 guide (UPDATED)
LICENSE                # MIT License (NO CHANGE)
```

## Files to DELETE from GitHub

Remove these obsolete files:

```bash
git rm install.sh
git rm install_kali.sh
git rm requirements.txt
git rm FIX_KALI_ERROR.txt
git rm TROUBLESHOOTING_KALI.md
git rm demo.sh
git rm EXAMPLES.sh
git rm PROJECT_SUMMARY.txt
git rm DOCKER_GUIDE.md
git rm DOCKER_README.md
git rm QUICKSTART.md
git rm web_pentest_scanner.py  # OLD NAME
git rm docker_helper.sh          # OLD NAME
```

## Upload Commands

```powershell
# In PowerShell (Windows)
cd C:\path\to\howbadisit

# Delete obsolete files
git rm install.sh install_kali.sh requirements.txt FIX_KALI_ERROR.txt
git rm TROUBLESHOOTING_KALI.md demo.sh EXAMPLES.sh PROJECT_SUMMARY.txt
git rm DOCKER_GUIDE.md DOCKER_README.md QUICKSTART.md
git rm web_pentest_scanner.py docker_helper.sh

# Add new/updated files
git add .

# Commit
git commit -m "🚀 Release v2.1.0 - English Rebrand as HowBadIsIt?

Major Changes:
- Renamed to HowBadIsIt? for global audience
- All code and docs now in English
- Simplified structure (12 core files vs 24)
- Docker abstraction (user doesn't see Docker mentions)
- Removed obsolete v1.0 compatibility scripts

Breaking Changes:
- Repository name changed
- Main script renamed: howbadisit.py (was web_pentest_scanner.py)
- CLI renamed: howbadisit.sh (was docker_helper.sh)

See CHANGELOG.md for full details."

# Push
git push origin main

# Tag
git tag -a v2.1.0 -m "Version 2.1.0 - English Rebrand"
git push origin v2.1.0
```

## Verify Upload

After uploading, verify:
1. Visit https://github.com/hsdesouza/howbadisit
2. Check README.md displays correctly (in English)
3. Verify obsolete files are gone
4. Test installation: `curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash`

## Installation URL (NEW)

```bash
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
```

Update any documentation/presentations with new URL.

