# 🚀 Release Quick Reference

## Most Common Commands

```bash
# 🔧 Patch Release (Bug fixes: 1.0.0 → 1.0.1)
./scripts/release.sh patch

# ✨ Minor Release (New features: 1.0.0 → 1.1.0)  
./scripts/release.sh minor --notes "Added user dashboard and notifications"

# 💥 Major Release (Breaking changes: 1.0.0 → 2.0.0)
./scripts/release.sh major --notes "New authentication system - see migration guide"

# 🧪 Preview Release (No changes made)
./scripts/release.sh minor --dry-run
```

## Quick Deploy After Release

```bash
# Deploy latest release
./deploy-from-ghcr.sh deploy

# Deploy specific version
VERSION=v1.2.3 ./deploy-from-ghcr.sh deploy

# Check status
./deploy-from-ghcr.sh status
```

## Container Images

After each release, images are available at:
```
ghcr.io/your-org/your-repo/backend:v1.2.3
ghcr.io/your-org/your-repo/frontend:v1.2.3
```

## GitHub Actions Alternative

1. Go to **Actions** → **🚀 Streamlined Release**
2. Click **Run workflow**  
3. Choose version type and options
4. Click **Run workflow**

## Version Types

| Type | When to Use | Example |
|------|-------------|---------|
| **patch** | Bug fixes, security patches | 1.0.0 → 1.0.1 |
| **minor** | New features, improvements | 1.0.0 → 1.1.0 |
| **major** | Breaking changes | 1.0.0 → 2.0.0 |
| **prerelease** | Beta testing | 1.0.0 → 1.0.1-rc.123 |

## Emergency Rollback

```bash
# Deploy previous version quickly
VERSION=v1.2.2 ./deploy-from-ghcr.sh deploy
```

---

📖 **Full Documentation**: See `VERSIONING_AND_RELEASES.md` for complete details