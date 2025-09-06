# 📛 Repository Badges

Add these badges to your main README.md to show build status, coverage, and security information:

## Build and Testing Status

```markdown
![Build Status](https://github.com/RelativeSure/notes/actions/workflows/build-and-deploy.yml/badge.svg)
![CI Status](https://github.com/RelativeSure/notes/actions/workflows/ci.yml/badge.svg)
![Security Scan](https://github.com/RelativeSure/notes/actions/workflows/security-scan.yml/badge.svg)
```

## Code Coverage

```markdown
[![codecov](https://codecov.io/gh/RelativeSure/notes/branch/main/graph/badge.svg)](https://codecov.io/gh/RelativeSure/notes)
[![Backend Coverage](https://codecov.io/gh/RelativeSure/notes/branch/main/graph/badge.svg?flag=backend)](https://codecov.io/gh/RelativeSure/notes)
[![Frontend Coverage](https://codecov.io/gh/RelativeSure/notes/branch/main/graph/badge.svg?flag=frontend)](https://codecov.io/gh/RelativeSure/notes)
```

## Container Images

```markdown
![Backend Image](https://ghcr-badge.deta.dev/relativesure/notes/backend/latest_tag?trim=major&label=backend)
![Frontend Image](https://ghcr-badge.deta.dev/relativesure/notes/frontend/latest_tag?trim=major&label=frontend)
![Backend Size](https://ghcr-badge.deta.dev/relativesure/notes/backend/size?tag=latest)
![Frontend Size](https://ghcr-badge.deta.dev/relativesure/notes/frontend/size?tag=latest)
```

## Security and Quality

```markdown
![Go Report Card](https://goreportcard.com/badge/github.com/RelativeSure/notes)
![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=RelativeSure_notes&metric=security_rating)
![Maintainability](https://sonarcloud.io/api/project_badges/measure?project=RelativeSure_notes&metric=sqale_rating)
```

## License and Version

```markdown
![License](https://img.shields.io/github/license/RelativeSure/notes)
![Latest Release](https://img.shields.io/github/v/release/RelativeSure/notes)
![Docker Pulls](https://img.shields.io/docker/pulls/ghcr.io/relativesure/notes/backend)
```

## Example README Section

Here's how to add them to your README.md:

```markdown
# 🔐 Secure Notes Application

![Build Status](https://github.com/RelativeSure/notes/actions/workflows/build-and-deploy.yml/badge.svg)
[![codecov](https://codecov.io/gh/RelativeSure/notes/branch/main/graph/badge.svg)](https://codecov.io/gh/RelativeSure/notes)
![Backend Image](https://ghcr-badge.deta.dev/relativesure/notes/backend/latest_tag?trim=major&label=backend)
![Frontend Image](https://ghcr-badge.deta.dev/relativesure/notes/frontend/latest_tag?trim=major&label=frontend)
![License](https://img.shields.io/github/license/RelativeSure/notes)

A secure, end-to-end encrypted notes application built with Go and React.

## 🚀 Quick Deploy

Deploy using pre-built container images:

\`\`\`bash
# Deploy latest version
./deploy-from-ghcr.sh deploy

# Deploy specific version
VERSION=v1.2.3 ./deploy-from-ghcr.sh deploy
\`\`\`

## 📊 Project Stats

- **Backend**: Go 1.23+ with Fiber framework
- **Frontend**: React 18 + TypeScript with Vite
- **Database**: PostgreSQL 15 with pgcrypto
- **Cache**: Redis 7 for sessions
- **Security**: End-to-end encryption with XChaCha20-Poly1305
```

## Badge Customization

### Colors
You can customize badge colors by adding `?color=` parameter:
- `?color=green` - Success/passing
- `?color=red` - Error/failing  
- `?color=yellow` - Warning
- `?color=blue` - Info
- `?color=lightgrey` - Neutral

### Labels
Customize labels with `?label=` parameter:
- `?label=backend%20build` - Custom label text
- `?label=tests` - Simple label

### Styles
Different badge styles with `?style=` parameter:
- `?style=flat` - Flat style (default)
- `?style=flat-square` - Flat square style
- `?style=for-the-badge` - Large badge
- `?style=plastic` - Plastic style

### Example with Customization
```markdown
![Custom Build](https://github.com/RelativeSure/notes/actions/workflows/build-and-deploy.yml/badge.svg?label=CI%2FCD&style=for-the-badge)
```

## 📈 Advanced Metrics

For more detailed metrics, consider integrating:

1. **SonarCloud** - Code quality and security
2. **Dependabot** - Dependency vulnerability alerts  
3. **CodeClimate** - Maintainability metrics
4. **Snyk** - Security vulnerability scanning
5. **FOSSA** - License compliance

These services typically provide their own badge APIs that can be added to your README.