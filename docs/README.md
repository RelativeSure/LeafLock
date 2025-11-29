# LeafLock Documentation

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)

Documentation site for LeafLock - A secure notes application with end-to-end encryption and real-time collaboration.

## 🚀 What's New

**Modern Authentication with Clerk** - LeafLock now uses Clerk for professional-grade authentication!

- **Social Logins**: Google, GitHub, and more
- **Passwordless Authentication**: Magic links, passkeys
- **Multi-Factor Authentication**: TOTP, SMS, backup codes
- **Enterprise Security**: Automatic breach detection, bot protection
- **Beautiful UX**: Accessible, themed authentication components

[Get Started with Clerk Authentication →](./src/content/docs/authentication/quick-start.mdx)

## 📁 Documentation Structure

```plaintext
docs/
├── src/content/docs/
│   ├── authentication/     # Clerk authentication guides
│   ├── architecture/       # System architecture
│   ├── features/          # Feature documentation
│   ├── deployment/        # Deployment guides
│   ├── operations/        # Operations & maintenance
│   ├── api/              # API documentation
│   ├── troubleshooting/   # Common issues & solutions
│   └── legal/            # Legal & compliance
├── src/assets/           # Images and assets
├── public/              # Static files
└── astro.config.mjs     # Astro configuration
```

## 🧞 Commands

All commands are run from the root of the project, from a terminal:

| Command                   | Action                                           |
| :------------------------ | :----------------------------------------------- |
| `pnpm install`             | Installs dependencies                            |
| `pnpm dev`             | Starts local dev server at `localhost:4321`      |
| `pnpm build`           | Build your production site to `./dist/`          |
| `pnpm preview`         | Preview your build locally, before deploying     |
| `pnpm astro ...`       | Run CLI commands like `astro add`, `astro check` |
| `pnpm astro -- --help` | Get help using the Astro CLI                     |

## 📖 Key Documentation

### Authentication
- **[Quick Start](./src/content/docs/authentication/quick-start.mdx)** - Get Clerk running in 5 minutes
- **[Implementation Details](./src/content/docs/authentication/implementation.mdx)** - Technical architecture
- **[Migration Guide](./src/content/docs/authentication/migration.mdx)** - Move from JWT to Clerk
- **[Configuration Reference](./src/content/docs/authentication/configuration.mdx)** - All config options
- **[Troubleshooting](./src/content/docs/authentication/troubleshooting.mdx)** - Fix common issues

### Development
- Start the docs server: `pnpm dev`
- Build for production: `pnpm build`
- Preview build: `pnpm preview`

## 🔗 Links

- **LeafLock Repository**: https://github.com/RelativeSure/LeafLock
- **Clerk Documentation**: https://clerk.com/docs
- **Starlight Documentation**: https://starlight.astro.build/
- **Astro Documentation**: https://docs.astro.build