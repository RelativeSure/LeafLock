# AstroJS Documentation Site

This directory contains the new AstroJS-based documentation site for LeafLock.

## Development

```bash
# Install dependencies
pnpm install

# Start development server
pnpm run dev

# Build for production
pnpm run build

# Preview production build
pnpm run preview
```

> **Note**: When running `pnpm install` for the first time, it will regenerate the complete `pnpm-lock.yaml` with all resolved dependencies and integrity hashes.

## Deployment

The site is built as a static site and can be deployed to any static hosting service:

- **Cloudflare Pages**: Use `wrangler.toml` configuration (see `CLOUDFLARE.md` for details)
- **GitHub Pages**: Deploy the `dist/` folder
- **Netlify**: Connect to repository and set build command to `pnpm run build` and publish directory to `dist`
- **Vercel**: Import project and it will auto-detect Astro settings
- **AWS S3**: Upload `dist/` contents to S3 bucket

### Cloudflare Pages (Recommended)

For Cloudflare Pages deployment:
1. Connect your GitHub repository to Cloudflare Pages
2. Set build command: `pnpm run build`
3. Set build output directory: `dist`
4. Set root directory: `docs/site`
5. See `CLOUDFLARE.md` for detailed configuration

## Migration from Hugo

All content has been migrated from the previous Hugo site:

- **✅ All markdown content converted to Astro pages**
- **✅ Styling preserved from original Hugo theme**
- **✅ Navigation structure maintained**
- **✅ SEO metadata preserved**
- **✅ Category and tag system preserved**

## Features

- 🚀 **Fast builds** with Astro
- 📱 **Responsive design** 
- 🎨 **Custom styling** preserved from Hugo
- 🔍 **SEO optimized** with meta tags and structured data
- 📝 **Easy content management** with Astro components
- 🏗️ **Static generation** for fast loading

## Pages Included

- Privacy Policy
- Terms of Use  
- GDPR Compliance
- GDPR Operations Guide
- Admin Guide
- Developer Guide
- Monitoring & Backups
- Global Compliance
- License

## Backup

The original Hugo site has been backed up to `../site-hugo-backup/` for reference.