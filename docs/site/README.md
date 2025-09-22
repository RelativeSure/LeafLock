# AstroJS Documentation Site

This directory contains the new AstroJS-based documentation site for LeafLock.

## Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Deployment

The site is built as a static site and can be deployed to any static hosting service:

- **GitHub Pages**: Deploy the `dist/` folder
- **Netlify**: Connect to repository and set build command to `npm run build` and publish directory to `dist`
- **Vercel**: Import project and it will auto-detect Astro settings
- **AWS S3**: Upload `dist/` contents to S3 bucket
- **Cloudflare Pages**: Connect repository with build command `npm run build` and output directory `dist`

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