# Cloudflare Pages Deployment Configuration

## Build Settings

- **Build command**: `npm run build`
- **Build output directory**: `dist`
- **Root directory**: `docs/site`
- **Node.js version**: `20.x`

## Environment Variables

Set these in your Cloudflare Pages dashboard:

- `NODE_ENV`: `production`

## Custom Domain

If you're using a custom domain like `docs.leaflock.app`:

1. Go to your Cloudflare Pages project
2. Navigate to **Custom domains**
3. Add `docs.leaflock.app`
4. Update your DNS records as instructed

## Deployment via GitHub

1. Connect your GitHub repository to Cloudflare Pages
2. Set build command: `npm run build`
3. Set build output directory: `dist`
4. Set root directory: `docs/site`
5. Deploy automatically on push to main branch

## Local Development with Wrangler

```bash
# Install Wrangler CLI
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Develop locally (optional - you can use npm run dev instead)
wrangler pages dev dist --port 8788

# Deploy manually (optional - auto-deploy via GitHub is recommended)
wrangler pages deploy dist --project-name leaflock-docs
```

## Features Enabled

- ✅ **Static Site Generation**: All pages pre-built for optimal performance
- ✅ **Security Headers**: Content Security Policy and security headers configured
- ✅ **Caching**: Optimized cache settings for assets and pages
- ✅ **Redirects**: Legacy URLs redirect to new structure
- ✅ **Custom Domain**: Ready for docs.leaflock.app setup

The site is now fully optimized for Cloudflare Pages deployment with security headers, caching, and redirect rules configured.