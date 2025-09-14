# LeafLock Icons

This app ships with a full set of favicons and PWA icons generated from the LeafLock motif. If you only need a single reference in HTML, you can use the primary SVG favicon link:

```
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
```

Assets included (no extra configuration needed unless you customize):
- `favicon.svg` (scalable primary icon)
- `favicon.ico` (multi-image 16/32/48)
- `favicon-16.png`, `favicon-32.png`, `favicon-48.png`, `favicon-64.png`
- `apple-touch-icon.png` (180×180)
- `icon-192.png`, `icon-512.png`
- `icon-192-maskable.png`, `icon-512-maskable.png` (safe padding for maskable PWAs)

Regenerate icons if you tweak branding:
- `node scripts/generate-icons.mjs`
