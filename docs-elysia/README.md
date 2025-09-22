# LeafLock Documentation - ElysiaJS

This is the new ElysiaJS-powered documentation site for LeafLock, migrated from Hugo.

## Features

- **🚀 ElysiaJS Framework**: Fast TypeScript web framework built on Bun
- **📚 Markdown Processing**: Automatic markdown to HTML conversion with frontmatter support
- **🎨 Modern Styling**: Responsive CSS with dark mode support  
- **🔍 Syntax Highlighting**: Code syntax highlighting with highlight.js
- **📖 API Documentation**: Integrated Swagger/OpenAPI documentation
- **⚡ Fast Development**: Hot reload with Bun's watch mode

## Getting Started

### Prerequisites

- [Bun](https://bun.sh) installed
- Node.js 18+ (fallback)

### Installation

```bash
# Install dependencies
bun install

# Start development server
bun run dev

# Build for production
bun run build

# Start production server
bun run start
```

### Development

The documentation site will be available at:
- **Documentation**: http://localhost:3000/docs
- **API Docs**: http://localhost:3000/api-docs
- **Health Check**: http://localhost:3000/api/health

### Project Structure

```
docs-elysia/
├── src/
│   ├── index.ts              # Main application entry
│   ├── routes/
│   │   ├── docs.ts          # Documentation routes
│   │   └── api.ts           # API routes
│   └── utils/
│       └── markdown.ts      # Markdown processing
├── content/                 # Markdown documentation files
├── public/                  # Static assets (CSS, images)
├── package.json
└── tsconfig.json
```

## Content Migration

The migration from Hugo includes:

### Migrated Content
- ✅ Index page (`docs/site/content/_index.md`)
- ✅ Admin Guide (`docs/admin-guide.md`)
- ✅ Privacy Policy (`docs/privacy-policy.md`)
- ⏳ Developer Guide
- ⏳ GDPR Compliance Guide
- ⏳ Additional documentation pages

### Migration Benefits

1. **Unified Stack**: Same TypeScript ecosystem as the frontend
2. **API Integration**: Seamless integration with backend API documentation
3. **Fast Performance**: Bun runtime for quick builds and serving
4. **Type Safety**: End-to-end TypeScript support
5. **Modern Tooling**: Contemporary web development practices

## Deployment

### Production Build

```bash
# Build the application
bun run build

# Start production server
bun run start
```

### Docker Deployment

```dockerfile
FROM oven/bun:latest

WORKDIR /app
COPY package.json bun.lockb ./
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build

EXPOSE 3000
CMD ["bun", "run", "start"]
```

### Environment Variables

- `NODE_ENV`: Set to `production` for production builds
- `PORT`: Server port (default: 3000)

## Comparison: Hugo vs ElysiaJS

| Feature | Hugo | ElysiaJS |
|---------|------|----------|
| **Build Time** | Static generation | Runtime serving |
| **Language** | Go templates | TypeScript |
| **API Docs** | Separate setup | Integrated Swagger |
| **Customization** | Template system | Full programmatic control |
| **Performance** | Pre-built static | Fast Bun runtime |
| **Ecosystem** | Hugo plugins | NPM ecosystem |

## Contributing

1. Add new documentation files to the `content/` directory
2. Update navigation in `src/utils/markdown.ts`
3. Test locally with `bun run dev`
4. Submit a pull request

## Support

- **Issues**: [GitHub Repository](https://github.com/RelativeSure/LeafLock)
- **Email**: contact@leaflock.app