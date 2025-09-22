FROM oven/bun:latest

WORKDIR /app

# Copy package files
COPY package.json bun.lockb* ./
RUN bun install --frozen-lockfile --production

# Copy source code and content
COPY src/ ./src/
COPY content/ ./content/
COPY public/ ./public/
COPY tsconfig.json ./

# Build the application
RUN bun run build

# Create non-root user
RUN addgroup --system --gid 1001 bunuser
RUN adduser --system --uid 1001 bunuser
USER bunuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Start the application
CMD ["bun", "run", "start"]