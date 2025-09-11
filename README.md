# 🔐 Secure Notes - End-to-End Encrypted Notes Application

[![CI/CD Pipeline](https://github.com/RelativeSure/notes/actions/workflows/ci.yml/badge.svg)](https://github.com/RelativeSure/notes/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A privacy-first, self-hosted notes application with end-to-end encryption, real-time collaboration, and zero-knowledge architecture. Your data never leaves your control.

## 🌟 Features

### Security & Privacy

- 🔐 **End-to-End Encryption**: All notes encrypted client-side using XChaCha20-Poly1305
- 🚫 **Zero-Knowledge Architecture**: Server never sees plaintext data
- 🔑 **Secure Authentication**: Argon2id password hashing with 600,000 iterations
- 🛡️ **At-Rest Encryption**: Database fields encrypted with AES-256
- 🔒 **Session Security**: JWT tokens with refresh rotation
- 🚨 **Audit Logging**: Complete audit trail for compliance

### Functionality

- 📝 **Rich Text Editor**: Full formatting support with TipTap
- 🎨 **Markdown Support**: Write in markdown with live preview
- 💻 **Code Blocks**: Syntax highlighting for 100+ languages
- 📎 **File Attachments**: Encrypted file storage
- 🔄 **Real-Time Collaboration**: Multiple users can edit simultaneously
- 🔍 **Full-Text Search**: Search through encrypted notes
- 📱 **Offline Support**: Work offline with automatic sync
- 🌙 **Dark Mode**: Beautiful dark theme by default

### Technology

- ⚡ **Fast Backend**: Go with Fiber framework
- ⚛️ **Modern Frontend**: React 18 with TypeScript
- 🐘 **PostgreSQL**: Reliable data storage with JSONB
- 🚀 **Redis**: Session management and caching
- 🐳 **Docker**: Easy deployment with Docker Compose
- ☸️ **Kubernetes Ready**: Scalable with k8s/k3s support

## 📋 Requirements

- Docker and Docker Compose (or Podman)
- 2GB RAM minimum (4GB recommended)
- 10GB disk space
- Linux, macOS, or Windows with WSL2

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/RelativeSure/notes.git
cd notes
```

### 2. Set Up Environment Variables

```bash
# Copy example environment file
cp .env.example .env

# Generate secure random values
openssl rand -base64 64 | tr -d '\n' > jwt_secret.txt
openssl rand -base64 32 | tr -d '\n' > encryption_key.txt

# Edit .env with your values
nano .env
```

### 3. Start with Docker Compose

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down
```

### 4. Access the Application

- **Frontend**: <http://localhost:3000>
- **Backend API**: <http://localhost:8080>
- **API Health Check**: <http://localhost:8080/api/v1/health>

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │
│  React Frontend │────▶│  Go Backend API │
│   (Port 3000)   │     │   (Port 8080)   │
│                 │     │                 │
└─────────────────┘     └────────┬────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
              ┌─────▼──────┐     ┌───────▼──────┐
              │             │     │              │
              │ PostgreSQL  │     │    Redis     │
              │  Database   │     │    Cache     │
              │             │     │              │
              └─────────────┘     └──────────────┘
```

### Technology Stack

#### Backend (Go)

- **Framework**: Fiber v2 (Fast HTTP framework)
- **Database**: PostgreSQL 15 with pgx driver
- **Cache**: Redis 7 for sessions
- **Authentication**: JWT with refresh tokens
- **Encryption**: XChaCha20-Poly1305, Argon2id
- **WebSockets**: Real-time collaboration

#### Frontend (React)

- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite 5 for fast development
- **State Management**: Zustand
- **Encryption**: libsodium-wrappers
- **Editor**: TipTap for rich text
- **Styling**: Tailwind CSS

#### Infrastructure

- **Containerization**: Docker / Podman
- **Orchestration**: Kubernetes / Docker Compose
- **Reverse Proxy**: Nginx
- **SSL/TLS**: Let's Encrypt (production)

## 🔧 Development

### Local Development Setup

#### Backend Development

```bash
cd backend

# Install dependencies
go mod download

# Set environment variables
export DATABASE_URL="postgres://postgres:password@localhost:5432/notes?sslmode=disable"
export REDIS_URL="localhost:6379"
export JWT_SECRET="development-secret-key"
export SERVER_ENCRYPTION_KEY="development-encryption-key-32ch"

# Run backend
go run main.go

# Or build and run
go build -o app .
./app
```

#### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

### Running Tests

```bash
# Backend tests
cd backend
go test -v ./...

# Frontend tests
cd frontend
npm test

# Integration tests
docker compose -f docker-compose.test.yml up --abort-on-container-exit
```

### Code Structure

```
secure-notes/
├── backend/
│   ├── main.go           # Server entry point
│   ├── go.mod            # Go dependencies
│   ├── Dockerfile        # Backend container
│   └── internal/         # Internal packages
│       ├── auth/         # Authentication logic
│       ├── crypto/       # Encryption utilities
│       └── database/     # Database operations
├── frontend/
│   ├── src/
│   │   ├── App.jsx       # Main React component
│   │   ├── main.jsx      # Entry point
│   │   └── components/   # React components
│   ├── package.json      # NPM dependencies
│   ├── vite.config.js    # Vite configuration
│   └── Dockerfile        # Frontend container
├── docker-compose.yml    # Docker Compose config
├── .env.example         # Environment template
└── README.md           # This file
```

## 🔒 Security Features

### Encryption Details

1. **Client-Side Encryption**
   - Algorithm: XChaCha20-Poly1305
   - Key Derivation: PBKDF2 with 600,000 iterations
   - All encryption happens in the browser

2. **Password Security**
   - Hashing: Argon2id (Memory: 64MB, Iterations: 3)
   - Salt: 32 bytes random per user
   - Account lockout after 5 failed attempts

3. **Database Security**
   - All sensitive fields encrypted at rest
   - PostgreSQL with SSL/TLS required
   - Connection pooling with pgx

4. **Network Security**
   - HTTPS enforced in production
   - CORS properly configured
   - Rate limiting on all endpoints
   - CSP headers implemented

### Security Best Practices

- Never commit `.env` files
- Rotate JWT secrets regularly
- Use strong passwords (12+ characters)
- Enable 2FA when available
- Regular security updates
- Monitor audit logs

## 🚢 Production Deployment

### Using Docker Compose

```bash
# Production deployment
docker compose up -d
```

### Using Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Or use Helm
helm install secure-notes ./charts/secure-notes
```

### Environment Variables

| Variable                | Description                      | Example                                |
| ----------------------- | -------------------------------- | -------------------------------------- |
| `DATABASE_URL`          | PostgreSQL connection string     | `postgres://user:pass@host:5432/notes` |
| `REDIS_URL`             | Redis connection string          | `redis:6379`                           |
| `JWT_SECRET`            | JWT signing secret (64 chars)    | Random 64-character string             |
| `SERVER_ENCRYPTION_KEY` | Server encryption key (32 chars) | Random 32-character string             |
| `CORS_ORIGINS`          | Allowed CORS origins             | `https://notes.example.com`            |
| `PORT`                  | Backend server port              | `8080`                                 |

## 📊 Monitoring

### Health Checks

- **Backend Health**: `GET /api/v1/health`
- **Database Status**: `GET /api/v1/ready`
- **Metrics**: `GET /metrics` (Prometheus format)

### Logging

All logs are structured JSON for easy parsing:

```json
{
  "level": "info",
  "timestamp": "2024-01-05T10:30:00Z",
  "message": "Server started",
  "port": 8080
}
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow existing code style and conventions
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📝 API Documentation

### Authentication

#### Register

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

#### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

### Notes

#### Create Note

```http
POST /api/v1/notes
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "My Encrypted Note",
  "content": "This will be encrypted",
  "encrypted": true
}
```

#### Get Notes

```http
GET /api/v1/notes
Authorization: Bearer <token>
```

## ⚠️ Troubleshooting

### Common Issues

**Problem**: Cannot connect to database

```bash
# Solution: Check PostgreSQL is running
docker compose ps
docker compose logs postgres
```

**Problem**: Frontend not loading

```bash
# Solution: Check backend is accessible
curl http://localhost:8080/api/v1/health
```

**Problem**: Build failures

```bash
# Solution: Clean and rebuild
docker compose down -v
docker compose build --no-cache
docker compose up
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Fiber](https://gofiber.io/) - Fast Go web framework
- [React](https://react.dev/) - UI library
- [PostgreSQL](https://www.postgresql.org/) - Database
- [Redis](https://redis.io/) - Caching layer
- [libsodium](https://libsodium.org/) - Encryption library
- [TipTap](https://tiptap.dev/) - Rich text editor

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/RelativeSure/notes/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/secure-notes/discussions)
- **Security**: TODO: Report security issues privately to <security@example.com>

---

**⭐ If you find this project useful, please consider giving it a star on GitHub!**
