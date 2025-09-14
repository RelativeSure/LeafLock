## RBAC Overview

This app supports role-based access control to protect admin-only features.

### Roles
- admin: full access to admin APIs and Swagger docs
- moderator: reserved for future moderation actions
- auditor: read-only reports in future
- user: default role for every user

Roles are stored in tables `roles` and `user_roles`. Users also have a boolean `is_admin` for a quick admin flag.

### Admin APIs
- GET `/api/v1/admin/health`
- PUT `/api/v1/admin/users/:id/admin` `{ "admin": true|false }`
- GET `/api/v1/admin/roles`
- GET `/api/v1/admin/users/:id/roles`
- POST `/api/v1/admin/users/:id/roles` `{ "role": "moderator" }`
- DELETE `/api/v1/admin/users/:id/roles/:role`

All admin endpoints require JWT and `admin` role. Swagger is available at `/api/v1/docs` for admins.

### Local bootstrap
- Temporary allowlist via env var: `ADMIN_USER_IDS=uuid1,uuid2`
- Use it to grant first admin, then set `is_admin` via API.

