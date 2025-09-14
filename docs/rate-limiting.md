## Registration Rate Limiting

To reduce abuse in non-local environments, the registration endpoint is rate-limited.

### Behavior
- Endpoint: `POST /api/v1/auth/register`
- Limit: 5 requests per minute per IP
- Enabled when `APP_ENV` is not `development` or `local`.

### Configuration
- Environment variables:
  - `APP_ENV=production` enables limiting.
  - `APP_ENV=development` disables limiting for local dev.

### Notes
- General app rate limiting (100/min/IP) still applies globally.

