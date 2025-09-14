## Admin Panel Usage

The admin panel allows privileged users to toggle admin, assign/remove roles, and inspect roles.

### Enable in builds
- Set build arg `VITE_ENABLE_ADMIN_PANEL=true` for the frontend (compose sets this in CI).
- Local compose: `export VITE_ENABLE_ADMIN_PANEL=true && docker compose up -d --build`.

### Using the panel
1. Log in as an admin.
2. Expand the “Admin” section below the app.
3. Enter a user UUID.
4. Use buttons to:
   - Load Roles
   - Make Admin / Revoke Admin
   - Assign Role / Remove Role (`moderator`, `auditor`, or `admin`)

The panel talks to admin endpoints documented in Swagger (`/api/v1/docs`).

### Admin Settings

- Registration toggle: enable/disable public sign‑ups.
  - Location: Admin Panel → User Management → “User Registration” switch.
  - Persists in database (`app_settings.registration_enabled`).
  - On boot, the backend seeds this from `ENABLE_REGISTRATION` if the DB value doesn’t exist yet.
  - Changing the toggle updates the DB immediately (survives restarts).

