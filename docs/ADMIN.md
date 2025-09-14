Admin Access and Panel

Overview
- Admin routes are protected by role-based access control on the backend.
- The frontend shows an admin panel icon only for admin users; non‑admins never see it.

Grant Yourself Admin (local/dev)
- Get your user ID (UUID):
  - Log in, then open the browser DevTools → Application → Local Storage → find `current_user_id`.
  - Alternatively, inspect the login/register response if debugging the network; it includes `user_id`.
  - Or decode the JWT stored in `secure_token`:
    - In the browser console:
      `JSON.parse(atob(localStorage.getItem('secure_token').split('.')[1])).user_id`
- Add your UUID to the `.env` file as a comma‑separated list:
  - `ADMIN_USER_IDS=<your-uuid-here>`
  - Multiple: `ADMIN_USER_IDS=<uuid-1>,<uuid-2>`
- Restart the stack so the backend picks up env changes:
  - `make down && make up` (or `COMPOSE_DRIVER=docker make up`)

Using the Admin Panel
- Once you are an admin, a shield icon appears in the app header.
- Click the shield icon to toggle the Admin Panel.
- The Admin Panel lets you:
  - Toggle a user’s built‑in `is_admin` flag.
  - Assign or remove RBAC roles (e.g., `moderator`, `auditor`).
  - Load current roles for a given user.
- Tip: The panel pre‑fills the “User ID” field with your own `current_user_id`. Use the “Use my ID” button if you need to re‑apply it.

Security Notes
- Admin endpoints require a valid JWT and admin role; the UI gating is a convenience, but the backend enforces access.
- Do not expose `ADMIN_USER_IDS` in production images; manage admin status through the database and role assignment flows instead.
