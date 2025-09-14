## Swagger API Docs

Admin-only Swagger is served at:
- UI: `/api/v1/docs`
- Spec: `/api/v1/docs/openapi.json`

All endpoints are documented in `backend/docs/openapi.json`.

### Authentication
- Add a JWT bearer token (from `/auth/register` or `/auth/login`).
- Access requires `admin` role.

### Testing locally
- Bootstrap by setting `ADMIN_USER_IDS=<your-user-id>` and restart backend.
- Open the UI and try the admin endpoints.

### Contributing to the spec
- Update `backend/docs/openapi.json` and include:
  - request/response schemas in `components.schemas`
  - examples in `responses[*].content[*].examples`
  - security requirements as needed

