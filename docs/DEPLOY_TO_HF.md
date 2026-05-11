Deploy backend to Hugging Face Spaces (Docker)

<p align="center">
  <img src="../frontend/src/assets/aegix-logo.png" alt="Aegix logo" width="180" />
</p>

This guide explains how to package and run the backend in Docker on a Hugging Face Space (Docker mode), and how to provide Turso/libSQL secrets so the running container connects to your Turso database.

Prerequisites
- A Turso (libSQL) database and DB token. Create with `turso db tokens create <db>`.
- (Optional) A container registry if you prefer to push images outside HF Spaces.
- HF account with permission to create a Space in Docker mode.

Recommended approach
1. Build locally (Linux / WSL recommended)
   - From repository root:
     ```bash
    docker build -t aegix:latest -f backend/Dockerfile .
     ```
   - Test locally with Turso env vars (or mount secret file):
     ```bash
     export TURSO_DATABASE_URL='libsql://<your-db>.turso.io'
     export TURSO_AUTH_TOKEN='<db-token>'
     export USE_TURSO=true
     docker run --rm -p 8000:8000 \
       -e TURSO_DATABASE_URL -e TURSO_AUTH_TOKEN -e USE_TURSO \
      aegix:latest
     ```
   - Or provide the token as a Docker secret when using `docker stack`/compose.

2. Push to HF Spaces (Docker mode)
   - In the Space settings choose "Use a Docker image" and either:
     - Provide an image from a public registry (e.g., `ghcr.io/your/image:tag`), or
     - Let HF build from a `Dockerfile` if you push the repo to a GitHub repo and connect it.

3. Set Secrets in HF Space
   - In the Space settings > "Secrets", add:
     - `TURSO_DATABASE_URL` = your libsql URL
     - `TURSO_AUTH_TOKEN` = the DB token you created
     - `USE_TURSO` = `true`
   - The container will receive these via environment variables.

4. Healthchecks & Ports
   - The backend listens on the configured `API_HOST` and `API_PORT` (defaults: `0.0.0.0:8000`).
   - Ensure your Space exposes the server port (HF Spaces maps ports automatically for Docker mode when the container binds to 0.0.0.0).

5. Verify runtime Turso connectivity
   - After the Space is running, use the HF Space logs or open a terminal to run:
     ```bash
     python -c "from backend.events.event_store import get_event_store; s=get_event_store(); print('size', s.size())"
     ```
   - If `USE_TURSO=true` and `TURSO_*` env vars are present, `get_event_store()` will attempt to connect to Turso automatically.

Notes & Troubleshooting
- Build environment: libsql Python client may build native extensions; building inside Linux (WSL or container) is recommended. On Windows the Rust/maturin toolchain can cause build failures.
- Secrets: HF Space secrets are environment variables; they are the safest way to provide the DB token.
- Logs: Replace debug prints with logging (backend already uses `logging`). Use HF Space logs to debug connection issues.
- If libsql client version incompatibility occurs: the code attempts runtime adaptation; inspect logs for `libsql` client errors.

Next steps
- Optionally create a `docker-compose` + secret file locally to test secret mounting path `/run/secrets/turso_auth_token` to match Docker Swarm or production setups.
- If you want, I can (A) run a repo-wide pass to convert remaining prints to logging, (B) build a minimal CI workflow for building and pushing the image, or (C) prepare the Space repo settings and sample `app.yml` for HF. Let me know which you'd prefer.
