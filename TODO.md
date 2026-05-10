TODO: Full run analysis Feature
TODO: LLM integration

---
### Phase 4: Cloud Deployment Architecture

#### Step 1 — Multi-Tenancy
- [ ] Add `agent_id` field to `ExecveEvent`, `AgentEventRequest`, `SecurityEvent`
- [ ] Stamp `agent_id` on every event at `/agent/events` ingestion
- [ ] Filter `GET /events?agent_id=xxx` by agent
- [ ] Filter WebSocket `/ws?agent_id=xxx` broadcast by agent

#### Step 2 — Database: Turso Cloud SQLite
- [ ] Create Turso account at turso.tech (free, no CC)
- [ ] `pip install libsql-experimental`
- [ ] Swap `sqlite3` connection in `event_store.py` for `libsql` with env-var connection string
- [ ] Add `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` to `.env.example`

#### Step 3 — Dockerize Backend
- [ ] Write `Dockerfile` (python:3.11-slim base, EXPOSE 8000)
- [ ] Write `.dockerignore` (exclude frontend/, *.db, .env, __pycache__)
- [ ] Write `docker-compose.yml` for local testing
- [ ] Test: `docker build -t aibouncer . && docker run -p 8000:8000 aibouncer`

#### Step 4 — Deploy Backend (Hugging Face Spaces)
- [ ] Create HF Space in Docker mode
- [ ] Push repo / connect GitHub
- [ ] Add secrets: `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `FRONTEND_ORIGINS`
- [ ] Verify `/healthz` returns 200

#### Step 5 — Agent Installer Script
- [ ] Write `scripts/install_agent.sh` (generates UUID agent_id, writes conf, installs systemd service)
- [ ] Write `backend/agent/standalone_agent.py` (self-contained, reads conf file)
- [ ] Add `GET /agent/download` endpoint to serve the agent script
- [ ] Add `GET /install.sh` endpoint to serve the installer
- [ ] Test one-liner: `curl -sSL https://your-app.hf.space/install.sh | bash`

#### Step 6 — Deploy Frontend
- [ ] Set `VITE_API_URL=https://your-app.hf.space` in `frontend/.env.production`
- [ ] Deploy to Vercel: `cd frontend && vercel --prod`
- [ ] Update `FRONTEND_ORIGINS` in backend env to include Vercel URL
