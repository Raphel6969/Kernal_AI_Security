TODO: Full run analysis Feature
TODO: LLM integration

---

## 📄 White Paper: Memory Resource Profiling Layer

### The Problem: Silent Memory Bombs & Resource Exhaustion Attacks

Traditional RCE prevention focuses on *command syntax* — detecting shells, injections, and obfuscated payloads. But an attacker can bypass all of these by launching a legitimate command that performs a destructive *side effect*. **Memory bombs** (processes that allocate massive RAM at spawn time) are a blind spot:

**Example Attack:**
```bash
# This looks "benign" from a syntax perspective
# But allocates 500MB of RAM immediately, causing DoS
python3 -c "import os; x = bytearray(500*1024*1024); os.execvp('bash', ['bash'])"
```

A traditional rule engine sees `python3` → "benign". But at the kernel level, `psutil` reports the process has already consumed 500MB at T=0. This is anomalous and suggests:
- **Crypto-mining payload** being decompressed and started
- **Memory exhaustion attack** on a resource-constrained container
- **Data exfiltration pipeline** (download + decompress in memory, then upload)

### How We Fix It: Memory-Aware Scoring

Our **RuleEngine** now captures three memory signals at process spawn time:

1. **Process Memory (RSS)** — Instantaneous RSS of the process at syscall intercept
   - Threshold: **>50MB at T=0** → +30 risk penalty
   - Rationale: Most legitimate shells, Python interpreters, and userland tools spawn at <30MB. Anything larger is statistically anomalous.

2. **System Memory Pressure** — Total system RAM usage at event time
   - Threshold: **>80% system RAM in use** → +10 risk penalty  
   - Rationale: Signals the system is already under stress; new spawns in this context are higher-risk (could be the final straw in an attack chain).

3. **Matched Rule** — `memory_hog_XXXmb` and `system_memory_critical_YYY%` are recorded in the event for forensic visibility.

All signals are captured in real-time by the kernel hook and streamed to the dashboard, where they appear in the **Live Events Table** and **Latest Detection Card** for operator awareness.

**Code locations:**
- Memory capture: [backend/app.py](backend/app.py#L212-L216)
- Rule-based scoring: [backend/detection/rule_engine.py](backend/detection/rule_engine.py#L102-L109)
- Pipeline integration: [backend/detection/pipeline.py](backend/detection/pipeline.py#L46)
- Event model: [backend/events/models.py](backend/events/models.py#L22-L23)
- UI display: [frontend/src/ThreatMonitor.tsx](frontend/src/ThreatMonitor.tsx) (Process Mem & System RAM columns)
- Test coverage: [tests/test_memory_profiling.py](tests/test_memory_profiling.py)

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
