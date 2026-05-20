# Aegix Roadmap & Product Development Plan

## Phase 1: Deploy-Ready Hardening (Weeks 1–2)

### Goals
Make the current system production-ready for single-instance demos and small deployments.

### Tasks
- [ ] **Health check endpoint** — add `/readyz` (liveness) and `/healthz` (readiness) probes that check DB, ML model, and eBPF hook status.
- [ ] **One-command startup** — create `start.sh` / `start.ps1` that handles Python venv, npm, and backend/frontend in parallel.
- [ ] **Persistent signing key** — verify `data/.session_secret` survives backend restarts (already done; validate in tests).
- [ ] **Event store cleanup** — implement TTL-based cleanup for SQLite (e.g., purge events older than 7 days).
- [ ] **CORS and security headers** — add CSP, X-Frame-Options, X-Content-Type-Options.
- [ ] **Rate limiting per IP** — apply stricter limits to `/analyze` and `/session` to prevent token spam.
- [ ] **Error handling and logging** — standardize JSON error responses and ensure logs are machine-readable.

**Deliverable**: A backend that survives restart, a frontend that persists tokens, and a startup script that works on Linux/WSL/Windows.

---

## Phase 2: Demo Operator Workflow (Weeks 2–3)

### Goals
Make it trivial for a non-technical operator to demo the system to customers.

### Tasks
- [ ] **Operator checklist** — create `DEMO.md` with step-by-step instructions:
  1. Start backend and frontend (one command).
  2. Open dashboard, copy session token.
  3. Paste token into Postman or second machine.
  4. Run test commands and show the dashboard update in real-time.
  5. Click New Session for a clean slate.
- [ ] **Pre-configured Postman collection** — include safe, suspicious, and malicious test cases with expected output (already done; validate UX).
- [ ] **Token visibility badge** — add session token (first 16 chars) to the top bar so the operator always knows which session they're on.
- [ ] **One-click test suite** — add a "Run Demo" button in the UI that submits a fixed set of test commands and shows results side-by-side.
- [ ] **Screen recording guide** — short video showing a demo end-to-end (no audio needed).

**Deliverable**: Operator can demo in < 10 minutes with zero setup confusion.

---

## Phase 3: Scale-Out Improvements (Weeks 3–4)

### Goals
Prepare the system for multi-instance deployments and persistent data.

### Tasks
- [ ] **Redis-backed session store** — replace in-memory `SessionEventStore` with Redis (compatible with current API).
- [ ] **Postgres support** — swap SQLite for Postgres as the primary event store (optional; keep SQLite as fallback).
- [ ] **Sticky session routing** — add load-balancer hints so a session always hits the same backend (or use Redis to make it stateless).
- [ ] **Cross-instance WebSocket broadcast** — use Redis pub/sub to broadcast events to subscribers on different backend instances.
- [ ] **JWT tokens with expiry** — optionally migrate to JWT with 1-hour TTL and refresh tokens (keep HMAC as fallback).

**Deliverable**: System can run on 2+ backend instances with events visible across all frontends.

---

## Phase 4: Real-Life Product Features (Months 2–6)

### 4.1 Authentication & Multi-User Support
- [ ] **User accounts** — basic auth (username/password or SAML/OAuth).
- [ ] **API keys** — for CI/CD and headless scanning.
- [ ] **Role-based access control (RBAC)** — admin, operator, analyst, read-only roles.
- [ ] **Team workspaces** — segregate events and rules by team.
- [ ] **Session sharing with expiry** — share a limited-time session link with a customer.

**Why**: Enterprise customers need to control who sees what and audit access.

### 4.2 Audit Logging & Compliance
- [ ] **Full audit trail** — log every action (login, command analysis, rule change, event deletion) with timestamp, user, IP, result.
- [ ] **Immutable logs** — write to a dedicated audit table that cannot be modified or deleted.
- [ ] **Compliance reports** — generate SOC 2, ISO 27001, or HIPAA compliance snapshots on demand.
- [ ] **Data retention policies** — auto-archive old events to S3/GCS; offer 30-day, 90-day, 1-year retention tiers.

**Why**: Regulated industries (fintech, healthcare, government) require proof of what happened and who did it.

### 4.3 Advanced Threat Intelligence
- [ ] **VirusTotal / AlienVault integration** — check command hashes against known malware databases.
- [ ] **Threat feed subscriptions** — auto-update rule engine with latest exploit patterns.
- [ ] **MITRE ATT&CK mapping** — label detected commands with MITRE ATT&CK tactics (e.g., "Execution").
- [ ] **Indicators of Compromise (IOCs)** — allow users to upload file/hash/domain IOCs and flag commands that touch them.

**Why**: SOC teams want to tie incidents to known threats and track attack techniques.

### 4.4 Team Collaboration & Incident Response
- [ ] **Slack / Teams integration** — auto-post malicious commands to a channel, with approval workflows.
- [ ] **Incident tickets** — auto-create tickets in Jira / ServiceNow for malicious events.
- [ ] **Comment & annotation** — team members add context to events (e.g., "False positive - deployment script").
- [ ] **Alert rules UI** — drag-and-drop rule builder instead of editing JSON.
- [ ] **Runbooks** — link events to runbooks (e.g., "If reverse shell detected, follow incident response playbook X").

**Why**: Security teams work in incident queues; integrate into their existing tools.

### 4.5 Enhanced Visibility & Reporting
- [ ] **Attack timeline** — visualize when commands run, grouped by severity and actor.
- [ ] **Risk dashboard** — KPIs like "# malicious commands blocked this week", "% of commands blocked", "mean response time".
- [ ] **Custom dashboards** — allow analysts to pin events, charts, and KPIs they care about.
- [ ] **CSV/JSON export** — download events and reports for external tools or insurance.
- [ ] **Scheduled reports** — auto-email daily/weekly/monthly summaries to stakeholders.

**Why**: Management wants metrics; analysts want flexible views.

### 4.6 Rule Management & Customization
- [ ] **Custom rule builder** — UI to add regexes, entropy thresholds, and keyword lists without code.
- [ ] **Rule versioning & rollback** — track rule changes and revert if a rule starts blocking legitimate traffic.
- [ ] **A/B testing for rules** — test a new rule on a sample of events before applying globally.
- [ ] **Rule provenance** — show who wrote each rule, when, and why (linked to tickets/docs).

**Why**: Every environment is different; one-size-fits-all rules fail fast.

### 4.7 Agent Deployment & Management
- [ ] **Agent registration** — agents self-register and report status (heartbeat, version, eBPF load).
- [ ] **Remote agent config** — push rule changes to agents without restart.
- [ ] **Agent auto-update** — agents fetch latest binary and restart safely.
- [ ] **Agent grouping** — tag agents by datacenter/app/environment and manage them in bulk.

**Why**: Running 100+ agents manually is unsustainable.

### 4.8 Cost Optimization & Performance
- [ ] **Local model inference** — cache model predictions to avoid re-scoring identical commands.
- [ ] **Batch analysis API** — accept 100 commands in one request and return scores in < 1s.
- [ ] **Metric sampling** — log detailed metrics only for suspicious/malicious commands.
- [ ] **Cost estimation** — show users how much they spend per month on analysis and storage.

**Why**: Customers care about both latency and monthly bill.

### 4.9 High Availability & Disaster Recovery
- [ ] **Multi-region deployment** — replicate data to a standby region and auto-failover.
- [ ] **Backup strategy** — daily snapshots of SQLite/Postgres to S3; restore in < 15 min.
- [ ] **Database sharding** — split events by time or customer to avoid single-table bottlenecks.
- [ ] **Circuit breaker for external APIs** — gracefully degrade if VirusTotal or threat feeds are down.

**Why**: Enterprise SLAs demand 99.9% uptime and < 1 hour RTO.

### 4.10 Container & Kubernetes Support
- [ ] **Helm chart** — one-command deploy to any K8s cluster.
- [ ] **Prometheus metrics** — expose request latency, error rates, model inference time.
- [ ] **Liveness / readiness probes** — Kubernetes can auto-restart failed containers.
- [ ] **Network policies** — specify which pods can talk to each other.

**Why**: Enterprise platforms run on K8s; make it a first-class deployment target.

---

## Timeline & Priorities

### Immediate (This week)
1. Move this plan to `plan.md` ✅
2. Validate Phase 1 tasks (health checks, startup script).
3. Create `DEMO.md` and test the operator workflow.

### Short-term (Weeks 2–3)
- Complete Phase 2 (demo UX).
- Begin Phase 3 exploration (Redis + Postgres).

### Medium-term (Months 2–3)
- Phase 3 full implementation.
- Start Phase 4.1 (auth) and 4.2 (audit logs).

### Long-term (Months 4–12)
- Roll out Phase 4.3–4.10 based on customer feedback.

---

## Success Metrics

- **Demo readiness**: Operator completes full demo in < 10 minutes.
- **Production readiness**: System survives 24-hour load test with no data loss.
- **Enterprise adoption**: 3+ production customers running 2+ backend instances each.
- **Performance**: < 10ms rule engine + < 50ms ML inference for 95th percentile.
- **Cost per analysis**: < $0.001 per command scored.

---

## Open Questions

1. **Threat intel**: Which feeds (VirusTotal, YARA, custom?) should we integrate first?
2. **Pricing model**: Per-command, per-agent, per-month seat, or usage-based?
3. **Target verticals**: Fintech, healthcare, government, SaaS, or all of the above?
4. **Deployment**: Should we offer SaaS or on-prem only?
5. **ML model**: Fine-tune the model on customer data, or keep it generic?

---

## Notes

- Keep backward compatibility with the current HMAC token format during migration to JWT.
- Ensure all new features have toggles so legacy customers are not forced to adopt them.
- Document every API change in a changelog and provide migration guides.
