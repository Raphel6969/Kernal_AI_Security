# Demo Data & Hosting Options — Plan

Date: 2026-05-16

Purpose: document safe hosting and storage options for demos so no user data is retained or shared unintentionally. This plan outlines architectures, trade-offs, and concrete implementation steps for each option.

Goals
- Demonstrate API and dashboard behavior for demos without persisting raw user commands publicly.
- Provide clear, low-effort options to isolate or avoid storing sensitive data.
- Recommend a path that minimizes code changes while meeting the promise: "I am not storing any user data."

Quick recommendation
- Preferred: Option 1 (Stateless demo) or Option 2 (Session-scoped ephemeral storage). Both meet the "no user data stored" promise and are low-risk.

Options

1) Stateless demo mode (recommended when promising no storage)
   - Behavior: `/analyze` runs detection and returns response; nothing is written to disk or DB.
   - Dashboard: shows only instant responses and optionally a short in-memory ring buffer (TTL) that is lost on restart.
   - Pros: easiest to guarantee no persisted PII/commands, minimal code changes.
   - Cons: no durable history for later analysis.
   - Implementation steps:
     1. Add a config flag (e.g., `DEMO_MODE=true`) to disable writes in `ingest_security_event`.
     2. When `DEMO_MODE` is set, skip `event_store.append(...)` and `alert_manager.dispatch(...)`.
     3. Keep WebSocket broadcast working from in-memory event list if desired.

2) Session-scoped ephemeral storage (recommended if you want short history per visitor)
   - Behavior: create a random `session_id` on dashboard load. Events are stored only under that `session_id` in-memory or in a short-lived cache (Redis with TTL or an in-process LRU cache with TTL).
   - Pros: users see their own events, history survives reloads for a short time, still avoids long-term storage.
   - Cons: requires generating and storing session token in the browser; careful eviction required.
   - Implementation steps:
     1. Add `session_id` query param or cookie when the dashboard connects (frontend change).
     2. Extend `ingest_security_event` to accept `session_id` and, when present and in demo mode, store events in an in-memory map keyed by `session_id` (or in Redis with TTL).
     3. Add `/events?session_id=...` support to return only that session's events; do not persist them to permanent DB.

3) Tenant-scoped Postgres with access control (for later persistence)
   - Behavior: store events with a `tenant_id` (not `agent_id`) and enforce isolation via Row-Level Security (RLS) or application-layer checks.
   - Pros: allows durable storage and multi-tenant isolation.
   - Cons: more complex; still requires strict privacy policy and credentials management; not ideal if you promised no storage.
   - Implementation steps:
     1. Add `tenant_id` to schema and require it on all API calls (or map session to tenant id).
     2. Configure DB auth / RLS (e.g., Supabase/Neon + RLS policies) or implement app-level access checks using API keys.
     3. Migrate data carefully; purge existing sensitive events first.

4) One isolated DB per demo (operationally heavy)
   - Behavior: create a dedicated DB/instance per demo audience or friend.
   - Pros: strong separation.
   - Cons: operationally expensive and still persists user data unless you purge it.

Data model & privacy notes
- Do not use `agent_id` as the privacy/tenant boundary. `agent_id` is a runtime observable and often `NULL` for API calls.
- If storing anything, prefer `session_id` or `tenant_id` as the isolation key.
- Consider storing only redacted results or hashes instead of raw commands:
  - `command_hash = sha256(trimmed_command)` (non-reversible)
  - Store `classification`, `risk_score`, `matched_rules`, and `explanation` (no raw command)

Neon/Postgres credentials
- The Neon connection string shared in the project must be rotated if exposed publicly. Do not leave production credentials in `.env` inside the repo.

Concrete code changes (minimal, safe path: choose Option 1 or 2)
- Add `DEMO_MODE` and `SESSION_MODE` flags to `backend/config.py`.
- Modify `backend/app.py::ingest_security_event` to:
  - if `DEMO_MODE`: do not call `event_store.append()` or persist the command; optionally keep a limited in-memory ring buffer.
  - if `SESSION_MODE`: accept `session_id` and store events only in volatile session store.
- Keep `DATABASE_URL` support (already added). When `DEMO_MODE` or `SESSION_MODE` is active, bypass Postgres writes.

Steps I can implement next (pick one)
1. Implement Option 1: add `DEMO_MODE` flag and stop writes to DB (fast, minimal risk).
2. Implement Option 2: session-scoped ephemeral store (requires frontend + backend changes).
3. Implement Option 3: full tenant model + RLS migration guide (larger effort).

Security checklist before public demos
- Rotate Neon/Postgres credentials if they were exposed.
- Ensure `.env` is not committed; enforce `.gitignore` (done).
- Do not publish dashboards with `FRONTEND_ORIGINS` set to `*`.

Appendix: Minimal demo-mode psuedocode

```
# in backend/app.py -> ingest_security_event
if settings.demo_mode:
    # run detection only, do not persist raw command
    asyncio.create_task(alert_manager.dispatch_demo(security_event))
    await broadcast_event(security_event)
    return security_event
else:
    event_store.append(security_event)
    asyncio.create_task(alert_manager.dispatch(security_event))
```

---
If you'd like, I can now implement Option 1 (safe, small patch) and add a short demo in `docs/DEPLOYMENT.md` showing how to run a stateless demo on Render or Fly.io. Tell me which option to implement and I will make the change and update tests accordingly.
