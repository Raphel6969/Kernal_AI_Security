# Postman & Testing Examples

This document shows how to obtain a session token, use it in Postman (pre-request script), example `curl` and WebSocket commands, and testing/checks to verify session isolation. It also discusses JWT vs HMAC session tokens and using Redis for session storage.

If you want the current browser session token, open the frontend, go to Settings, and use the copy button under Session Token. That token is the one to paste into Postman or another machine when you want to share the same live demo session.

**Create a session token (GET /session)**

- Request: `GET /session`
- Response: `{ "session_token": "<token>" }`

Postman Pre-request Script (automatically fetch token and set an environment variable)

```javascript
pm.sendRequest({
  url: pm.environment.get('API_URL') + '/session',
  method: 'GET'
}, function (err, res) {
  if (!err && res && res.json) {
    pm.environment.set('session_token', res.json().session_token);
  }
});
```

Requests — include the session token as a query parameter (or header if you prefer):

- Analyze (POST)

```
POST {{API_URL}}/analyze?session_token={{session_token}}
Content-Type: application/json

{
  "command": "bash -c 'echo hello'"
}
```

If you want a totally separate history, turn `AUTO_FETCH_SESSION` off in the Postman collection variables and paste a different token manually. That keeps machine B on a different session from machine A.

- Get events (GET)

```
GET {{API_URL}}/events?session_token={{session_token}}&limit=100
```

- Get stats (GET)

```
GET {{API_URL}}/stats?session_token={{session_token}}
```

- Delete session events (DELETE)

```
DELETE {{API_URL}}/events?session_token={{session_token}}
```

WebSocket connection example (wscat or browser)

```
# wscat (npm install -g wscat)
wscat -c "{{WS_URL}}?session_token={{session_token}}"

# or JavaScript in browser
const ws = new WebSocket(`${WS_URL}?session_token=${sessionToken}`);
```

Curl examples

```bash
# Create session
curl -s {{API_URL}}/session | jq

# Analyze using token (replace TOKEN value)
curl -s -X POST "{{API_URL}}/analyze?session_token=TOKEN" -H 'Content-Type: application/json' -d '{"command": "echo hi"}'

# Fetch events
curl -s "{{API_URL}}/events?session_token=TOKEN"
```

How to test and verify it works

- Start backend locally:

```bash
conda activate aibouncer
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

- In Postman: add `API_URL` environment variable (e.g. `http://localhost:8000`), add the pre-request script to a collection or a request, then send `Analyze` and verify results show in the dashboard and `GET /events` returns only session events.

- Using `curl` and two tokens: create two tokens and ensure events posted under token A do not appear when fetching with token B (this mirrors the automated test `tests/test_session_isolation.py`).

Will this be different on different systems / deployments?

- Local single-instance demo: session-scoped in-memory store works as implemented. Each backend instance holds its own sessions in memory — sessions are isolated per instance.
- Multi-instance (scaled) deployments: in-memory sessions will be isolated per instance. To have session continuity across instances you need either:
  - Sticky sessions at the load balancer (route a session to the same backend instance).
  - A central session store (Redis) so all instances can read/write session data.

Trade-offs: HMAC-signed tokens (current) vs JWT

- HMAC signed token (current implementation):
  - Format: `<session_id>.<signature>` using the server `secret_key` (HMAC-SHA256).
  - Pros: simple, no external libraries, minimal token size, easy verification.
  - Cons: cannot carry metadata (expiry) unless you encode it into `session_id` or maintain server-side expiry; requires the same `secret_key` across instances or rotation strategy.

- JWT (JSON Web Token):
  - Pros: self-contained (can include `exp`, `iat`, `claims`), widely supported, easy to verify with public/private keys for asymmetric signing.
  - Cons: larger, needs library support (PyJWT / jose), if you include sensitive claims be careful; revocation requires server-side mapping (unless short expiry used).

How JWT would change workflow

- With JWT you can embed an expiry (e.g., 1 hour) inside the token (`exp`) so the server needs only to verify the signature and expiry — no server lookup required to validate token age.
- For demos, JWT simplifies client handling (no need to maintain server-side TTL), but you still need a session store for per-session event lists unless you encode events elsewhere. JWT alone does not replace session storage for event history.
- Migration steps to JWT:
  1. Add PyJWT dependency and a config for `JWT_SECRET` and `JWT_ALG` (or asymmetric keys).
  2. Change `/session` to return a JWT with `sub=session_id` and `exp` set.
  3. Replace `verify_session_token()` to decode and validate JWT and return `session_id` from `sub`.

Redis for session storage (when scaling or for persistence)

- Why Redis:
  - Shared in-memory datastore accessible by all backend instances.
  - Native TTL support (e.g., `EXPIRE`) so sessions auto-expire without background threads.
  - Fast, battle-tested for session caching and pub/sub (could also handle WebSocket notifications across instances).

- Integration points:
  - Replace `SessionEventStore` with a Redis implementation that stores events per key `session:<session_id>` (e.g., a Redis list or stream). Use `LPUSH` and `LRANGE` for append/read operations.
  - Use Redis TTL on the key so it expires automatically.
  - Optionally use Redis pub/sub or Redis Streams to broadcast events across instances for real-time WS updates.

- Trade-offs:
  - Adds an operational dependency (Redis server), but many free hosting options exist (e.g., Upstash for serverless Redis, free tier).
  - Slightly more complexity to implement (and test). But it enables correct behavior when scaling horizontally.

Summary recommendations

- For immediate demo needs: use the current HMAC signed session token + in-memory `SessionEventStore` (fast, minimal). Use Postman pre-request script to fetch a token automatically.
- If you plan to scale or want session persistence across instances, migrate `SessionEventStore` to Redis and keep the signed tokens (or move to JWT for embedded expiry).
- If you want revocable tokens or shorter-lived sessions, use JWT with short expiration and/or store a revocation list in Redis.

If you want, I can:

- Add a Postman collection JSON file to the repo containing the requests and pre-request script.
- Implement Redis-backed `SessionEventStore` and switch the app to use it when `REDIS_URL` is configured.
- Convert session tokens to JWT and implement decoding/validation.

Which of these should I do next?
