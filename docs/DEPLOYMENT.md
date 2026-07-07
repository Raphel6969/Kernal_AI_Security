# Deployment Guide

<p align="center">
    <img src="../frontend/src/assets/aegix-logo.png" alt="Aegix logo" width="180" />
</p>

## 🚀 Current Deployment Status

✅ **Live on Hugging Face Spaces**: https://huggingface.co/spaces/Raphel3116/aegix_security

The Aegix system is currently deployed on Hugging Face Spaces with:
- Single Docker container (frontend + backend combined)
- Trained ML model baked into the image at build time
- SQLite persistence
- WebSocket real-time event streaming
- Auto-remediation disabled (hosted container constraint — no kernel-level privileges)

This guide covers deploying the Aegix system in production, including the backend API and frontend web UI.

## Architecture Overview

**Multi-Container Docker Compose Stack**

```
┌─────────────────────────────────────────────────────────────┐
│                   DOCKER COMPOSE NETWORK                    │
│                                                             │
│  ┌─────────────────┐       ┌─────────────────────────────┐  │
│  │ NGINX (Port 80) │──────▶│ React Frontend (Port 5173)  │  │
│  │ Reverse Proxy   │       │ / (Static SPA routing)      │  │
│  └───────┬─────────┘       └─────────────────────────────┘  │
│          │                                                  │
│          │ /api/*                                           │
│          ▼                                                  │
│  ┌─────────────────────────────┐    ┌────────────────────┐  │
│  │ Go Backend (Port 8000)      │───▶│ PostgreSQL (5432)  │  │
│  │ Chi Router, OAuth logic     │    │ Central Storage    │  │
│  └───────┬─────────────────────┘    └────────────────────┘  │
│          │                                                  │
│          │ Edge Sync / Caching                              │
│          ▼                                                  │
│  ┌─────────────────────────────┐                            │
│  │ SQLite (.aegix_edge.db)     │                            │
│  │ Local high-speed persistence│                            │
│  └─────────────────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Highly scalable and decoupled services
- Secure reverse-proxy routing via NGINX (hides internal ports)
- Dual-database architecture ensures zero event loss at the edge
- Production-grade authentication with HTTP-only cookies and SameSite restrictions

---

## Local Testing

Before deploying to production, test the Docker image locally.

### 1. Setup Environment Variables

```bash
cp .env.example .env
```
Edit the `.env` file to include your OAuth credentials:
```env
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### 2. Build and Run via Docker Compose

```bash
docker-compose up -d --build
```

Verify all services are running:
```bash
docker-compose ps
# You should see nginx, postgres, backend, and frontend containers running
```

### 3. Test Endpoints

**Local Testing**:
```bash
# Check API health
curl http://localhost/api/healthz

# Analyze a command
curl -X POST http://localhost/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"curl http://example.com"}'

# Test WebSocket
curl -i -N -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  http://localhost/api/ws
```

### 4. Stop Services

```bash
docker-compose down
```

---

## Production Deployment

### Option A: Self-Hosted (Recommended for Full Control)

#### Prerequisites
- Linux server with Docker installed
- Domain name (for HTTPS)
- Let's Encrypt certificate (for HTTPS)

#### 1. Push Image to Registry

```bash
# Tag image with registry name
docker tag aegix:latest your-registry/aegix:latest

# Push to Docker Hub, AWS ECR, or private registry
docker push your-registry/aegix:latest
```

#### 2. Deploy on Server

```bash
# SSH into server
ssh user@your-server.com

# Clone or update repo
git clone https://github.com/your-org/kernal_ai_bouncer.git
cd kernal_ai_bouncer

# Create production .env
cat > .env.prod << EOF
API_HOST=0.0.0.0
API_PORT=8000
API_LOG_LEVEL=warning
DB_PATH=/data/events.db
EVENT_CACHE_SIZE=1000
FRONTEND_ORIGINS=https://your-domain.com
BACKEND_URL=https://your-domain.com
AGENT_EVENT_TIMEOUT=30
EOF

# Create data directory with permissions
mkdir -p ./data
chmod 755 ./data

# Pull and run with docker-compose
docker-compose -f docker-compose.yml up -d
```

#### 3. Setup Reverse Proxy (Nginx)

```nginx
# /etc/nginx/sites-available/aegix
upstream backend {
    server 127.0.0.1:8000;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL certificates (from Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Proxy API requests
    location /api/ {
        proxy_pass http://backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://backend/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }

    # Frontend (served by backend)
    location / {
        proxy_pass http://backend/;
        proxy_set_header Host $host;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

Enable and restart Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/aegix /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### 4. Setup SSL Certificate

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --nginx -d your-domain.com

# Auto-renewal (should be enabled by default)
sudo systemctl enable certbot.timer
```

#### 5. Verify Deployment

```bash
# Check container status
docker-compose logs -f aibouncer-backend

# Test HTTPS endpoint
curl https://your-domain.com/stats

# Open in browser
open https://your-domain.com
```

---

### Option B: HuggingFace Spaces (Free, Easy)

Current public Space: https://huggingface.co/spaces/Raphel3116/aegix_security

#### 1. Create Spaces Repository

1. Go to https://huggingface.co/spaces
2. Click "Create new Space"
3. Name: `aegix`
4. License: Apache 2.0
5. Space type: **Docker**
6. Private/Public: Your choice

---

### Option C: Isolated Container Deployment with Native eBPF

To run Aegix in a containerized, isolated environment (e.g. Docker) while retaining full **eBPF kernel-level process monitoring**, the container must have access to the host's kernel and compile tools.

#### Why eBPF is disabled in standard containers
By default, Docker isolates container processes in their own PID, network, and security namespaces. eBPF tracepoints require `CAP_SYS_ADMIN` or `CAP_BPF` permissions to load code into the host kernel and need access to kernel header files to compile the tracepoint source.

#### Setup Requirements

1. **Host OS**: The physical or virtual machine running Docker must be a Linux system (Kernel >= 5.4) with BCC headers installed (e.g. `linux-headers-$(uname -r)`).
2. **Container Privileges**: The container must be run in **privileged mode** (`--privileged`) to allow syscall hooks.
3. **PID Namespace**: Set the container PID mode to `host` so it can track process IDs across the entire machine.
4. **Volume Mounts**: Mount the kernel headers, modules, and debug interfaces:
   * `/lib/modules:/lib/modules:ro` (Kernel modules)
   * `/usr/src:/usr/src:ro` (Kernel source files for header references)
   * `/sys/kernel/debug:/sys/kernel/debug` (Kernel debug filesystem for eBPF ring buffer interaction)

#### Docker Compose Configuration (`docker-compose.ebpf.yml`)

Create a specialized Docker Compose file to launch Aegix with eBPF isolation:

```yaml
version: '3.8'

services:
  aegix-secure:
    build: .
    image: aegix:latest
    container_name: aegix-secure-ebpf
    restart: unless-stopped
    privileged: true
    pid: "host"
    network_mode: "host"  # Binding directly to host ports for zero-overhead
    environment:
      - API_HOST=0.0.0.0
      - API_PORT=8000
      - API_LOG_LEVEL=info
      - KERNEL_MONITOR_OWNER=backend  # The container's backend daemon compiles and attaches eBPF
      - DB_PATH=/app/data/events.db
      - EVENT_CACHE_SIZE=5000
      - BACKEND_URL=http://localhost:8000
    volumes:
      - ./data:/app/data
      - /lib/modules:/lib/modules:ro
      - /usr/src:/usr/src:ro
      - /sys/kernel/debug:/sys/kernel/debug
```

#### Launching the Isolated eBPF Daemon

Run the container using the configuration:
```bash
# Build the image containing dependencies
docker build -t aegix:latest .

# Launch in isolated eBPF mode
docker compose -f docker-compose.ebpf.yml up -d
```

Verify that the eBPF tracepoint is running inside the container:
```bash
docker logs -f aegix-secure-ebpf
# Look for: "RCE Monitor started - monitoring execve syscalls"
```

