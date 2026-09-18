# Modern multi-stage Dockerfile for Aegix security backend and dashboard.
# Compatible with Hugging Face Spaces (port 7860), Render, and standalone Docker deployments.

# ── Stage 1: Frontend Build ────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

ARG VITE_API_URL
ENV VITE_API_URL=${VITE_API_URL}

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# ── Stage 2: Go Backend Build ──────────────────────────────────────────────────
FROM golang:alpine AS backend-builder

WORKDIR /app/backend

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
RUN go build -o aegix ./cmd/aegix

# ── Stage 3: Production Runtime ────────────────────────────────────────────────
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy Go binary
COPY --from=backend-builder /app/backend/aegix /usr/local/bin/aegix

# Copy frontend static build for embedded Chi SPA serving
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Copy trained model weights and initial data
COPY data/trained_model.json /app/data/trained_model.json

# Default environment
ENV API_HOST=0.0.0.0 \
    API_PORT=7860 \
    PORT=7860 \
    DB_PATH=/app/data/events.db \
    KERNEL_MONITOR_OWNER=disabled \
    EVENT_CACHE_SIZE=1000

EXPOSE 7860 8000

CMD ["aegix"]