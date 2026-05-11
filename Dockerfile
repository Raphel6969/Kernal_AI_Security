# Dockerfile for Aegix security backend
FROM node:20-slim AS frontend-builder

WORKDIR /app/frontend

# Build the React frontend inside the image so clean checkouts work everywhere.
COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for the backend runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install backend dependencies first for better cache reuse.
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend source and the built frontend bundle from the build stage.
COPY backend/ /app/backend/
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
COPY README.md /app/README.md

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
