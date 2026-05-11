#!/bin/bash
cd /mnt/c/Users/raphe/Webdev/Projects/kernal_ai_bouncer
docker rm -f aibouncer 2>/dev/null || true
echo "Building Docker image..."
docker build --no-cache -t aibouncer-backend:latest -f Dockerfile . 2>&1 | tail -20
echo "---"
echo "Starting container..."
docker run --name aibouncer --rm -d -p 8000:8000 --env-file .env aibouncer-backend:latest
sleep 4
echo "---"
curl -s http://localhost:8000/ | head -5
