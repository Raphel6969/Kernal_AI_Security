# Documentation Hub

This folder contains the project documentation in one place.

## Start Here

- [Quick Start](QUICK_START.md) - Fast setup and test flow for the current build
- [Setup Guide](SETUP.md) - Environment setup and runtime notes
- [Architecture](ARCHITECTURE.md) - System design and data flow
- [API Reference](API.md) - HTTP and WebSocket contract
- [Phase 2 Testing](PHASE2_TESTING.md) - Validation guide for kernel capture and fallback mode

## Status Notes

- Kernel capture is Linux-only and falls back cleanly on Windows and WSL2.
- The dashboard now receives live events through the WebSocket stream.
- The current remaining work is persistence, alerting, and optional platform expansion.

## Supporting Files

- [BUILD_LOG.md](../BUILD_LOG.md) - Session history and implementation notes
- [README.md](../README.md) - Project overview and top-level entry point