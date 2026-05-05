# Build Log

Project: AI Bouncer + Kernel Guard: Real-time RCE Prevention System
Date: May 5, 2026

## What has been built so far

This workspace now has a full MVP scaffold for the system:
- a Python FastAPI backend for command analysis and WebSocket streaming
- a rule-based detection engine for obvious RCE patterns
- an ML training and inference path using scikit-learn
- in-memory event storage and shared event models
- a FastAPI app that exposes `/analyze`, `/events`, `/stats`, and `/ws`
- a React/Vite dashboard shell for real-time visualization
- Linux setup scripts for backend and kernel prerequisites
- curated safe and malicious command lists for model training and demo use
- setup and architecture documentation for the demo flow

The eBPF enforcement layer is scaffolded, but the actual kernel hook implementation is still a stub and will be built in the next phase.

## Session 1: Foundation and MVP scaffold

### Files created and what each one does

| File | Purpose | Current behavior |
| --- | --- | --- |
| [README.md](README.md) | Project entry point and quick start guide | Describes the system, setup steps, architecture, and run commands. |
| [.gitignore](.gitignore) | Ignore rules for local/build artifacts | Keeps virtualenvs, caches, compiled models, and frontend build output out of git. |
| [backend/requirements.txt](backend/requirements.txt) | Python dependency list | Pins FastAPI, scikit-learn, BCC, and supporting libraries for the backend. |
| [backend/__init__.py](backend/__init__.py) | Backend package marker | Makes `backend` importable as a Python package. |
| [backend/detection/__init__.py](backend/detection/__init__.py) | Detection package marker | Makes the detection modules importable. |
| [backend/events/__init__.py](backend/events/__init__.py) | Events package marker | Makes event model and store modules importable. |
| [backend/detection/rule_engine.py](backend/detection/rule_engine.py) | Rule-based threat detection | Scores commands using regex and keyword patterns for shells, reverse shells, destructive commands, exfiltration, and encoding. |
| [backend/detection/ml_scorer.py](backend/detection/ml_scorer.py) | ML inference wrapper | Loads the trained scikit-learn model and returns a malicious risk score for a command. |
| [backend/detection/pipeline.py](backend/detection/pipeline.py) | Combined decision engine | Blends rule score and ML score into a final classification and explanation. |
| [backend/models/train_model.py](backend/models/train_model.py) | Model training script | Reads safe/malicious command lists, trains a Logistic Regression classifier, and saves the model artifact. |
| [backend/events/models.py](backend/events/models.py) | Shared event dataclasses | Defines `ExecveEvent`, `DetectionResult`, and `SecurityEvent` for backend and UI data flow. |
| [backend/events/event_store.py](backend/events/event_store.py) | In-memory event buffer | Stores the latest security events in a deque and exposes helpers for stats and filtering. |
| [backend/kernel/rce_monitor.py](backend/kernel/rce_monitor.py) | eBPF monitor stub | Provides the process wrapper that will load and poll the execve kernel hook in the next phase. |
| [backend/kernel/execve_hook.py](backend/kernel/execve_hook.py) | Kernel hook manager wrapper | Gives a higher-level start/stop interface around the monitor stub. |
| [backend/app.py](backend/app.py) | FastAPI backend app | Exposes `/`, `/analyze`, `/events`, `/stats`, and `/ws`, and wires the detection pipeline to the event store. |
| [frontend/package.json](frontend/package.json) | Frontend dependencies and scripts | Sets up React, Vite, TypeScript, and the dev/build commands. |
| [frontend/tsconfig.json](frontend/tsconfig.json) | TypeScript compiler settings | Configures strict TypeScript compilation for the dashboard app. |
| [frontend/index.html](frontend/index.html) | Vite HTML entry point | Provides the root page shell that loads the React app. |
| [frontend/vite.config.ts](frontend/vite.config.ts) | Vite dev server config | Adds React support and a proxy target for backend API calls. |
| [frontend/src/main.tsx](frontend/src/main.tsx) | React bootstrapping entry | Mounts the app into the DOM. |
| [frontend/src/index.css](frontend/src/index.css) | Base document styles | Sets the page-wide typography, background, and root layout. |
| [frontend/src/App.tsx](frontend/src/App.tsx) | Top-level dashboard shell | Checks backend health and switches between the live dashboard and the offline message. |
| [frontend/src/App.css](frontend/src/App.css) | App shell styling | Styles the header, status badge, layout, and fallback message. |
| [frontend/src/useWebSocket.ts](frontend/src/useWebSocket.ts) | WebSocket hook | Connects to the backend socket, stores incoming events, and supports reconnect behavior. |
| [frontend/src/Dashboard.tsx](frontend/src/Dashboard.tsx) | Live dashboard view | Renders statistics, connection state, and a table of recent events. |
| [frontend/src/Dashboard.css](frontend/src/Dashboard.css) | Dashboard styling | Styles the stats cards, event table, risk bars, and classification badges. |
| [data/commands_safe.txt](data/commands_safe.txt) | Safe training examples | Contains benign shell and admin commands for model training and demo checks. |
| [data/commands_malicious.txt](data/commands_malicious.txt) | Malicious training examples | Contains known RCE, shell, exfiltration, and destructive examples for training and demo checks. |
| [scripts/setup_backend.sh](scripts/setup_backend.sh) | Python backend bootstrap script | Creates a venv and installs backend dependencies. |
| [scripts/setup_kernel.sh](scripts/setup_kernel.sh) | Linux kernel/eBPF bootstrap script | Installs clang, llvm, kernel headers, and BCC prerequisites. |
| [scripts/setup_frontend.sh](scripts/setup_frontend.sh) | Frontend bootstrap script | Installs frontend dependencies and prepares the dashboard app. |
| [scripts/demo.sh](scripts/demo.sh) | Demo runner | Sends sample commands to the backend and prints the detection results. |
| [scripts/test_attacks.sh](scripts/test_attacks.sh) | Detection smoke test script | Exercises the analyzer with safe, suspicious, and malicious commands. |
| [docs/SETUP.md](docs/SETUP.md) | Environment setup guide | Explains how to install dependencies, train the model, and run the stack. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architecture deep dive | Documents the three-layer flow, data flow, threat model, and implementation notes. |
| [docs/API.md](docs/API.md) | API reference | Documents the HTTP and WebSocket endpoints and response formats. |

## Current working state

- The backend is ready to run as an API-first MVP.
- The detection pipeline works in user space with rules plus ML scaffolding.
- The frontend is ready to consume the API and WebSocket stream.
- The kernel layer is prepared structurally, but the actual eBPF execve hook still needs implementation.

## Next implementation phase

1. Build the eBPF `execve` hook and ring-buffer event path.
2. Connect kernel events to the existing detection pipeline.
3. Add real-time event injection into the dashboard from kernel events.
4. Tighten the rule engine and train the initial ML model.
