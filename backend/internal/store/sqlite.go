// Package store — SQLite hot-cache implementation of HotStore.
package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

const sqliteDriverName = "sqlite"

// SQLiteStore is the synchronous hot-cache backed by a local SQLite file.
// Writes are serialised with a mutex so the single SQLite writer is never
// blocked by concurrent API calls.  WAL mode allows unlimited parallel reads.
type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex // serialises all writes
}

// NewSQLiteStore opens (or creates) the SQLite database at dbPath,
// enables WAL mode, and runs schema migrations.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("sqlite: create db dir: %w", err)
	}

	// busy_timeout gives writers up to 5 s to wait for the lock before
	// returning SQLITE_BUSY — avoids errors under brief concurrent load.
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", dbPath)
	db, err := sql.Open(sqliteDriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}

	// One writer at a time; WAL allows unlimited readers concurrently.
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)

	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate: %w", err)
	}

	slog.Info("SQLiteStore ready", "path", dbPath)
	return s, nil
}

// ── Schema ────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) migrate() error {
	// Idempotent table creation — safe to run on every startup.
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS security_events (
			id                    TEXT PRIMARY KEY,   -- internal UUID (row key)
			event_id              TEXT NOT NULL,      -- application ID "evt_…"
			agent_id              TEXT,
			session_id            TEXT,
			timestamp             REAL NOT NULL,
			detected_at           REAL NOT NULL,
			pid                   INTEGER DEFAULT 0,
			ppid                  INTEGER DEFAULT 0,
			uid                   INTEGER DEFAULT 0,
			gid                   INTEGER DEFAULT 0,
			command               TEXT DEFAULT '',
			argv_str              TEXT DEFAULT '',
			comm                  TEXT DEFAULT '',
			classification        TEXT DEFAULT '',
			risk_score            REAL DEFAULT 0,
			ml_confidence         REAL DEFAULT 0,
			matched_rules         TEXT DEFAULT '[]',  -- JSON array
			explanation           TEXT DEFAULT '',
			llm_explanation       TEXT DEFAULT '',
			remediation_action    TEXT,
			remediation_status    TEXT,
			process_memory_mb     REAL DEFAULT 0,
			system_memory_percent REAL DEFAULT 0,
			synced_to_postgres    INTEGER DEFAULT 0,  -- 0=pending, 1=synced
			synced_at             REAL,               -- epoch when synced
			created_at            REAL DEFAULT (unixepoch())
		);

		CREATE INDEX IF NOT EXISTS idx_event_id
			ON security_events(event_id);
		CREATE INDEX IF NOT EXISTS idx_timestamp
			ON security_events(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_agent_ts
			ON security_events(agent_id, timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_session_ts
			ON security_events(session_id, timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_classification
			ON security_events(classification);
		CREATE INDEX IF NOT EXISTS idx_unsynced
			ON security_events(synced_to_postgres, detected_at ASC);
	`)
	if err != nil {
		return err
	}

	// Additive migrations for databases created by the old Python backend.
	// Errors are intentionally swallowed — they just mean the column exists.
	additions := []string{
		`ALTER TABLE security_events ADD COLUMN llm_explanation TEXT DEFAULT ''`,
		`ALTER TABLE security_events ADD COLUMN process_memory_mb REAL DEFAULT 0`,
		`ALTER TABLE security_events ADD COLUMN system_memory_percent REAL DEFAULT 0`,
		`ALTER TABLE security_events ADD COLUMN synced_to_postgres INTEGER DEFAULT 0`,
		`ALTER TABLE security_events ADD COLUMN synced_at REAL`,
		`ALTER TABLE security_events ADD COLUMN agent_id TEXT`,
		`ALTER TABLE security_events ADD COLUMN session_id TEXT`,
		`ALTER TABLE security_events ADD COLUMN remediation_action TEXT`,
		`ALTER TABLE security_events ADD COLUMN remediation_status TEXT`,
	}
	for _, stmt := range additions {
		_, _ = s.db.Exec(stmt)
	}

	return nil
}

// ── HotStore interface ────────────────────────────────────────────────────────

// Append writes a SecurityEvent to SQLite synchronously.
func (s *SQLiteStore) Append(event *model.SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rowID := uuid.New().String()
	_, err := s.db.Exec(`
		INSERT INTO security_events (
			id, event_id, agent_id, session_id,
			timestamp, detected_at,
			pid, ppid, uid, gid,
			command, argv_str, comm,
			classification, risk_score, ml_confidence,
			matched_rules, explanation, llm_explanation,
			remediation_action, remediation_status,
			process_memory_mb, system_memory_percent
		) VALUES (
			?,?,?,?,
			?,?,
			?,?,?,?,
			?,?,?,
			?,?,?,
			?,?,?,
			?,?,
			?,?
		)`,
		rowID, event.ID,
		event.ExecveEvent.AgentID, event.ExecveEvent.SessionID,
		event.ExecveEvent.Timestamp, event.DetectedAt,
		event.ExecveEvent.PID, event.ExecveEvent.PPID,
		event.ExecveEvent.UID, event.ExecveEvent.GID,
		event.ExecveEvent.Command, event.ExecveEvent.ArgvStr, event.ExecveEvent.Comm,
		event.DetectionResult.Classification,
		event.DetectionResult.RiskScore,
		event.DetectionResult.MLConfidence,
		model.MarshalRules(event.DetectionResult.MatchedRules),
		event.DetectionResult.Explanation,
		event.DetectionResult.LLMExplanation,
		event.RemediationAction, event.RemediationStatus,
		event.ExecveEvent.ProcessMemoryMB,
		event.ExecveEvent.SystemMemoryPercent,
	)
	return err
}

// GetRecent returns up to limit events, newest first.
func (s *SQLiteStore) GetRecent(limit int, agentID, sessionID *string) ([]*model.SecurityEvent, error) {
	where, args := buildWhere(agentID, sessionID)
	query := fmt.Sprintf(
		`SELECT %s FROM security_events %s ORDER BY timestamp DESC LIMIT ?`,
		selectCols, where,
	)
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// GetEvent fetches one event by application event_id.
func (s *SQLiteStore) GetEvent(id string, sessionID *string) (*model.SecurityEvent, error) {
	var (
		query string
		args  []any
	)
	if sessionID != nil {
		query = fmt.Sprintf(
			`SELECT %s FROM security_events WHERE event_id=? AND session_id=? LIMIT 1`,
			selectCols,
		)
		args = []any{id, *sessionID}
	} else {
		query = fmt.Sprintf(
			`SELECT %s FROM security_events WHERE event_id=? LIMIT 1`,
			selectCols,
		)
		args = []any{id}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events, err := scanEvents(rows)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	return events[0], nil
}

// Size returns the count of events, optionally scoped.
func (s *SQLiteStore) Size(sessionID, agentID *string) (int, error) {
	where, args := buildWhere(agentID, sessionID)
	row := s.db.QueryRow(
		fmt.Sprintf(`SELECT COUNT(*) FROM security_events %s`, where),
		args...,
	)
	var n int
	return n, row.Scan(&n)
}

// CountByClassification counts events with a given classification label.
func (s *SQLiteStore) CountByClassification(class string, agentID, sessionID *string) (int, error) {
	where, args := buildWhere(agentID, sessionID)
	var extra string
	if where == "" {
		extra = "WHERE classification=?"
	} else {
		extra = where + " AND classification=?"
	}
	args = append(args, class)

	row := s.db.QueryRow(
		fmt.Sprintf(`SELECT COUNT(*) FROM security_events %s`, extra),
		args...,
	)
	var n int
	return n, row.Scan(&n)
}

// UpdateExplanation persists a Tier A/B explanation on an existing event.
func (s *SQLiteStore) UpdateExplanation(eventID, explanation string, sessionID *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sessionID != nil {
		_, err := s.db.Exec(
			`UPDATE security_events SET explanation=? WHERE event_id=? AND session_id=?`,
			explanation, eventID, *sessionID,
		)
		return err
	}
	_, err := s.db.Exec(
		`UPDATE security_events SET explanation=? WHERE event_id=?`,
		explanation, eventID,
	)
	return err
}

// UpdateLLMExplanation persists the async Tier C LLM explanation.
func (s *SQLiteStore) UpdateLLMExplanation(eventID, explanation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`UPDATE security_events SET llm_explanation=? WHERE event_id=?`,
		explanation, eventID,
	)
	return err
}

// Clear deletes events. If sessionID is non-nil only that session is cleared.
func (s *SQLiteStore) Clear(sessionID *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sessionID != nil {
		_, err := s.db.Exec(
			`DELETE FROM security_events WHERE session_id=?`, *sessionID,
		)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM security_events`)
	return err
}

// GetUnsynced returns up to batchSize events not yet pushed to Postgres,
// ordered oldest-first.
func (s *SQLiteStore) GetUnsynced(batchSize int) ([]*model.SecurityEvent, error) {
	rows, err := s.db.Query(
		fmt.Sprintf(
			`SELECT %s FROM security_events WHERE synced_to_postgres=0 ORDER BY detected_at ASC LIMIT ?`,
			selectCols,
		),
		batchSize,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// MarkSynced marks the given event IDs as successfully pushed to Postgres.
func (s *SQLiteStore) MarkSynced(eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Build IN clause: (?,?,?,...) — safe because eventIDs are our own UUIDs.
	placeholders := strings.Repeat("?,", len(eventIDs))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]any, len(eventIDs)+1)
	args[0] = float64(time.Now().UnixNano()) / 1e9
	for i, id := range eventIDs {
		args[i+1] = id
	}

	_, err := s.db.Exec(
		fmt.Sprintf(
			`UPDATE security_events SET synced_to_postgres=1, synced_at=? WHERE event_id IN (%s)`,
			placeholders,
		),
		args...,
	)
	return err
}

// FlushSession deletes all already-synced rows for a session.
// Any unsynced rows are left in place so the SyncAgent can still push them.
func (s *SQLiteStore) FlushSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(
		`DELETE FROM security_events WHERE session_id=? AND synced_to_postgres=1`,
		sessionID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	slog.Debug("SQLiteStore: flushed session", "session_id", sessionID, "deleted", n)
	return nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// selectCols is the canonical column list used in every SELECT query.
// Explicit ordering avoids bugs if the schema is later altered.
const selectCols = `
	event_id, agent_id, session_id,
	timestamp, detected_at,
	pid, ppid, uid, gid,
	command, argv_str, comm,
	classification, risk_score, ml_confidence,
	matched_rules, explanation, llm_explanation,
	remediation_action, remediation_status,
	process_memory_mb, system_memory_percent
`

// buildWhere constructs a WHERE clause and argument list from optional filters.
func buildWhere(agentID, sessionID *string) (string, []any) {
	var clauses []string
	var args []any

	if sessionID != nil {
		clauses = append(clauses, "session_id=?")
		args = append(args, *sessionID)
	}
	if agentID != nil {
		clauses = append(clauses, "agent_id=?")
		args = append(args, *agentID)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// scanEvents reads all rows into a SecurityEvent slice.
func scanEvents(rows *sql.Rows) ([]*model.SecurityEvent, error) {
	var events []*model.SecurityEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			slog.Error("SQLiteStore: scan row error", "err", err)
			continue
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// scanEvent scans a single row into a SecurityEvent.
func scanEvent(row *sql.Rows) (*model.SecurityEvent, error) {
	var (
		eventID              string
		agentID, sessionID   sql.NullString
		timestamp, detectedAt float64
		pid, ppid, uid, gid  int64
		command, argvStr, comm string
		classification       string
		riskScore, mlConf    float64
		matchedRulesJSON     string
		explanation          string
		llmExplanation       sql.NullString
		remAction, remStatus sql.NullString
		procMem, sysMem      float64
	)

	err := row.Scan(
		&eventID, &agentID, &sessionID,
		&timestamp, &detectedAt,
		&pid, &ppid, &uid, &gid,
		&command, &argvStr, &comm,
		&classification, &riskScore, &mlConf,
		&matchedRulesJSON, &explanation, &llmExplanation,
		&remAction, &remStatus,
		&procMem, &sysMem,
	)
	if err != nil {
		return nil, err
	}

	ev := &model.SecurityEvent{
		ID: eventID,
		ExecveEvent: model.ExecveEvent{
			PID:                 pid,
			PPID:                ppid,
			UID:                 uid,
			GID:                 gid,
			Command:             command,
			ArgvStr:             argvStr,
			Timestamp:           timestamp,
			Comm:                comm,
			ProcessMemoryMB:     procMem,
			SystemMemoryPercent: sysMem,
		},
		DetectionResult: model.DetectionResult{
			RiskScore:      riskScore,
			Classification: classification,
			MatchedRules:   model.UnmarshalRules(matchedRulesJSON),
			MLConfidence:   mlConf,
			Explanation:    explanation,
		},
		DetectedAt: detectedAt,
	}

	if agentID.Valid {
		ev.ExecveEvent.AgentID = &agentID.String
	}
	if sessionID.Valid {
		ev.ExecveEvent.SessionID = &sessionID.String
	}
	if llmExplanation.Valid {
		ev.DetectionResult.LLMExplanation = llmExplanation.String
	}
	if remAction.Valid {
		ev.RemediationAction = &remAction.String
	}
	if remStatus.Valid {
		ev.RemediationStatus = &remStatus.String
	}

	return ev, nil
}
