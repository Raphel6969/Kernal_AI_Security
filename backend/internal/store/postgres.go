// Package store — Postgres cold-store implementation of ColdStore.
// Uses pgxpool for connection pooling and batched upserts.
// If DATABASE_URL is empty NewPostgresStore returns (nil, nil) and the
// SyncAgent skips all Postgres operations gracefully.
package store

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

// PostgresStore is the async durable store backed by Postgres.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects to Postgres using the provided DSN and runs
// schema migrations.  Returns (nil, nil) when databaseURL is empty so
// callers can treat a nil *PostgresStore as "Postgres disabled".
func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	if databaseURL == "" {
		slog.Info("PostgresStore: DATABASE_URL not set — Postgres storage disabled")
		return nil, nil
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}

	// Pool tuning — sensible defaults for a security backend.
	cfg.MaxConns = 10
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect pool: %w", err)
	}

	// Verify the connection is reachable.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping failed: %w", err)
	}

	ps := &PostgresStore{pool: pool}
	if err := ps.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}

	slog.Info("PostgresStore ready", "url", maskDSN(databaseURL))
	return ps, nil
}

// ── Schema ────────────────────────────────────────────────────────────────────

func (ps *PostgresStore) migrate(ctx context.Context) error {
	_, err := ps.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS security_events (
			id                    TEXT PRIMARY KEY,   -- application event ID "evt_…"
			agent_id              TEXT,
			session_id            TEXT,
			timestamp             DOUBLE PRECISION NOT NULL,
			detected_at           DOUBLE PRECISION NOT NULL,
			pid                   BIGINT DEFAULT 0,
			ppid                  BIGINT DEFAULT 0,
			uid                   BIGINT DEFAULT 0,
			gid                   BIGINT DEFAULT 0,
			command               TEXT DEFAULT '',
			argv_str              TEXT DEFAULT '',
			comm                  TEXT DEFAULT '',
			classification        TEXT DEFAULT '',
			risk_score            DOUBLE PRECISION DEFAULT 0,
			ml_confidence         DOUBLE PRECISION DEFAULT 0,
			matched_rules         TEXT DEFAULT '[]',
			explanation           TEXT DEFAULT '',
			llm_explanation       TEXT DEFAULT '',
			remediation_action    TEXT,
			remediation_status    TEXT,
			process_memory_mb     DOUBLE PRECISION DEFAULT 0,
			system_memory_percent DOUBLE PRECISION DEFAULT 0,
			created_at            TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS pg_idx_session_ts
			ON security_events(session_id, timestamp DESC);
		CREATE INDEX IF NOT EXISTS pg_idx_agent_ts
			ON security_events(agent_id, timestamp DESC);

		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'viewer',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'local';
		ALTER TABLE users ADD COLUMN IF NOT EXISTS provider_id TEXT NOT NULL DEFAULT '';
		
		CREATE INDEX IF NOT EXISTS pg_idx_classification
			ON security_events(classification);
		CREATE INDEX IF NOT EXISTS pg_idx_detected_at
			ON security_events(detected_at DESC);
	`)
	return err
}

// ── ColdStore interface ───────────────────────────────────────────────────────

// UpsertBatch inserts a slice of events into Postgres, silently ignoring
// duplicates (ON CONFLICT DO NOTHING makes this fully idempotent).
func (ps *PostgresStore) UpsertBatch(events []*model.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use pgx.CopyFrom for maximum batch throughput.
	rows := make([][]any, 0, len(events))
	for _, e := range events {
		rows = append(rows, []any{
			e.ID,
			e.ExecveEvent.AgentID,
			e.ExecveEvent.SessionID,
			e.ExecveEvent.Timestamp,
			e.DetectedAt,
			e.ExecveEvent.PID,
			e.ExecveEvent.PPID,
			e.ExecveEvent.UID,
			e.ExecveEvent.GID,
			e.ExecveEvent.Command,
			e.ExecveEvent.ArgvStr,
			e.ExecveEvent.Comm,
			e.DetectionResult.Classification,
			e.DetectionResult.RiskScore,
			e.DetectionResult.MLConfidence,
			model.MarshalRules(e.DetectionResult.MatchedRules),
			e.DetectionResult.Explanation,
			e.DetectionResult.LLMExplanation,
			e.RemediationAction,
			e.RemediationStatus,
			e.ExecveEvent.ProcessMemoryMB,
			e.ExecveEvent.SystemMemoryPercent,
		})
	}

	cols := []string{
		"id", "agent_id", "session_id",
		"timestamp", "detected_at",
		"pid", "ppid", "uid", "gid",
		"command", "argv_str", "comm",
		"classification", "risk_score", "ml_confidence",
		"matched_rules", "explanation", "llm_explanation",
		"remediation_action", "remediation_status",
		"process_memory_mb", "system_memory_percent",
	}

	// pgx.CopyFrom does not support ON CONFLICT, so we use a temp table
	// + INSERT … SELECT … ON CONFLICT DO NOTHING pattern.
	conn, err := ps.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: acquire conn: %w", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Create a temp staging table matching the main schema (without indices).
	_, err = tx.Exec(ctx, `
		CREATE TEMP TABLE IF NOT EXISTS _stage_events (LIKE security_events INCLUDING DEFAULTS)
		ON COMMIT DELETE ROWS
	`)
	if err != nil {
		return fmt.Errorf("postgres: create stage: %w", err)
	}

	// Bulk-copy into the staging table.
	_, err = tx.CopyFrom(
		ctx,
		pgx.Identifier{"_stage_events"},
		cols,
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("postgres: copy to stage: %w", err)
	}

	// Upsert from staging → main, ignoring duplicates.
	_, err = tx.Exec(ctx, fmt.Sprintf(`
		INSERT INTO security_events (%s)
		SELECT %s FROM _stage_events
		ON CONFLICT (id) DO NOTHING
	`, strings.Join(cols, ","), strings.Join(cols, ",")))
	if err != nil {
		return fmt.Errorf("postgres: upsert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}

	slog.Debug("PostgresStore: upserted batch", "count", len(events))
	return nil
}

// GetRecent returns up to limit events from Postgres, newest first.
func (ps *PostgresStore) GetRecent(limit int, agentID, sessionID *string) ([]*model.SecurityEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	where, args := pgWhere(agentID, sessionID)
	query := fmt.Sprintf(`
		SELECT %s FROM security_events %s ORDER BY timestamp DESC LIMIT $%d
	`, pgSelectCols, where, len(args)+1)
	args = append(args, limit)

	rows, err := ps.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetRecent: %w", err)
	}
	defer rows.Close()

	return pgScanEvents(rows)
}

// GetEvent fetches a single event by application-level event ID.
func (ps *PostgresStore) GetEvent(id string) (*model.SecurityEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := ps.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM security_events WHERE id=$1 LIMIT 1`, pgSelectCols),
		id,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetEvent: %w", err)
	}
	defer rows.Close()

	events, err := pgScanEvents(rows)
	if err != nil || len(events) == 0 {
		return nil, err
	}
	return events[0], nil
}

// CountByClassification returns the count of events with the given label.
func (ps *PostgresStore) CountByClassification(class string, agentID, sessionID *string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	where, args := pgWhere(agentID, sessionID)
	extra := fmt.Sprintf("AND classification=$%d", len(args)+1)
	if where == "" {
		extra = fmt.Sprintf("WHERE classification=$%d", len(args)+1)
		where = ""
	}
	args = append(args, class)

	var n int
	err := ps.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM security_events %s %s`, where, extra),
		args...,
	).Scan(&n)
	return n, err
}

// Close shuts down the connection pool.
func (ps *PostgresStore) Close() {
	ps.pool.Close()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

const pgSelectCols = `
	id, agent_id, session_id,
	timestamp, detected_at,
	pid, ppid, uid, gid,
	command, argv_str, comm,
	classification, risk_score, ml_confidence,
	matched_rules, explanation, llm_explanation,
	remediation_action, remediation_status,
	process_memory_mb, system_memory_percent
`

// pgWhere builds a parameterised WHERE clause for pgx (uses $N placeholders).
func pgWhere(agentID, sessionID *string) (string, []any) {
	var clauses []string
	var args []any

	if sessionID != nil {
		args = append(args, *sessionID)
		clauses = append(clauses, fmt.Sprintf("session_id=$%d", len(args)))
	}
	if agentID != nil {
		args = append(args, *agentID)
		clauses = append(clauses, fmt.Sprintf("agent_id=$%d", len(args)))
	}

	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// pgScanEvents scans pgx rows into a SecurityEvent slice.
func pgScanEvents(rows pgx.Rows) ([]*model.SecurityEvent, error) {
	var events []*model.SecurityEvent
	for rows.Next() {
		var (
			eventID              string
			agentID, sessionID   *string
			timestamp, detectedAt float64
			pid, ppid, uid, gid  int64
			command, argvStr, comm string
			classification       string
			riskScore, mlConf    float64
			matchedRulesJSON     string
			explanation          string
			llmExplanation       *string
			remAction, remStatus *string
			procMem, sysMem      float64
		)

		err := rows.Scan(
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
			slog.Error("PostgresStore: scan row", "err", err)
			continue
		}

		ev := &model.SecurityEvent{
			ID: eventID,
			ExecveEvent: model.ExecveEvent{
				AgentID:             agentID,
				SessionID:           sessionID,
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
			DetectedAt:        detectedAt,
			RemediationAction: remAction,
			RemediationStatus: remStatus,
		}
		if llmExplanation != nil {
			ev.DetectionResult.LLMExplanation = *llmExplanation
		}

		events = append(events, ev)
	}
	return events, rows.Err()
}

// maskDSN hides the password in a DSN for safe logging.
func maskDSN(dsn string) string {
	if i := strings.Index(dsn, "@"); i != -1 {
		if j := strings.LastIndex(dsn[:i], ":"); j != -1 {
			return dsn[:j+1] + "****" + dsn[i:]
		}
	}
	return dsn
}

// ── User Management ───────────────────────────────────────────────────────────

func (ps *PostgresStore) CreateUser(ctx context.Context, u *model.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, auth_provider, provider_id, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := ps.pool.Exec(ctx, query, u.ID, u.Email, u.PasswordHash, u.Provider, u.ProviderID, u.Role, u.CreatedAt, u.UpdatedAt)
	return err
}

func (ps *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `
		SELECT id, email, password_hash, auth_provider, provider_id, role, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	var u model.User
	err := ps.pool.QueryRow(ctx, query, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Provider, &u.ProviderID, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (ps *PostgresStore) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	query := `
		SELECT id, email, password_hash, auth_provider, provider_id, role, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	var u model.User
	err := ps.pool.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Provider, &u.ProviderID, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (ps *PostgresStore) UpsertOAuthUser(ctx context.Context, u *model.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, auth_provider, provider_id, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (email) DO UPDATE SET
			auth_provider = EXCLUDED.auth_provider,
			provider_id = EXCLUDED.provider_id,
			updated_at = NOW()
		RETURNING id, role, created_at
	`
	return ps.pool.QueryRow(ctx, query, 
		u.ID, u.Email, u.PasswordHash, u.Provider, u.ProviderID, u.Role, u.CreatedAt, u.UpdatedAt,
	).Scan(&u.ID, &u.Role, &u.CreatedAt)
}
