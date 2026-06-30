// Package store defines the storage contracts for the Aegix two-tier
// database architecture:
//
//	HotStore  — SQLite synchronous cache (instant reads/writes per session)
//	ColdStore — Postgres durable store   (async batched upserts)
//	SyncAgent — background goroutine that drains Hot → Cold
package store

import "github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"

// HotStore is the SQLite-backed synchronous event cache.
// Every incoming event is written here first so dashboard reads are instant.
// The SyncAgent drains unsynced rows to Postgres in the background.
type HotStore interface {
	// Append writes a SecurityEvent synchronously.
	Append(event *model.SecurityEvent) error

	// GetRecent returns up to limit events, newest first.
	// agentID and sessionID are optional filters.
	GetRecent(limit int, agentID, sessionID *string) ([]*model.SecurityEvent, error)

	// GetEvent fetches one event by its application-level ID ("evt_…").
	// sessionID is an optional scoping filter.
	GetEvent(id string, sessionID *string) (*model.SecurityEvent, error)

	// Size returns the event count, optionally scoped by session or agent.
	Size(sessionID, agentID *string) (int, error)

	// CountByClassification counts events with the given classification label.
	CountByClassification(class string, agentID, sessionID *string) (int, error)

	// UpdateExplanation persists the Tier A/B rule explanation on an event.
	UpdateExplanation(eventID, explanation string, sessionID *string) error

	// UpdateLLMExplanation persists the async Tier C LLM explanation.
	UpdateLLMExplanation(eventID, explanation string) error

	// Clear deletes all events.  If sessionID is non-nil only that session
	// is affected.
	Clear(sessionID *string) error

	// GetUnsynced returns up to batchSize events not yet pushed to Postgres,
	// ordered oldest-first to maintain chronological order in Postgres.
	GetUnsynced(batchSize int) ([]*model.SecurityEvent, error)

	// MarkSynced marks eventIDs as successfully pushed to Postgres.
	MarkSynced(eventIDs []string) error

	// FlushSession deletes all already-synced rows for the given session.
	// Called when a session TTL expires or the user goes offline.
	FlushSession(sessionID string) error

	// Close releases database resources.
	Close() error
}

// ColdStore is the Postgres-backed durable store.
// Events are written here asynchronously by the SyncAgent.
type ColdStore interface {
	// UpsertBatch inserts a slice of events, ignoring duplicates (idempotent).
	UpsertBatch(events []*model.SecurityEvent) error

	// GetRecent returns up to limit events from Postgres.
	GetRecent(limit int, agentID, sessionID *string) ([]*model.SecurityEvent, error)

	// GetEvent fetches one event by application-level ID from Postgres.
	GetEvent(id string) (*model.SecurityEvent, error)

	// CountByClassification returns classification counts from Postgres.
	CountByClassification(class string, agentID, sessionID *string) (int, error)

	// Close tears down the connection pool.
	Close()
}
