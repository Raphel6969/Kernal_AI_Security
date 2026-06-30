// Package store — SyncAgent: the background goroutine that drains the SQLite
// hot cache into the Postgres cold store on a configurable interval.
package store

import (
	"context"
	"log/slog"
	"time"
)

// SyncAgent drains unsynced events from the HotStore (SQLite) and pushes
// them to the ColdStore (Postgres) on a fixed interval.
//
// Data-flow:
//
//	SQLite.GetUnsynced(batch)
//	    → Postgres.UpsertBatch(events)
//	    → SQLite.MarkSynced(ids)
//
// Lifecycle:
//
//	agent := NewSyncAgent(hot, cold, 5, 100)
//	agent.Start()                     // non-blocking
//	// … application runs …
//	agent.Stop()                      // blocks until the goroutine exits
//
// Session flush:
//
//	agent.FlushSession(sessionID)     // removes synced rows for that session
type SyncAgent struct {
	hot       HotStore
	cold      ColdStore  // may be nil when Postgres is not configured
	interval  time.Duration
	batchSize int
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewSyncAgent creates a SyncAgent.
//   - hot        — the SQLite HotStore (required)
//   - cold       — the Postgres ColdStore (nil = Postgres disabled, loop is a no-op)
//   - intervalSec — seconds between drain cycles (default 5)
//   - batchSize  — max events per cycle  (default 100)
func NewSyncAgent(hot HotStore, cold ColdStore, intervalSec, batchSize int) *SyncAgent {
	if intervalSec <= 0 {
		intervalSec = 5
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	return &SyncAgent{
		hot:       hot,
		cold:      cold,
		interval:  time.Duration(intervalSec) * time.Second,
		batchSize: batchSize,
		done:      make(chan struct{}),
	}
}

// Start launches the drain loop as a background goroutine.
// Calling Start on an already-running agent is a no-op.
func (a *SyncAgent) Start() {
	if a.cancel != nil {
		return // already running
	}

	if a.cold == nil {
		slog.Info("SyncAgent: Postgres not configured — sync loop disabled")
		close(a.done) // satisfy Stop() callers
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go a.loop(ctx)
	slog.Info("SyncAgent: started", "interval", a.interval, "batch_size", a.batchSize)
}

// Stop signals the drain loop to exit and blocks until it has finished.
// It attempts one final drain on shutdown to minimise data loss.
func (a *SyncAgent) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	<-a.done
	slog.Info("SyncAgent: stopped")
}

// FlushSession removes all already-synced rows for the given session from
// the hot cache (SQLite).  Call this when a session TTL expires or the
// user explicitly logs out.
func (a *SyncAgent) FlushSession(sessionID string) {
	if err := a.hot.FlushSession(sessionID); err != nil {
		slog.Error("SyncAgent: FlushSession failed",
			"session_id", sessionID, "err", err)
		return
	}
	slog.Debug("SyncAgent: flushed session", "session_id", sessionID)
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (a *SyncAgent) loop(ctx context.Context) {
	defer close(a.done)

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final drain on shutdown — best-effort, no deadline.
			slog.Info("SyncAgent: shutdown drain starting")
			a.drain()
			return

		case <-ticker.C:
			a.drain()
		}
	}
}

// drain fetches one batch from SQLite, pushes it to Postgres, and marks it
// synced.  A single failure aborts the batch so nothing is lost — it will
// be retried on the next tick.
func (a *SyncAgent) drain() {
	events, err := a.hot.GetUnsynced(a.batchSize)
	if err != nil {
		slog.Error("SyncAgent: GetUnsynced failed", "err", err)
		return
	}
	if len(events) == 0 {
		return // nothing to sync
	}

	if err := a.cold.UpsertBatch(events); err != nil {
		slog.Error("SyncAgent: UpsertBatch failed",
			"count", len(events), "err", err)
		return
	}

	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	if err := a.hot.MarkSynced(ids); err != nil {
		slog.Error("SyncAgent: MarkSynced failed",
			"count", len(ids), "err", err)
		// Events were already written to Postgres; on next tick MarkSynced
		// will succeed and ON CONFLICT DO NOTHING handles the duplicate upsert.
		return
	}

	slog.Debug("SyncAgent: drain complete", "synced", len(events))
}
