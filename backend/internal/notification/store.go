// Package notification — in-memory notification store and department registry.
//
// NotificationStore is safe for concurrent use.
// Notifications are optionally scoped to a session_id when session mode is active.
// The store caps at 500 entries to prevent unbounded growth.
package notification

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

const maxNotifications = 500

// NotificationStore holds notifications and the department email registry.
type NotificationStore struct {
	mu            sync.RWMutex
	notifications []*model.Notification
	departments   []model.Department
}

// NewNotificationStore allocates a NotificationStore.
func NewNotificationStore() *NotificationStore {
	return &NotificationStore{}
}

// ── Notifications ─────────────────────────────────────────────────────────────

// Add appends a new notification, assigning an ID and timestamp.
func (ns *NotificationStore) Add(n *model.Notification) {
	n.ID = "notif_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:8]
	n.CreatedAt = time.Now()

	ns.mu.Lock()
	ns.notifications = append(ns.notifications, n)
	// Cap the store.
	if len(ns.notifications) > maxNotifications {
		ns.notifications = ns.notifications[len(ns.notifications)-maxNotifications:]
	}
	ns.mu.Unlock()
}

// List returns all notifications, newest-first, optionally filtered by sessionID.
func (ns *NotificationStore) List(sessionID *string) []*model.Notification {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	var out []*model.Notification
	for i := len(ns.notifications) - 1; i >= 0; i-- {
		n := ns.notifications[i]
		if sessionID == nil || n.SessionID == nil || *n.SessionID == *sessionID {
			// Return a copy to avoid data races on the pointer.
			cp := *n
			out = append(out, &cp)
		}
	}
	if out == nil {
		return []*model.Notification{}
	}
	return out
}

// UnreadCount returns the number of unread notifications in scope.
func (ns *NotificationStore) UnreadCount(sessionID *string) int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	count := 0
	for _, n := range ns.notifications {
		if !n.Read {
			if sessionID == nil || n.SessionID == nil || *n.SessionID == *sessionID {
				count++
			}
		}
	}
	return count
}

// MarkRead marks a single notification as read and returns an error if not found.
func (ns *NotificationStore) MarkRead(id string, sessionID *string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for _, n := range ns.notifications {
		if n.ID == id {
			if sessionID != nil && n.SessionID != nil && *n.SessionID != *sessionID {
				return fmt.Errorf("notification %q not in this session", id)
			}
			n.Read = true
			return nil
		}
	}
	return fmt.Errorf("notification %q not found", id)
}

// MarkAllRead marks all in-scope notifications as read.
func (ns *NotificationStore) MarkAllRead(sessionID *string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for _, n := range ns.notifications {
		if sessionID == nil || n.SessionID == nil || *n.SessionID == *sessionID {
			n.Read = true
		}
	}
}

// Delete removes a notification by ID.
func (ns *NotificationStore) Delete(id string, sessionID *string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for i, n := range ns.notifications {
		if n.ID == id {
			if sessionID != nil && n.SessionID != nil && *n.SessionID != *sessionID {
				return fmt.Errorf("notification %q not in this session", id)
			}
			ns.notifications = append(ns.notifications[:i], ns.notifications[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("notification %q not found", id)
}

// Clear deletes all in-scope notifications.
func (ns *NotificationStore) Clear(sessionID *string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if sessionID == nil {
		ns.notifications = nil
		return
	}
	kept := ns.notifications[:0]
	for _, n := range ns.notifications {
		if n.SessionID != nil && *n.SessionID != *sessionID {
			kept = append(kept, n)
		}
	}
	ns.notifications = kept
}

// ── Departments ───────────────────────────────────────────────────────────────

// SetDepartments replaces the full department list.
func (ns *NotificationStore) SetDepartments(depts []model.Department) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.departments = make([]model.Department, len(depts))
	copy(ns.departments, depts)
}

// GetDepartments returns a copy of the department list.
func (ns *NotificationStore) GetDepartments() []model.Department {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	if len(ns.departments) == 0 {
		return []model.Department{}
	}
	out := make([]model.Department, len(ns.departments))
	copy(out, ns.departments)
	return out
}

// UpsertDepartment adds or updates a department entry by name.
func (ns *NotificationStore) UpsertDepartment(dept model.Department) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	for i, d := range ns.departments {
		if d.Name == dept.Name {
			ns.departments[i] = dept
			return
		}
	}
	ns.departments = append(ns.departments, dept)
}
