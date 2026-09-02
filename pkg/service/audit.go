package service

import (
	"context"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

const (
	defaultAuditLogsListLimit = 50
	maxAuditLogsListLimit     = 200
)

// recordAuditEvent persists an audit-log row if Cfg.AuditLog.Enabled. Called
// by auditHook (see hook.go) for the lifecycle events it wraps, plus a
// couple of call sites in auth.go that aren't backed by a Hook method
// (failed logins, account lockout). Failures are logged, not returned —
// audit persistence must never block the security event it's recording.
func (a *Auth) recordAuditEvent(ctx context.Context, userID, eventType string, metadata models.JSONMap) {
	if !a.Cfg.AuditLog.Enabled {
		return
	}
	if _, err := a.Repo.AuditLogCreate(ctx, &models.AuditLog{
		UserID:    userID,
		EventType: eventType,
		Metadata:  metadata,
	}); err != nil {
		xlog.Error("failed to record audit event", "user_id", userID, "event_type", eventType, "err", err)
	}
}

// ListAuditLogsOptions defines the filter/pagination parameters for AuditLogs.
type ListAuditLogsOptions struct {
	// EventType filters to a single models.AuditEvent* value; "" means no filter.
	EventType string

	// Since/Until filter by event time (inclusive).
	Since *time.Time
	Until *time.Time

	Limit  int
	Offset int
}

// ListAuditLogsResult is a page of a user's audit log.
type ListAuditLogsResult struct {
	Events  []*models.AuditLog `json:"events"`
	HasMore bool               `json:"has_more"`
}

// AuditLogs lists/filters a user's persisted audit log, most recent first.
// ezauth performs no authorization check here — same stance as UsersList —
// the caller is responsible for verifying the requester may view this
// user's audit log.
func (a *Auth) AuditLogs(ctx context.Context, userID string, opts ListAuditLogsOptions) (*ListAuditLogsResult, error) {
	limit := opts.Limit
	if limit <= 0 || limit > maxAuditLogsListLimit {
		limit = defaultAuditLogsListLimit
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	filter := models.AuditLogFilter{
		EventType: opts.EventType,
		Since:     opts.Since,
		Until:     opts.Until,
	}

	events, hasMore, err := a.Repo.AuditLogListByUserID(ctx, userID, filter, limit, offset)
	if err != nil {
		return nil, err
	}
	return &ListAuditLogsResult{Events: events, HasMore: hasMore}, nil
}
