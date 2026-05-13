package audit

import (
	"context"
	"time"

	"github.com/joey/lumen-oauth/internal/application/ports"
)

type Service struct {
	Sink ports.AuditSink
}

func (s Service) Record(ctx context.Context, action, actor, clientID, result, traceID string, details map[string]any) error {
	if s.Sink == nil {
		return nil
	}
	return s.Sink.Record(ctx, ports.AuditEvent{
		Action:    action,
		Actor:     actor,
		ClientID:  clientID,
		Result:    result,
		TraceID:   traceID,
		Timestamp: time.Now().UTC(),
		Details:   details,
	})
}
