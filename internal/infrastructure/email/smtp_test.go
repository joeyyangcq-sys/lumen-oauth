package email

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSMTPSenderRespectsCanceledContextBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := (SMTPSender{
		Host:    "127.0.0.1",
		Port:    1,
		From:    "noreply@example.com",
		Timeout: time.Second,
	}).SendVerificationCode(ctx, "user@example.com", "123456")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
}

func TestSMTPSenderDefaultTimeout(t *testing.T) {
	if got := (SMTPSender{}).timeout(); got != 10*time.Second {
		t.Fatalf("timeout=%s, want 10s", got)
	}
	if got := (SMTPSender{Timeout: time.Second}).timeout(); got != time.Second {
		t.Fatalf("timeout=%s, want 1s", got)
	}
}
