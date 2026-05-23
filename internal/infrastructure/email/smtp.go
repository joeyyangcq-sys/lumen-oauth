package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	Timeout  time.Duration
}

func (s SMTPSender) SendVerificationCode(ctx context.Context, to, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	subject := "Lumen - Email Verification Code"
	body := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 10 minutes.", code)

	msg := strings.Join([]string{
		"From: " + s.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	conn, err := (&net.Dialer{Timeout: s.timeout()}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(s.timeout()))
	}

	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(s.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(msg)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (s SMTPSender) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 10 * time.Second
}

type ConsoleSender struct {
	Logger *slog.Logger
}

func (c ConsoleSender) SendVerificationCode(_ context.Context, to, code string) error {
	if c.Logger != nil {
		c.Logger.Info("verification code", "to", to, "code", code)
	} else {
		slog.Info("verification code", "to", to, "code", code)
	}
	return nil
}
