package email

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func (s SMTPSender) SendVerificationCode(_ context.Context, to, code string) error {
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
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	return smtp.SendMail(addr, auth, s.From, []string{to}, []byte(msg))
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
