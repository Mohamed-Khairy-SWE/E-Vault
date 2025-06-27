package email

import (
	"fmt"
	"net/smtp"
	"strings"

	"E-Vault/internal/config"
	"E-Vault/internal/domain"
)

// EmailService defines an interface for sending transactional emails
type EmailService interface {
	SendVerificationEmail(user *domain.User, token string) error
	SendPasswordResetEmail(user *domain.User, token string) error
}

// SMTPEmailService is a concrete implementation of EmailService using SMTP
type SMTPEmailService struct {
	cfg config.Email
	// remoteURL is the base URL of the front-end application
	remoteURL string
}

// NewSMTPEmailService creates a new SMTPEmailService
func NewSMTPEmailService(cfg config.Email, remoteURL string) *SMTPEmailService {
	return &SMTPEmailService{
		cfg:       cfg,
		remoteURL: remoteURL,
	}
}

// send performs the actual email sending via SMTP
func (s *SMTPEmailService) send(to, subject, body string) error {
	// the auth mechanism for SMTP
	// We use PlainAuth, which is widely supported
	// the username is the from-address,, and the password is the API key/password
	auth := smtp.PlainAuth("", s.cfg.Address, s.cfg.APIKey, s.cfg.Host)

	// the message is formatted according to RFC 822
	// It must include headers for From, To, Subject, and the message body
	msg := []byte(strings.ReplaceAll(
		fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", s.cfg.Address, to, subject, body),
		"\n", "\r\n"),
	)

	// the address for the SMTP server (e.g., "smtp.sendgrid.net:587")
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	// Send the email
	return smtp.SendMail(addr, auth, s.cfg.Address, []string{to}, msg)
}

// SendVerificationEmail sends an email to the user with a link to verify their account
func (s *SMTPEmailService) SendVerificationEmail(user *domain.User, token string) error {
	subject := "E-Vault Email Verification"
	url := fmt.Sprintf("%s/verify-email/%s", s.remoteURL, token)
	body := "Please navigate to the following link to verify your email address: " + url

	return s.send(user.Email, subject, body)
}

// SendPasswordResetEmail sends an email to the user with a link to reset their password
func (s *SMTPEmailService) SendPasswordResetEmail(user *domain.User, token string) error {
	subject := "E-Vault Email Verification"
	url := fmt.Sprintf("%s/reset-password/%s", s.remoteURL, token)
	body := "Please navigate to the following link to reset your password: " + url

	return s.send(user.Email, subject, body)
}
