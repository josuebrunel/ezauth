package service

import (
	"fmt"
	"net/smtp"
	"strings"
)

type Mailer interface {
	Send(to []string, subject, body string) error
}

type SMTPMailer struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func NewSMTPMailer(host string, port int, username, password, from string) *SMTPMailer {
	return &SMTPMailer{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		From:     from,
	}
}

func (m *SMTPMailer) Send(to []string, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.Host, m.Port)
	auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)

	header := make(map[string]string)
	header["From"] = m.From
	header["To"] = strings.Join(to, ",")
	header["Subject"] = subject
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/plain; charset=\"utf-8\""

	message := ""
	for k, v := range header {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	return smtp.SendMail(addr, auth, m.From, to, []byte(message))
}

type MockMailer struct {
	SentEmails []SentEmail
}

type SentEmail struct {
	To      []string
	Subject string
	Body    string
}

func (m *MockMailer) Send(to []string, subject, body string) error {
	m.SentEmails = append(m.SentEmails, SentEmail{
		To:      to,
		Subject: subject,
		Body:    body,
	})
	return nil
}
