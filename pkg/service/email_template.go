package service

import (
	"bytes"
	"text/template"
)

// EmailTemplateData contains variables available in email templates.
type EmailTemplateData struct {
	Link  string // Full URL for the action (e.g., magic link URL)
	Token string // Raw token value
	Email string // User's email address
}

// RenderTemplate renders a template string with the given data.
// Returns the original template string if parsing or execution fails.
func RenderTemplate(tmpl string, data EmailTemplateData) string {
	t, err := template.New("email").Parse(tmpl)
	if err != nil {
		return tmpl
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return tmpl
	}

	return buf.String()
}
