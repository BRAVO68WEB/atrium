package mailer

import (
	"sort"
	"time"
)

// TemplateNames is the stable list of email themes.
func TemplateNames() []string {
	names := make([]string, 0, len(builtinMail))
	for name := range builtinMail {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// UsesFile reports whether name.txt in the templates directory replaced the built-in text.
func (set *Templates) UsesFile(name string) bool {
	return set != nil && set.parsed[name] != nil
}

// HasHTML reports whether name.html exists beside the text template.
func (set *Templates) HasHTML(name string) bool {
	return set != nil && set.html[name] != nil
}

// SampleData fills every field a mail template can read.
func SampleData(issuer string) Data {
	if issuer == "" {
		issuer = "https://issuer.example"
	}
	return Data{
		Issuer:   issuer,
		Username: "ada",
		Email:    "ada@example.com",
		Link:     issuer + "/reset?token=preview",
		Code:     "482913",
		TTL:      "15 minutes",
		IP:       "203.0.113.10",
		Time:     time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Agent:    "Firefox",
		Count:    "4",
	}
}
