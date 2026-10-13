package models

import (
	"strings"
	"unicode/utf8"
)

// Palette is dark enough for white initials. The color is chosen from the
// name so the same organization keeps the same mark.
var orgMarkPalette = []string{
	"#0f6b4c", "#1d4ed8", "#b45309", "#9f1239", "#6d28d9",
	"#0f766e", "#9a3412", "#1e40af", "#3f6212", "#7e22ce",
}

// Initial is the first letter of the organization name.
func (o Organization) Initial() string {
	name := strings.TrimSpace(o.Name)
	if name == "" {
		name = strings.TrimSpace(o.Slug)
	}
	if name == "" {
		return "?"
	}
	r, _ := utf8.DecodeRuneInString(name)
	return strings.ToUpper(string(r))
}

// MarkColor is the fallback avatar color when LogoURL is empty.
func (o Organization) MarkColor() string {
	sum := 0
	for _, r := range o.Name + "\n" + o.Slug {
		sum += int(r)
	}
	if sum < 0 {
		sum = -sum
	}
	return orgMarkPalette[sum%len(orgMarkPalette)]
}
