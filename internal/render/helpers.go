package render

import (
	"fmt"
	"strings"
)

func dotEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func dotID(name string) string {
	var b strings.Builder
	b.WriteString("n_")
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			fmt.Fprintf(&b, "_%04x", c)
		}
	}
	return b.String()
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func truncLabel(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// stripOwner removes the owner prefix from "Owner$$Method" for IL2CPP names.
func stripOwner(funcName, owner string) string {
	prefix := owner + "$$"
	if strings.HasPrefix(funcName, prefix) {
		return funcName[len(prefix):]
	}
	return funcName
}
