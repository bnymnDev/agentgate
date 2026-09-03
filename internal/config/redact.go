package config

import "regexp"

// builtinRedactionPatterns are applied to every recorded call unless
// audit.builtin_redaction is false. They are intentionally broad: an audit log
// that leaks a token is worse than one that redacts a harmless string.
//
// A pattern is used in two ways (see internal/audit): it is matched against
// each "key: value" pair of an arguments or result object, and against every
// string value on its own. The first form catches {"api_key": "..."}, the
// second catches secrets embedded in free text such as a shell command.
var builtinRedactionPatterns = []string{
	`(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|pwd|authorization|auth[_-]?token|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*\S+`,
	`(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{12,}=*`,
	`\bAKIA[0-9A-Z]{16}\b`,
	`\bgh[pousr]_[A-Za-z0-9]{16,}\b`,
	`\bsk-[A-Za-z0-9]{16,}\b`,
	`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`,
	`-----BEGIN[A-Z ]*PRIVATE KEY-----`,
	`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`,
}

var builtinRedactors = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(builtinRedactionPatterns))
	for _, p := range builtinRedactionPatterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}()

// BuiltinRedactors returns the patterns agentgate redacts out of the box.
func BuiltinRedactors() []*regexp.Regexp {
	return builtinRedactors
}

// BuiltinRedactionPatterns returns the source of the built-in patterns, for
// documentation and for the web UI.
func BuiltinRedactionPatterns() []string {
	return append([]string(nil), builtinRedactionPatterns...)
}
