package security

import "regexp"

// Redaction placeholders returned to the model instead of raw values.
const (
	EmailPlaceholder = "[EMAIL_REDACTED]"
	PhonePlaceholder = "[PHONE_REDACTED]"
	CardPlaceholder  = "[CARD_REDACTED]"
	IDPlaceholder    = "[ID_REDACTED]"
)

var (
	// Emails, including the ones embedded in query plans such as
	// Filter: (email = 'juan@example.com'::text).
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

	// Payment card numbers: 13-19 digits, optionally grouped with spaces or
	// dashes. Evaluated before the phone rule so a 16-digit card is not
	// partially matched as a phone number.
	cardPattern = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)

	// Phone numbers must contain a separator between groups (or be
	// parenthesised), which avoids redacting EXPLAIN cost/row numbers.
	phonePattern = regexp.MustCompile(`(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.\-]\d{3,4}[\s.\-]\d{3,4}`)

	// National IDs, NITs and similar 8-12 digit identifiers.
	idPattern = regexp.MustCompile(`\b\d{8,12}\b`)
)

// MaskPII redacts emails, phone numbers, payment card numbers and national IDs
// from free-form text. It is applied to every query plan, slow-query log line
// and sampled row before the data leaves the process.
//
// The function is intentionally conservative: it may redact a harmless number
// that looks like an identifier, but it must never leak a real one.
func MaskPII(input string) string {
	if input == "" {
		return input
	}

	masked := emailPattern.ReplaceAllString(input, EmailPlaceholder)
	masked = cardPattern.ReplaceAllString(masked, CardPlaceholder)
	masked = phonePattern.ReplaceAllString(masked, PhonePlaceholder)
	masked = idPattern.ReplaceAllString(masked, IDPlaceholder)
	return masked
}
