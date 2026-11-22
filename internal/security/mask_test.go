package security

import "testing"

func TestMaskPII(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "email",
			input: "Filter: (email = 'carlos.perez@empresa.co'::text)",
			want:  "Filter: (email = '" + EmailPlaceholder + "'::text)",
		},
		{
			name:  "phone with country code",
			input: "tel = '+57 300 123 4567'",
			want:  "tel = '" + PhonePlaceholder + "'",
		},
		{
			name:  "phone with dashes",
			input: "tel = '300-123-4567'",
			want:  "tel = '" + PhonePlaceholder + "'",
		},
		{
			name:  "phone in parentheses",
			input: "tel = '(601) 555 0199'",
			want:  "tel = '" + PhonePlaceholder + "'",
		},
		{
			name:  "national id",
			input: "cedula = '1020304050'::text",
			want:  "cedula = '" + IDPlaceholder + "'::text",
		},
		{
			name:  "contiguous card",
			input: "card = '4111111111111111'",
			want:  "card = '" + CardPlaceholder + "'",
		},
		{
			name:  "grouped card",
			input: "card = '4111 1111 1111 1111' end",
			want:  "card = '" + CardPlaceholder + "' end",
		},
		{
			name:  "combined plan fragment",
			input: `Filter: ((email = 'carlos.perez@empresa.co'::text) AND (cedula = '1020304050'::text) AND (tel = '+57 300 123 4567'::text))`,
			want:  `Filter: ((email = '` + EmailPlaceholder + `'::text) AND (cedula = '` + IDPlaceholder + `'::text) AND (tel = '` + PhonePlaceholder + `'::text))`,
		},
		{
			name:  "json plan",
			input: `{"Plan": {"Filter": "((email = 'ana@example.com'::text) AND (cedula = '1020304050'::text))"}}`,
			want:  `{"Plan": {"Filter": "((email = '` + EmailPlaceholder + `'::text) AND (cedula = '` + IDPlaceholder + `'::text))"}}`,
		},
		{
			name:  "harmless plan is untouched",
			input: "Seq Scan on orders  (cost=0.00..1834.00 rows=100000 width=32) (actual time=0.015..12.345 rows=100000 loops=1)",
			want:  "Seq Scan on orders  (cost=0.00..1834.00 rows=100000 width=32) (actual time=0.015..12.345 rows=100000 loops=1)",
		},
		{
			name:  "dates are untouched",
			input: "created_at >= '2024-01-15 10:30:45'",
			want:  "created_at >= '2024-01-15 10:30:45'",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := MaskPII(tt.input); got != tt.want {
				t.Fatalf("MaskPII(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaskPIIMasksEveryOccurrence(t *testing.T) {
	t.Parallel()

	input := "a@b.co and c@d.co, ids 12345678 and 87654321"
	want := EmailPlaceholder + " and " + EmailPlaceholder + ", ids " + IDPlaceholder + " and " + IDPlaceholder
	if got := MaskPII(input); got != want {
		t.Fatalf("MaskPII() = %q, want %q", got, want)
	}
}
