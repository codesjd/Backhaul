package transport

import "testing"

// TestAuthorizedToken pins the accept/reject behaviour of the tunnel's only
// authentication check, so a later "simplification" back to == (or an inverted
// sense) fails here rather than in production.
func TestAuthorizedToken(t *testing.T) {
	const expected = "Bearer s3cret"

	for _, tc := range []struct {
		header string
		want   bool
	}{
		{expected, true},
		{"Bearer s3cre", false},   // prefix
		{"Bearer s3crett", false}, // extension
		{"Bearer S3CRET", false},  // case
		{"bearer s3cret", false},  // scheme case
		{"s3cret", false},         // no scheme
		{"", false},               // absent header
	} {
		if got := authorizedToken(tc.header, expected); got != tc.want {
			t.Errorf("authorizedToken(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}
