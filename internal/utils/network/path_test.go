package network

import (
	"testing"
)

func TestNormalizeBasePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single slash",
			input:    "/",
			expected: "",
		},
		{
			name:     "foo",
			input:    "foo",
			expected: "/foo",
		},
		{
			name:     "slash foo",
			input:    "/foo",
			expected: "/foo",
		},
		{
			name:     "foo slash",
			input:    "foo/",
			expected: "/foo",
		},
		{
			name:     "slash foo slash",
			input:    "/foo/",
			expected: "/foo",
		},
		{
			name:     "whitespace",
			input:    "  foo  ",
			expected: "/foo",
		},
		{
			name:     "whitespace slash",
			input:    "  /foo/  ",
			expected: "/foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeBasePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeBasePath(%q) = %q; expected %q", tt.input, result, tt.expected)
			}
		})
	}
}
