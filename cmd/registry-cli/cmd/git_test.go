package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInjectToken(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		token    string
		expected string
	}{
		{
			name:     "HTTPS URL with token",
			url:      "https://github.com/org/private-repo.git",
			token:    "ghp_abc123",
			expected: "https://x-access-token:ghp_abc123@github.com/org/private-repo.git",
		},
		{
			name:     "HTTPS URL without token",
			url:      "https://github.com/org/public-repo.git",
			token:    "",
			expected: "https://github.com/org/public-repo.git",
		},
		{
			name:     "SSH URL ignored",
			url:      "git@github.com:org/repo.git",
			token:    "ghp_abc123",
			expected: "git@github.com:org/repo.git",
		},
		{
			name:     "non-HTTPS scheme ignored",
			url:      "http://example.com/repo.git",
			token:    "token",
			expected: "http://example.com/repo.git",
		},
		{
			name:     "HTTPS URL with existing userinfo",
			url:      "https://user:pass@github.com/org/repo.git",
			token:    "ghp_new",
			expected: "https://x-access-token:ghp_new@github.com/org/repo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := injectToken(tt.url, tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}
