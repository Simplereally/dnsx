package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBaseDomain(t *testing.T) {
	detector := &AutoWildcardDetector{
		cache:     make(map[string][]string),
		threshold: 5,
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"www.google.com", "google.com"},
		{"api.subdomain.google.com", "google.com"},
		{"example.co.uk", "example.co.uk"},
		{"test.example.co.uk", "example.co.uk"},
		{"localhost", "localhost"},
		{"simple.com", "simple.com"},
		{"www.google.com.", "google.com"},  // FQDN with trailing dot
		{"api.github.com.", "github.com"},  // Another FQDN case
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := detector.GetBaseDomain(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestIsWildcardWithNoWildcards(t *testing.T) {
	detector := &AutoWildcardDetector{
		cache:     make(map[string][]string),
		threshold: 5,
	}

	// Empty cache means no wildcards detected
	detector.cache["example.com"] = []string{}

	result := detector.IsWildcard("test.example.com", []string{"1.2.3.4"})
	assert.False(t, result, "Should return false when no wildcard IPs are cached")
}

func TestIsWildcardWithMatchingIP(t *testing.T) {
	detector := &AutoWildcardDetector{
		cache:     make(map[string][]string),
		threshold: 5,
	}

	// Simulate detected wildcard IPs
	detector.cache["example.com"] = []string{"10.0.0.1", "10.0.0.2"}

	// Should detect as wildcard when IP matches
	result := detector.IsWildcard("test.example.com", []string{"10.0.0.1"})
	assert.True(t, result, "Should return true when IP matches wildcard")

	// Should not detect as wildcard when IP doesn't match
	result = detector.IsWildcard("test.example.com", []string{"192.168.1.1"})
	assert.False(t, result, "Should return false when IP doesn't match wildcard")
}
