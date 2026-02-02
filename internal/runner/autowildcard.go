package runner

import (
	"strings"
	"sync"

	"github.com/rs/xid"
	"golang.org/x/net/publicsuffix"
)

// AutoWildcardDetector handles automatic wildcard detection across multiple domains
type AutoWildcardDetector struct {
	runner    *Runner
	cache     map[string][]string // domain -> wildcard IPs
	cacheLock sync.RWMutex
	threshold int
}

// NewAutoWildcardDetector creates a new auto wildcard detector
func NewAutoWildcardDetector(runner *Runner, threshold int) *AutoWildcardDetector {
	if threshold <= 0 {
		threshold = 5 // default threshold
	}
	return &AutoWildcardDetector{
		runner:    runner,
		cache:     make(map[string][]string),
		threshold: threshold,
	}
}

// GetBaseDomain extracts the base domain (eTLD+1) from a hostname
func (a *AutoWildcardDetector) GetBaseDomain(host string) string {
	// Remove any leading dots
	host = strings.TrimPrefix(host, ".")
	
	// Try to get the eTLD+1 (effective top-level domain plus one)
	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: try to extract last two parts
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	}
	return baseDomain
}

// DetectWildcard checks if a domain has a wildcard and caches the wildcard IPs
func (a *AutoWildcardDetector) DetectWildcard(baseDomain string) []string {
	a.cacheLock.RLock()
	if ips, ok := a.cache[baseDomain]; ok {
		a.cacheLock.RUnlock()
		return ips
	}
	a.cacheLock.RUnlock()

	// Generate random subdomains and query them
	wildcardIPs := make(map[string]int)
	
	for i := 0; i < a.threshold; i++ {
		randomSub := xid.New().String() + "." + baseDomain
		result, err := a.runner.dnsx.QueryOne(randomSub)
		if err != nil || result == nil {
			continue
		}
		
		// Count occurrences of each IP
		for _, ip := range result.A {
			wildcardIPs[ip]++
		}
	}
	
	// IPs that appear in most queries are wildcard IPs
	var wildcards []string
	minOccurrences := (a.threshold / 2) + 1 // majority threshold
	for ip, count := range wildcardIPs {
		if count >= minOccurrences {
			wildcards = append(wildcards, ip)
		}
	}
	
	// Cache the result
	a.cacheLock.Lock()
	a.cache[baseDomain] = wildcards
	a.cacheLock.Unlock()
	
	return wildcards
}

// IsWildcard checks if the given host's IPs match known wildcard IPs for its base domain
func (a *AutoWildcardDetector) IsWildcard(host string, ips []string) bool {
	baseDomain := a.GetBaseDomain(host)
	
	// Get or detect wildcard IPs for this base domain
	wildcardIPs := a.DetectWildcard(baseDomain)
	if len(wildcardIPs) == 0 {
		return false
	}
	
	// Create a set of wildcard IPs for fast lookup
	wildcardSet := make(map[string]struct{})
	for _, wip := range wildcardIPs {
		wildcardSet[wip] = struct{}{}
	}
	
	// Check if any of the host's IPs match wildcard IPs
	for _, ip := range ips {
		if _, ok := wildcardSet[ip]; ok {
			return true
		}
	}
	
	return false
}

// GetWildcardDomains returns all detected wildcard domains and their IPs
func (a *AutoWildcardDetector) GetWildcardDomains() map[string][]string {
	a.cacheLock.RLock()
	defer a.cacheLock.RUnlock()
	
	result := make(map[string][]string)
	for k, v := range a.cache {
		if len(v) > 0 {
			result[k] = v
		}
	}
	return result
}
