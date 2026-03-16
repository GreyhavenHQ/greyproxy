package greyproxy

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// MatchesContainer checks if containerName matches the given glob pattern.
func MatchesContainer(containerName, pattern string) bool {
	if pattern == "*" {
		return true
	}
	matched, err := filepath.Match(pattern, containerName)
	if err != nil {
		return false
	}
	return matched
}

// MatchesDestination checks if destination matches the given pattern.
// Supports: exact match, CIDR, *.domain (subdomains only), **.domain (domain + subdomains).
func MatchesDestination(destination, pattern string) bool {
	if pattern == "*" {
		return true
	}

	destination = strings.ToLower(destination)
	pattern = strings.ToLower(pattern)

	// CIDR match
	if strings.Contains(pattern, "/") {
		_, cidr, err := net.ParseCIDR(pattern)
		if err == nil {
			ip := net.ParseIP(destination)
			if ip != nil {
				return cidr.Contains(ip)
			}
		}
		return false
	}

	// Double wildcard: **.domain.com matches domain.com AND *.domain.com
	if strings.HasPrefix(pattern, "**.") {
		baseDomain := pattern[3:]
		if destination == baseDomain {
			return true
		}
		return strings.HasSuffix(destination, "."+baseDomain)
	}

	// Single wildcard: *.domain.com matches only subdomains, NOT root
	if strings.HasPrefix(pattern, "*.") {
		baseDomain := pattern[2:] // "example.com"
		return strings.HasSuffix(destination, "."+baseDomain)
	}

	// Exact match
	return destination == pattern
}

// MatchesPort checks if port matches the given pattern.
// Supports: exact, comma-separated list, range (e.g., "8000-9000"), wildcard "*".
func MatchesPort(port int, pattern string) bool {
	if pattern == "*" {
		return true
	}

	// Comma-separated list
	if strings.Contains(pattern, ",") {
		for _, part := range strings.Split(pattern, ",") {
			part = strings.TrimSpace(part)
			if matchSinglePort(port, part) {
				return true
			}
		}
		return false
	}

	return matchSinglePort(port, pattern)
}

func matchSinglePort(port int, pattern string) bool {
	// Range
	if strings.Contains(pattern, "-") {
		parts := strings.SplitN(pattern, "-", 2)
		if len(parts) == 2 {
			low, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			high, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil {
				return port >= low && port <= high
			}
		}
		return false
	}

	// Exact
	p, err := strconv.Atoi(strings.TrimSpace(pattern))
	if err != nil {
		return false
	}
	return port == p
}

// MatchesRule checks if all three dimensions match.
func MatchesRule(containerName, destHost string, destPort int, containerPattern, destPattern, portPattern string) bool {
	return MatchesContainer(containerName, containerPattern) &&
		MatchesDestination(destHost, destPattern) &&
		MatchesPort(destPort, portPattern)
}

// CalculateSpecificity returns a score indicating how specific a rule is.
// Higher = more specific. Used to pick the best matching rule.
func CalculateSpecificity(containerPattern, destinationPattern, portPattern string) int {
	score := 0

	// Container specificity
	if containerPattern != "*" {
		score += 100
		if !strings.ContainsAny(containerPattern, "*?[") {
			score += 100 // No wildcards = exact match
		}
	}

	// Destination specificity
	if destinationPattern != "*" {
		score += 10
		if !strings.ContainsAny(destinationPattern, "*?[") {
			score += 10 // No wildcards = exact match
		}
	}

	// Port specificity
	if portPattern != "*" {
		score += 1
	}

	return score
}
