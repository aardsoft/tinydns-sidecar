package auth

import "strings"

// FQDNInAllowedZones reports whether fqdn falls within any zone the key is
// authorised to manage.
//
// A FQDN belongs to a zone if it equals the zone name or is a subdomain.
// Wildcard zone patterns follow the same semantics as ZoneAllowed:
//   - "example.com"  → allows example.com and *.example.com FQDNs
//   - "*.example.com" → allows FQDNs ending with .example.com (not example.com itself)
func FQDNInAllowedZones(allowedZones []string, fqdn string) bool {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	for _, pattern := range allowedZones {
		if fqdnMatchesPattern(pattern, fqdn) {
			return true
		}
	}
	return false
}

// fqdnMatchesPattern checks whether fqdn (already normalised) is within the
// zone described by pattern.
func fqdnMatchesPattern(pattern, fqdn string) bool {
	if strings.HasPrefix(pattern, "*.") {
		// Wildcard: authorises any subdomain of the suffix zone.
		// A FQDN belongs here if it ends with ".suffix" (same rule as matchZone
		// but applied to individual hostnames rather than zone names).
		suffix := pattern[2:] // "example.com"
		return strings.HasSuffix(fqdn, "."+suffix)
	}
	// Exact zone: FQDN must equal the zone or be a subdomain.
	return fqdn == pattern || strings.HasSuffix(fqdn, "."+pattern)
}

// ZoneAllowed reports whether zoneName is permitted by the allowedZones list.
//
// Rules:
//   - Exact match: "example.com" matches "example.com"
//   - Wildcard prefix: "*.example.com" matches "sub.example.com" and
//     "deep.sub.example.com" but NOT "example.com" itself.
//     The wildcard requires at least one label before the suffix.
func ZoneAllowed(allowedZones []string, zoneName string) bool {
	for _, pattern := range allowedZones {
		if matchZone(pattern, zoneName) {
			return true
		}
	}
	return false
}

func matchZone(pattern, zone string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		// exact match
		return pattern == zone
	}
	// wildcard: "*.example.com" matches any subdomain of example.com
	// (≥1 label prefix), but NOT example.com itself.
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(zone, suffix) {
		return false
	}
	// ensure there is at least one label before the suffix
	prefix := zone[:len(zone)-len(suffix)]
	return len(prefix) > 0
}
