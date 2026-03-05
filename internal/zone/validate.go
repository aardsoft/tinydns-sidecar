package zone

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ValidationError carries the field path and message for a single problem.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a slice of ValidationError that implements error.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

var hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_.\-]*[a-zA-Z0-9])?\.?$`)

// ValidateZoneContainment checks that every record hostname in z is within
// zoneName (the zone being uploaded to).  It is called after Validate so it
// can assume hostnames are syntactically valid.
//
// This prevents a key authorised for example.com from embedding records for
// evil.com inside an example.com upload.
func ValidateZoneContainment(z ZoneFile, zoneName string) ValidationErrors {
	var errs ValidationErrors
	zoneName = strings.ToLower(zoneName)
	for host := range z.Records {
		norm := strings.ToLower(strings.TrimSuffix(host, "."))
		if norm != zoneName && !strings.HasSuffix(norm, "."+zoneName) {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("records[%s]", host),
				Message: fmt.Sprintf("hostname not within zone %s", zoneName),
			})
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// rawDataTypeChars is the set of characters that may begin a tinydns record line.
//
// Standard tinydns format: https://cr.yp.to/djbdns/tinydns-data.html
// IPv6 extensions (3, 6):  http://www.fefe.de/dns/
//
// Patch extensions supported by the custom tinydns build:
//
//	S  SRV   Sfqdn:ip:x:port:weight:priority:ttl:timestamp
//	N  NAPTR Nfqdn:order:pref:flags:service:regexp:replacement:ttl:timestamp
//
// FQDN extraction works identically for all types: characters between
// position 1 and the first ':'.
const rawDataTypeChars = ".&=+@'^CZ:36SN"

// ExtractRawDataFQDNs parses a tinydns data file and returns every FQDN found.
// Only lines whose first character is a known tinydns record-type character are
// processed; blank lines, comments (#), location lines (%), and any other lines
// (e.g. YAML keys) are skipped.
// The FQDN is the text between position 1 and the first ':' on each record line.
func ExtractRawDataFQDNs(data []byte) []string {
	var fqdns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) == 0 || line[0] == '#' || line[0] == '%' {
			continue
		}
		if !strings.ContainsRune(rawDataTypeChars, rune(line[0])) {
			continue // not a tinydns record line
		}
		rest := line[1:]
		if idx := strings.IndexByte(rest, ':'); idx >= 0 {
			fqdns = append(fqdns, rest[:idx])
		}
	}
	return fqdns
}

// HasRawDataLines reports whether data contains at least one tinydns record line.
// Used by the handler to reject content that is clearly not tinydns data
// (e.g. a YAML zone file accidentally sent to POST /data).
func HasRawDataLines(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) > 0 && strings.ContainsRune(rawDataTypeChars, rune(line[0])) {
			return true
		}
	}
	return false
}

// SanitizeRawData filters a raw tinydns data body so that only known-safe lines
// are stored verbatim.  Lines with an unrecognised leading character — which
// would bypass FQDN validation — are neutralised by rewriting them as comments
// prefixed with "# invalid: ".  Blank lines, comments (#), and location lines
// (%) are passed through unchanged.
//
// Returns the sanitised body and one warning string per affected line.  The
// caller should forward warnings to the client so the operator knows something
// was silently rewritten rather than stored as-is.
func SanitizeRawData(data []byte) (sanitized []byte, warnings []string) {
	var sb strings.Builder
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if i > 0 {
			sb.WriteByte('\n')
		}
		if len(line) == 0 || line[0] == '#' || line[0] == '%' {
			sb.WriteString(line)
			continue
		}
		if strings.ContainsRune(rawDataTypeChars, rune(line[0])) {
			sb.WriteString(line)
			continue
		}
		// Unrecognised type character — neutralise as a comment.
		sb.WriteString("# invalid: ")
		sb.WriteString(line)
		warnings = append(warnings, fmt.Sprintf("line %d: unrecognised record type %q commented out", i+1, string(line[0])))
	}
	return []byte(sb.String()), warnings
}

// Validate checks a ZoneFile for semantic correctness. It collects all errors
// rather than failing at the first one.
func Validate(z ZoneFile) ValidationErrors {
	var errs ValidationErrors

	add := func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Message: msg})
	}

	// Zone-level int fields must be non-negative
	for name, val := range map[string]int{
		"serial":  z.Serial,
		"refresh": z.Refresh,
		"retry":   z.Retry,
		"expire":  z.Expire,
		"minimum": z.Minimum,
		"ttl":     z.TTL,
	} {
		if val < 0 {
			add(name, "must be >= 0")
		}
	}

	// Servers
	for fqdn, entry := range z.Servers {
		f := fmt.Sprintf("servers[%s]", fqdn)
		if fqdn == "" {
			add(f, "FQDN must not be empty")
		} else if strings.ContainsAny(fqdn, " \t") {
			add(f, "FQDN must not contain whitespace")
		} else if !hostnameRE.MatchString(fqdn) {
			add(f, "invalid FQDN syntax")
		}
		if entry != nil {
			if entry.IP != "" {
				if ip := net.ParseIP(entry.IP); ip == nil || ip.To4() == nil {
					add(f+".ip", "must be a valid IPv4 address")
				}
			}
			for i, ip := range entry.IPs {
				if net.ParseIP(ip) == nil {
					add(fmt.Sprintf("%s.ips[%d]", f, i), "must be a valid IP address")
				}
			}
		}
	}

	// Records
	for host, rs := range z.Records {
		f := fmt.Sprintf("records[%s]", host)
		if !hostnameRE.MatchString(host) {
			add(f, "invalid hostname syntax")
		}
		validateRecordSet(f, rs, &errs)
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}

func validateRecordSet(prefix string, rs RecordSet, errs *ValidationErrors) {
	add := func(field, msg string) {
		*errs = append(*errs, ValidationError{Field: field, Message: msg})
	}

	if a := rs.A; a != nil {
		f := prefix + ".a"
		if a.IPv4 == "" && len(a.IPv4s) == 0 {
			add(f, "at least one of ipv4/ipv4s must be set")
		}
		if a.IPv4 != "" {
			if ip := net.ParseIP(a.IPv4); ip == nil || ip.To4() == nil {
				add(f+".ipv4", "must be a valid IPv4 address")
			}
		}
		for i, ip := range a.IPv4s {
			if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
				add(fmt.Sprintf("%s.ipv4s[%d]", f, i), "must be a valid IPv4 address")
			}
		}
	}

	if aaaa := rs.AAAA; aaaa != nil {
		f := prefix + ".aaaa"
		if aaaa.IPv6 == "" {
			add(f+".ipv6", "must be set")
		} else if ip := net.ParseIP(aaaa.IPv6); ip == nil || ip.To4() != nil {
			add(f+".ipv6", "must be a valid IPv6 address")
		}
	}

	if aptr := rs.APTR; aptr != nil {
		f := prefix + ".aptr"
		if aptr.IPv4 == "" && len(aptr.IPv4s) == 0 {
			add(f, "at least one of ipv4/ipv4s must be set")
		}
		if aptr.IPv4 != "" {
			if ip := net.ParseIP(aptr.IPv4); ip == nil || ip.To4() == nil {
				add(f+".ipv4", "must be a valid IPv4 address")
			}
		}
		for i, ip := range aptr.IPv4s {
			if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
				add(fmt.Sprintf("%s.ipv4s[%d]", f, i), "must be a valid IPv4 address")
			}
		}
	}

	if aaaap := rs.AAAAPtr; aaaap != nil {
		f := prefix + ".aaaaptr"
		if aaaap.IPv6 == "" {
			add(f+".ipv6", "must be set")
		} else if ip := net.ParseIP(aaaap.IPv6); ip == nil || ip.To4() != nil {
			add(f+".ipv6", "must be a valid IPv6 address")
		}
	}

	if cname := rs.CNAME; cname != nil {
		if cname.PTR == "" {
			add(prefix+".cname.ptr", "must not be empty")
		}
	}

	if mx := rs.MX; mx != nil {
		if mx.Priority < 0 || mx.Priority > 65535 {
			add(prefix+".mx.priority", "must be 0–65535")
		}
	}

	for svcKey, srv := range rs.SRV {
		f := fmt.Sprintf("%s.srv[%s]", prefix, svcKey)
		if srv.Port < 1 || srv.Port > 65535 {
			add(f+".port", "must be 1–65535")
		}
	}

	if txt := rs.TXT; txt != nil {
		f := prefix + ".txt"
		if len(txt.Data) == 0 {
			add(f+".data", "must not be empty")
		}
		for i, s := range txt.Data {
			if s == "" {
				add(fmt.Sprintf("%s.data[%d]", f, i), "element must not be empty")
			}
		}
	}

	if spf := rs.SPF; spf != nil {
		f := prefix + ".spf"
		if len(spf.Data) == 0 {
			add(f+".data", "must not be empty")
		}
		for i, s := range spf.Data {
			if s == "" {
				add(fmt.Sprintf("%s.data[%d]", f, i), "element must not be empty")
			}
		}
	}
}
