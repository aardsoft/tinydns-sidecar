package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ParsedHeader holds the fields extracted from an Authorization header.
type ParsedHeader struct {
	KeyID     string
	Timestamp int64
	Signature []byte
}

// ParseAuthHeader parses:
//
//	Authorization: TinyDNS-Sig keyId="<id>",timestamp="<unix>",signature="<base64url>"
func ParseAuthHeader(header string) (ParsedHeader, error) {
	const scheme = "TinyDNS-Sig "
	if !strings.HasPrefix(header, scheme) {
		return ParsedHeader{}, fmt.Errorf("expected scheme TinyDNS-Sig")
	}
	rest := header[len(scheme):]

	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return ParsedHeader{}, fmt.Errorf("malformed field %q", part)
		}
		key := strings.TrimSpace(part[:eq])
		val := strings.TrimSpace(part[eq+1:])
		// strip surrounding quotes
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		fields[key] = val
	}

	keyID, ok := fields["keyId"]
	if !ok || keyID == "" {
		return ParsedHeader{}, fmt.Errorf("missing keyId")
	}
	tsStr, ok := fields["timestamp"]
	if !ok {
		return ParsedHeader{}, fmt.Errorf("missing timestamp")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return ParsedHeader{}, fmt.Errorf("invalid timestamp: %w", err)
	}
	sigStr, ok := fields["signature"]
	if !ok || sigStr == "" {
		return ParsedHeader{}, fmt.Errorf("missing signature")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return ParsedHeader{}, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return ParsedHeader{}, fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}

	return ParsedHeader{KeyID: keyID, Timestamp: ts, Signature: sig}, nil
}

// CanonicalString builds the string that must be signed:
//
//	"<timestamp>\n<METHOD>\n<path>\n<hex-sha256-of-body>"
func CanonicalString(timestamp int64, method, path string, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%d\n%s\n%s\n%s",
		timestamp, method, path, hex.EncodeToString(sum[:]))
}

// Verify returns true if sig is a valid Ed25519 signature over the canonical
// string for the given parameters, using pubKeyB64 (base64url, raw, 32 bytes).
func Verify(pubKeyB64 string, timestamp int64, method, path string, body, sig []byte) (bool, error) {
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		// also try standard base64 for convenience
		pubKeyBytes, err = base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return false, fmt.Errorf("decoding public key: %w", err)
		}
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	canonical := CanonicalString(timestamp, method, path, body)
	return ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(canonical), sig), nil
}
