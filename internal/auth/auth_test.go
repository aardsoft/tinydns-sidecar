package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func generateKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	return pub, priv, pubB64
}

func signRequest(t *testing.T, priv ed25519.PrivateKey, ts int64, method, path string, body []byte) []byte {
	t.Helper()
	canonical := CanonicalString(ts, method, path, body)
	return ed25519.Sign(priv, []byte(canonical))
}

func buildHeader(keyID string, ts int64, sig []byte) string {
	return fmt.Sprintf(`TinyDNS-Sig keyId="%s",timestamp="%d",signature="%s"`,
		keyID, ts, base64.RawURLEncoding.EncodeToString(sig))
}

// --- ParseAuthHeader tests ---

func TestParseAuthHeader_Valid(t *testing.T) {
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)
	hdr := buildHeader("my-key", 1700000000, sig)
	p, err := ParseAuthHeader(hdr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.KeyID != "my-key" {
		t.Errorf("KeyID = %q, want %q", p.KeyID, "my-key")
	}
	if p.Timestamp != 1700000000 {
		t.Errorf("Timestamp = %d, want %d", p.Timestamp, 1700000000)
	}
}

func TestParseAuthHeader_WrongScheme(t *testing.T) {
	_, err := ParseAuthHeader(`Bearer token`)
	if err == nil {
		t.Fatal("expected error for wrong scheme")
	}
}

func TestParseAuthHeader_MissingKeyID(t *testing.T) {
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)
	hdr := fmt.Sprintf(`TinyDNS-Sig timestamp="1700000000",signature="%s"`,
		base64.RawURLEncoding.EncodeToString(sig))
	_, err := ParseAuthHeader(hdr)
	if err == nil {
		t.Fatal("expected error for missing keyId")
	}
}

func TestParseAuthHeader_ShortSignature(t *testing.T) {
	hdr := `TinyDNS-Sig keyId="k",timestamp="1",signature="dG9vc2hvcnQ"`
	_, err := ParseAuthHeader(hdr)
	if err == nil {
		t.Fatal("expected error for short signature")
	}
}

func TestParseAuthHeader_InvalidKeyIDChars(t *testing.T) {
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	cases := []struct {
		name  string
		keyID string
	}{
		{"slash", "my/key"},
		{"backslash", `my\key`},
		{"dotdot", "../etc/passwd"},
		{"space", "my key"},
		{"at", "my@key"},
		{"comma", "my,key"},
		{"quote", `my"key`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := fmt.Sprintf(`TinyDNS-Sig keyId="%s",timestamp="1700000000",signature="%s"`, tc.keyID, sigB64)
			_, err := ParseAuthHeader(hdr)
			if err == nil {
				t.Fatalf("expected error for keyId %q", tc.keyID)
			}
		})
	}
}

func TestParseAuthHeader_ValidKeyIDs(t *testing.T) {
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	cases := []string{
		"mykey",
		"my-key",
		"my_key",
		"my.key",
		"key123",
		"KEY",
		"a",
	}
	for _, keyID := range cases {
		t.Run(keyID, func(t *testing.T) {
			hdr := fmt.Sprintf(`TinyDNS-Sig keyId="%s",timestamp="1700000000",signature="%s"`, keyID, sigB64)
			p, err := ParseAuthHeader(hdr)
			if err != nil {
				t.Fatalf("unexpected error for keyId %q: %v", keyID, err)
			}
			if p.KeyID != keyID {
				t.Errorf("KeyID = %q, want %q", p.KeyID, keyID)
			}
		})
	}
}

// --- Verify tests ---

func TestVerify_ValidSignature(t *testing.T) {
	_, priv, pubB64 := generateKeyPair(t)
	ts := time.Now().Unix()
	body := []byte(`serial: 1`)
	sig := signRequest(t, priv, ts, "PUT", "/zones/example.com", body)

	ok, err := Verify(pubB64, ts, "PUT", "/zones/example.com", body, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected valid signature to verify")
	}
}

func TestVerify_WrongMethod(t *testing.T) {
	_, priv, pubB64 := generateKeyPair(t)
	ts := time.Now().Unix()
	body := []byte(`serial: 1`)
	sig := signRequest(t, priv, ts, "PUT", "/zones/example.com", body)

	ok, err := Verify(pubB64, ts, "PATCH", "/zones/example.com", body, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected invalid signature for wrong method")
	}
}

func TestVerify_WrongBody(t *testing.T) {
	_, priv, pubB64 := generateKeyPair(t)
	ts := time.Now().Unix()
	body := []byte(`serial: 1`)
	sig := signRequest(t, priv, ts, "PUT", "/zones/example.com", body)

	ok, err := Verify(pubB64, ts, "PUT", "/zones/example.com", []byte(`serial: 2`), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected invalid signature for tampered body")
	}
}

func TestVerify_ReplayDetection(t *testing.T) {
	// Replay detection is in the middleware; Verify itself doesn't check time.
	// This test confirms that the canonical string includes the timestamp,
	// so a replayed request with a different timestamp produces a bad sig.
	_, priv, pubB64 := generateKeyPair(t)
	ts := time.Now().Unix()
	body := []byte(`serial: 1`)
	sig := signRequest(t, priv, ts, "PUT", "/zones/example.com", body)

	// Verify with a different timestamp (simulating replay with modified ts).
	ok, err := Verify(pubB64, ts+1, "PUT", "/zones/example.com", body, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected invalid signature for modified timestamp")
	}
}

// --- ZoneAllowed tests ---

func TestZoneAllowed_Exact(t *testing.T) {
	allowed := []string{"example.com"}
	if !ZoneAllowed(allowed, "example.com") {
		t.Error("expected exact match to be allowed")
	}
	if ZoneAllowed(allowed, "sub.example.com") {
		t.Error("expected non-matching zone to be denied")
	}
}

func TestZoneAllowed_Wildcard(t *testing.T) {
	allowed := []string{"*.example.com"}
	if !ZoneAllowed(allowed, "sub.example.com") {
		t.Error("expected single-label subdomain to be allowed")
	}
	if !ZoneAllowed(allowed, "a.b.example.com") {
		t.Error("expected multi-label subdomain to be allowed")
	}
	if ZoneAllowed(allowed, "example.com") {
		t.Error("wildcard must not match base domain itself")
	}
	if ZoneAllowed(allowed, "other.com") {
		t.Error("expected unrelated domain to be denied")
	}
}

func TestZoneAllowed_Multiple(t *testing.T) {
	allowed := []string{"example.com", "*.example.net"}
	if !ZoneAllowed(allowed, "example.com") {
		t.Error("expected example.com to be allowed")
	}
	if !ZoneAllowed(allowed, "foo.example.net") {
		t.Error("expected foo.example.net to be allowed via wildcard")
	}
	if ZoneAllowed(allowed, "example.net") {
		t.Error("expected example.net to be denied (wildcard only)")
	}
}

func TestZoneAllowed_Empty(t *testing.T) {
	if ZoneAllowed([]string{}, "example.com") {
		t.Error("expected empty list to deny all")
	}
}

// --- FQDNInAllowedZones tests ---

func TestFQDNInAllowedZones_ExactZoneApex(t *testing.T) {
	if !FQDNInAllowedZones([]string{"example.com"}, "example.com") {
		t.Error("apex FQDN should be allowed by exact zone")
	}
	if !FQDNInAllowedZones([]string{"example.com"}, "example.com.") {
		t.Error("apex FQDN with trailing dot should be allowed")
	}
}

func TestFQDNInAllowedZones_ExactZoneSubdomain(t *testing.T) {
	if !FQDNInAllowedZones([]string{"example.com"}, "host.example.com") {
		t.Error("subdomain should be allowed by exact zone")
	}
	if !FQDNInAllowedZones([]string{"example.com"}, "deep.sub.example.com") {
		t.Error("deep subdomain should be allowed by exact zone")
	}
}

func TestFQDNInAllowedZones_ExactZoneRejectsOther(t *testing.T) {
	if FQDNInAllowedZones([]string{"example.com"}, "evil.com") {
		t.Error("unrelated domain should be denied")
	}
	if FQDNInAllowedZones([]string{"example.com"}, "fakeexample.com") {
		t.Error("domain that merely contains the zone name should be denied")
	}
	if FQDNInAllowedZones([]string{"example.com"}, "com") {
		t.Error("parent TLD should be denied")
	}
}

func TestFQDNInAllowedZones_WildcardSubdomain(t *testing.T) {
	allowed := []string{"*.example.com"}
	if !FQDNInAllowedZones(allowed, "host.example.com") {
		t.Error("single-label subdomain should be allowed by wildcard")
	}
	if !FQDNInAllowedZones(allowed, "deep.sub.example.com") {
		t.Error("multi-label subdomain should be allowed by wildcard")
	}
}

func TestFQDNInAllowedZones_WildcardDoesNotGrantApex(t *testing.T) {
	if FQDNInAllowedZones([]string{"*.example.com"}, "example.com") {
		t.Error("wildcard must not grant access to the apex zone FQDN")
	}
}

func TestFQDNInAllowedZones_CaseNormalised(t *testing.T) {
	if !FQDNInAllowedZones([]string{"example.com"}, "HOST.EXAMPLE.COM") {
		t.Error("FQDN comparison should be case-insensitive")
	}
}

func TestFQDNInAllowedZones_EmptyList(t *testing.T) {
	if FQDNInAllowedZones([]string{}, "example.com") {
		t.Error("empty allowed list should deny all")
	}
}
