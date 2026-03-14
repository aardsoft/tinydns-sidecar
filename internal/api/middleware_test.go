package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aardsoft/tinydns-sidecar/internal/auth"
	"github.com/aardsoft/tinydns-sidecar/internal/config"
	"github.com/aardsoft/tinydns-sidecar/internal/zone"
)

// --- helpers ---

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pub, priv, base64.RawURLEncoding.EncodeToString(pub)
}

func signHeader(t *testing.T, priv ed25519.PrivateKey, keyID, method, path string, body []byte) string {
	t.Helper()
	return auth.Sign(priv, keyID, time.Now().Unix(), method, path, body)
}

// noopStore is a minimal Store that returns "not found" for everything.
type noopStore struct{}

func (noopStore) ReadZone(_ string) (*zone.ZoneFile, error)        { return nil, nil }
func (noopStore) WriteZone(_ string, _ zone.ZoneFile) error        { return nil }
func (noopStore) DeleteZone(_ string) error                         { return nil }
func (noopStore) WriteRawData(_ string, _ []byte) error             { return nil }
func (noopStore) ReadRawData(_ string) ([]byte, error)             { return nil, nil }
func (noopStore) DeleteRawData(_ string) error                      { return nil }

// testServer returns a Server configured with two keys:
//
//	"allowed-key"  – AllowReplace + AllowMerge + allowed_zones: ["example.com"]
//	"no-replace"   – AllowMerge only          + allowed_zones: ["example.com"]
func testServer(t *testing.T, allowedPriv, noReplacePriv ed25519.PrivateKey, allowedPub, noReplacePub string) *Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:           ":0",
			ClockSkewSeconds: 300,
		},
		Keys: map[string]config.KeyConfig{
			"allowed-key": {
				PublicKey:    allowedPub,
				AllowedZones: []string{"example.com"},
				AllowReplace: true,
				AllowMerge:   true,
			},
			"no-replace": {
				PublicKey:    noReplacePub,
				AllowedZones: []string{"example.com"},
				AllowReplace: false,
				AllowMerge:   true,
			},
		},
	}
	return NewServer(cfg, noopStore{})
}

// --- zoneAuthMiddleware ordering tests ---

// TestZoneAuth_UnauthorizedZoneFastFail verifies that a key requesting a zone
// it is not authorized for receives 403 immediately, even when the signature is
// invalid.  This confirms the "fail fast" design: cheap authorization checks
// run before expensive Ed25519 signature verification.
func TestZoneAuth_UnauthorizedZoneFastFail(t *testing.T) {
	_, allowedPriv, allowedPub := generateTestKey(t)
	_, noReplacePriv, noReplacePub := generateTestKey(t)
	s := testServer(t, allowedPriv, noReplacePriv, allowedPub, noReplacePub)

	body := []byte("")
	// Bad signature — but zone authorization should fail first.
	badSig := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(badSig)
	badSigB64 := base64.RawURLEncoding.EncodeToString(badSig)
	// "allowed-key" is only authorized for "example.com", not "other.com".
	hdr := fmt.Sprintf(`TinyDNS-Sig keyId="allowed-key",timestamp="%d",signature="%s"`,
		time.Now().Unix(), badSigB64)

	req := httptest.NewRequest(http.MethodPut, "/zones/other.com", bytes.NewReader(body))
	req.Header.Set("Authorization", hdr)
	req.Header.Set("Content-Type", "application/yaml")
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	// Must be 403 (zone not authorized), not 401 (signature invalid).
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (zone authz check runs before sig verification)", rr.Code)
	}
}

// TestZoneAuth_UnauthorizedMethodFastFail verifies that a key lacking the
// required method permission receives 403 even when the signature is invalid.
func TestZoneAuth_UnauthorizedMethodFastFail(t *testing.T) {
	_, allowedPriv, allowedPub := generateTestKey(t)
	_, noReplacePriv, noReplacePub := generateTestKey(t)
	s := testServer(t, allowedPriv, noReplacePriv, allowedPub, noReplacePub)

	body := []byte("")
	// Bad signature — but method authorization should fail first.
	badSig := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(badSig)
	badSigB64 := base64.RawURLEncoding.EncodeToString(badSig)
	// "no-replace" key lacks AllowReplace, so PUT to an authorized zone must 403.
	hdr := fmt.Sprintf(`TinyDNS-Sig keyId="no-replace",timestamp="%d",signature="%s"`,
		time.Now().Unix(), badSigB64)

	req := httptest.NewRequest(http.MethodPut, "/zones/example.com", bytes.NewReader(body))
	req.Header.Set("Authorization", hdr)
	req.Header.Set("Content-Type", "application/yaml")
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	// Must be 403 (method not authorized), not 401 (signature invalid).
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (method authz check runs before sig verification)", rr.Code)
	}
}

// TestZoneAuth_NormalizedPathSig verifies that a signature produced with the
// lowercase-normalized path (/zones/example.com) is accepted even if the
// request URL uses upper-case characters (/zones/EXAMPLE.COM).
func TestZoneAuth_NormalizedPathSig(t *testing.T) {
	_, priv, pub := generateTestKey(t)
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:           ":0",
			ClockSkewSeconds: 300,
		},
		Keys: map[string]config.KeyConfig{
			"k": {
				PublicKey:    pub,
				AllowedZones: []string{"example.com"},
				AllowReplace: true,
			},
		},
	}
	s := NewServer(cfg, noopStore{})

	body := []byte("serial: 1\n")
	// Client signs with the normalized (lowercase) path.
	sigHdr := signHeader(t, priv, "k", http.MethodPut, "/zones/example.com", body)

	// But sends the request with an upper-case path.
	req := httptest.NewRequest(http.MethodPut, "/zones/EXAMPLE.COM", bytes.NewReader(body))
	req.Header.Set("Authorization", sigHdr)
	req.Header.Set("Content-Type", "application/yaml")
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	// 401 would mean the normalized path wasn't used for sig verification.
	// We expect something other than 401 (probably 422 since noopStore doesn't
	// validate zone structure, or 200 if accepted).
	if rr.Code == http.StatusUnauthorized {
		t.Errorf("status = 401: normalized-path signature was rejected; server must verify against normalized path")
	}
}

// TestZoneAuth_UpperCasePathMismatch verifies that signing with an upper-case
// path fails if the server normalizes to lower-case for verification.
func TestZoneAuth_UpperCasePathMismatch(t *testing.T) {
	_, priv, pub := generateTestKey(t)
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:           ":0",
			ClockSkewSeconds: 300,
		},
		Keys: map[string]config.KeyConfig{
			"k": {
				PublicKey:    pub,
				AllowedZones: []string{"example.com"},
				AllowReplace: true,
			},
		},
	}
	s := NewServer(cfg, noopStore{})

	body := []byte("serial: 1\n")
	// Client signs with an upper-case path — should NOT match the server's
	// normalized verification path.
	sigHdr := signHeader(t, priv, "k", http.MethodPut, "/zones/EXAMPLE.COM", body)

	req := httptest.NewRequest(http.MethodPut, "/zones/EXAMPLE.COM", bytes.NewReader(body))
	req.Header.Set("Authorization", sigHdr)
	req.Header.Set("Content-Type", "application/yaml")
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: upper-case path signature must be rejected by normalized verification", rr.Code)
	}
}

// TestZoneAuth_ValidRequest verifies the happy path: a well-formed, correctly
// signed request with a normalized path is accepted.
func TestZoneAuth_ValidRequest(t *testing.T) {
	_, priv, pub := generateTestKey(t)
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:           ":0",
			ClockSkewSeconds: 300,
		},
		Keys: map[string]config.KeyConfig{
			"k": {
				PublicKey:    pub,
				AllowedZones: []string{"example.com"},
				AllowReplace: true,
			},
		},
	}
	s := NewServer(cfg, noopStore{})

	body := []byte("serial: 1\nrecords:\n  example.com.:\n    a:\n      ipv4: 1.2.3.4\n")
	sigHdr := signHeader(t, priv, "k", http.MethodPut, "/zones/example.com", body)

	req := httptest.NewRequest(http.MethodPut, "/zones/example.com", bytes.NewReader(body))
	req.Header.Set("Authorization", sigHdr)
	req.Header.Set("Content-Type", "application/yaml")
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for valid request; body: %s", rr.Code, rr.Body.String())
	}
}

// --- dataAuthMiddleware ordering tests ---

// TestDataAuth_UnauthorizedMethodFastFail verifies that a key lacking
// allow_raw_upload receives 403 even when the signature is invalid.
// This confirms the "fail fast" design for the /data endpoint.
func TestDataAuth_UnauthorizedMethodFastFail(t *testing.T) {
	_, _, pub := generateTestKey(t)
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:           ":0",
			ClockSkewSeconds: 300,
		},
		Keys: map[string]config.KeyConfig{
			"no-upload": {
				PublicKey:      pub,
				AllowRawUpload: false, // missing permission
			},
		},
	}
	s := NewServer(cfg, noopStore{})

	badSig := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(badSig)
	badSigB64 := base64.RawURLEncoding.EncodeToString(badSig)
	hdr := fmt.Sprintf(`TinyDNS-Sig keyId="no-upload",timestamp="%d",signature="%s"`,
		time.Now().Unix(), badSigB64)

	req := httptest.NewRequest(http.MethodPost, "/data", bytes.NewReader([]byte("+example.com:1.2.3.4\n")))
	req.Header.Set("Authorization", hdr)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	// Must be 403 (method not authorized), not 401 (signature invalid).
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (method authz check runs before sig verification)", rr.Code)
	}
}

// TestAuth_InvalidKeyIDChars verifies that an Authorization header with an
// invalid keyId (containing forbidden characters) is rejected with 401.
// keyId validation is in ParseAuthHeader and applies to all middleware that
// calls it (zoneAuthMiddleware and dataAuthMiddleware).
func TestAuth_InvalidKeyIDChars(t *testing.T) {
	s := &Server{
		cfg: &config.Config{
			Server: config.ServerConfig{
				Listen:           ":0",
				ClockSkewSeconds: 300,
			},
			Keys: map[string]config.KeyConfig{},
		},
		store: noopStore{},
	}

	// A keyId with a path-traversal sequence should be rejected at parse time.
	sig := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(sig)
	hdr := fmt.Sprintf(`TinyDNS-Sig keyId="../etc/passwd",timestamp="%d",signature="%s"`,
		time.Now().Unix(), base64.RawURLEncoding.EncodeToString(sig))

	req := httptest.NewRequest(http.MethodPut, "/zones/example.com", nil)
	req.Header.Set("Authorization", hdr)
	req.Header.Set("Content-Type", "application/yaml")
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for invalid keyId characters", rr.Code)
	}
}
