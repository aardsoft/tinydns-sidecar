package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Sign builds the Authorization header value for a request.
// It signs the canonical string with privKey and returns the full header value
// ready to be set as Authorization: <returned string>.
func Sign(privKey ed25519.PrivateKey, keyID string, timestamp int64, method, path string, body []byte) string {
	canonical := CanonicalString(timestamp, method, path, body)
	sig := ed25519.Sign(privKey, []byte(canonical))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf(`TinyDNS-Sig keyId="%s",timestamp="%d",signature="%s"`, keyID, timestamp, sigB64)
}

// SignNow calls Sign with the current Unix timestamp.
func SignNow(privKey ed25519.PrivateKey, keyID, method, path string, body []byte) string {
	return Sign(privKey, keyID, time.Now().Unix(), method, path, body)
}

// LoadPrivateKey reads a PKCS#8 PEM file and returns an Ed25519 private key.
// Generate with: openssl genpkey -algorithm ed25519 -out key.pem or
// the tinydns-client
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	key, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not an Ed25519 private key", path)
	}
	return key, nil
}
