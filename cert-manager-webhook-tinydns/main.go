package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, &tinydnsSolver{})
}

type tinydnsSolver struct{}

type tinydnsSolverConfig struct {
	SidecarURL     string   `json:"sidecarURL"`
	KeyID          string   `json:"keyID"`
	PrivateKeyPath string   `json:"privateKeyPath"`
	AllowedZones   []string `json:"allowedZones,omitempty"`
}

func (t *tinydnsSolver) Name() string {
	return "tinydns"
}

func (t *tinydnsSolver) Initialize(_ *rest.Config, _ <-chan struct{}) error {
	return nil
}

func (t *tinydnsSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	fqdn := ch.ResolvedFQDN
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	// Build tinydns TXT line: '_fqdn:key:60::'
	// Colons inside the key must be escaped as \072.
	escaped := strings.ReplaceAll(ch.Key, ":", "\\072")
	line := fmt.Sprintf("'%s:%s:60::\n", fqdn, escaped)

	client, err := newSidecarClient(cfg)
	if err != nil {
		return err
	}

	// Fetch current raw data.
	data, err := client.getData()
	if err != nil {
		return fmt.Errorf("fetching raw data: %w", err)
	}

	// Append the challenge line.
	data = append(data, []byte(line)...)

	// Upload updated raw data.
	if err := client.postData(data); err != nil {
		return fmt.Errorf("uploading raw data: %w", err)
	}

	return nil
}

func (t *tinydnsSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	fqdn := ch.ResolvedFQDN
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	client, err := newSidecarClient(cfg)
	if err != nil {
		return err
	}

	// Fetch current raw data.
	data, err := client.getData()
	if err != nil {
		return fmt.Errorf("fetching raw data: %w", err)
	}

	// Remove the challenge line.
	prefix := "'" + fqdn + ":"
	lines := strings.Split(string(data), "\n")
	var kept []string
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			continue
		}
		if strings.TrimSpace(l) != "" {
			kept = append(kept, l)
		}
	}

	out := strings.Join(kept, "\n")
	if len(kept) > 0 {
		out += "\n"
	}

	// Upload updated raw data only if there's something to upload.
	// The sidecar rejects empty POSTs; if all records were removed
	// there's nothing to update.
	if len(out) > 0 {
		if err := client.postData([]byte(out)); err != nil {
			return fmt.Errorf("uploading raw data: %w", err)
		}
	}

	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (tinydnsSolverConfig, error) {
	cfg := tinydnsSolverConfig{}
	if cfgJSON == nil {
		return cfg, fmt.Errorf("webhook config is required")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing webhook config: %w", err)
	}
	if cfg.SidecarURL == "" {
		return cfg, fmt.Errorf("sidecarURL is required in webhook config")
	}
	if cfg.KeyID == "" {
		return cfg, fmt.Errorf("keyID is required in webhook config")
	}
	if cfg.PrivateKeyPath == "" {
		return cfg, fmt.Errorf("privateKeyPath is required in webhook config")
	}
	return cfg, nil
}

// --- sidecar HTTP client ---

type sidecarClient struct {
	url        string
	keyID      string
	privateKey ed25519.PrivateKey
	httpClient *http.Client
}

func newSidecarClient(cfg tinydnsSolverConfig) (*sidecarClient, error) {
	key, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading private key: %w", err)
	}
	return &sidecarClient{
		url:        strings.TrimSuffix(cfg.SidecarURL, "/"),
		keyID:      cfg.KeyID,
		privateKey: key,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (c *sidecarClient) getData() ([]byte, error) {
	url := c.url + "/data"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	authHeader := signNow(c.privateKey, c.keyID, http.MethodGet, "/data", nil)
	req.Header.Set("Authorization", authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		// No raw data exists yet — start with empty.
		return []byte{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sidecar returned %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *sidecarClient) postData(data []byte) error {
	url := c.url + "/data"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")

	authHeader := signNow(c.privateKey, c.keyID, http.MethodPost, "/data", data)
	req.Header.Set("Authorization", authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sidecar returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// --- auth helpers (copied from tinydns-sidecar) ---

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
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

func signNow(privKey ed25519.PrivateKey, keyID, method, path string, body []byte) string {
	return sign(privKey, keyID, time.Now().Unix(), method, path, body)
}

func sign(privKey ed25519.PrivateKey, keyID string, timestamp int64, method, path string, body []byte) string {
	canonical := canonicalString(timestamp, method, path, body)
	sig := ed25519.Sign(privKey, []byte(canonical))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf(`TinyDNS-Sig keyId="%s",timestamp="%d",signature="%s"`, keyID, timestamp, sigB64)
}

func canonicalString(timestamp int64, method, path string, body []byte) string {
	if body == nil {
		body = []byte{}
	}
	sum := sha256Sum(body)
	return fmt.Sprintf("%d\n%s\n%s\n%s", timestamp, method, path, sum)
}

func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
