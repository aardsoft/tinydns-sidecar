// tinydns-client — manage tinydns-sidecar zones and keys.
//
// Usage:
//
//	tinydns-client [flags] <command> [args]
//
// Commands:
//
//	edit-zone <zone>        Download zone YAML, open in $EDITOR, push back
//	edit-data               Download raw data, open in $EDITOR, push back
//	pull-zone <zone> [file] Download zone YAML to file (or stdout)
//	push-zone <zone> [file] Upload zone YAML from file (or stdin) via PUT
//	pull-data [file]        Download raw data to file (or stdout)
//	push-data [file]        Upload raw data from file (or stdin) via POST
//	capabilities            Print the authenticated key's permissions and format
//	gen-key <file>          Generate Ed25519 key pair; save private key to file
//	pub-key [file]          Print base64url public key from private key file
//
// Configuration (flags override env vars):
//
//	-endpoint   / TINYDNS_ENDPOINT   base URL of the sidecar
//	-key-id     / TINYDNS_KEY_ID     key ID in the sidecar config
//	-key-file   / TINYDNS_KEY_FILE   path to Ed25519 private key (PEM)
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aardsoft/tinydns-sidecar/internal/auth"
)

// cfg holds resolved configuration for API commands.
type cfg struct {
	endpoint string
	keyID    string
	keyFile  string
}

func main() {
	log.SetFlags(0) // no timestamps in user-facing output

	var c cfg
	flag.StringVar(&c.endpoint, "endpoint", os.Getenv("TINYDNS_ENDPOINT"), "sidecar base URL (env: TINYDNS_ENDPOINT)")
	flag.StringVar(&c.keyID, "key-id", os.Getenv("TINYDNS_KEY_ID"), "key ID (env: TINYDNS_KEY_ID)")
	flag.StringVar(&c.keyFile, "key-file", os.Getenv("TINYDNS_KEY_FILE"), "Ed25519 private key PEM (env: TINYDNS_KEY_FILE)")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	// Key management commands do not need API config — dispatch first.
	switch args[0] {
	case "gen-key":
		if len(args) < 2 {
			log.Fatal("gen-key requires an output file argument")
		}
		if err := genKey(args[1]); err != nil {
			log.Fatalf("gen-key: %v", err)
		}
		return
	case "pub-key":
		keyFile := c.keyFile
		if len(args) >= 2 {
			keyFile = args[1]
		}
		if keyFile == "" {
			log.Fatal("pub-key requires a key file (argument or -key-file flag)")
		}
		if err := pubKey(keyFile); err != nil {
			log.Fatalf("pub-key: %v", err)
		}
		return
	}

	// API commands need full config and a loaded key.
	if err := c.validate(); err != nil {
		log.Fatalf("configuration error: %v\nRun with -help for usage.", err)
	}
	privKey, err := auth.LoadPrivateKey(c.keyFile)
	if err != nil {
		log.Fatalf("loading key: %v", err)
	}

	switch args[0] {
	case "edit-zone":
		if len(args) < 2 {
			log.Fatal("edit-zone requires a zone name argument")
		}
		if err := editZone(c, privKey, strings.ToLower(args[1])); err != nil {
			log.Fatalf("edit-zone: %v", err)
		}
	case "edit-data":
		if err := editData(c, privKey); err != nil {
			log.Fatalf("edit-data: %v", err)
		}
	case "pull-zone":
		if len(args) < 2 {
			log.Fatal("pull-zone requires a zone name argument")
		}
		outFile := ""
		if len(args) >= 3 {
			outFile = args[2]
		}
		if err := pullZone(c, privKey, strings.ToLower(args[1]), outFile); err != nil {
			log.Fatalf("pull-zone: %v", err)
		}
	case "push-zone":
		if len(args) < 2 {
			log.Fatal("push-zone requires a zone name argument")
		}
		inFile := ""
		if len(args) >= 3 {
			inFile = args[2]
		}
		if err := pushZone(c, privKey, strings.ToLower(args[1]), inFile); err != nil {
			log.Fatalf("push-zone: %v", err)
		}
	case "pull-data":
		outFile := ""
		if len(args) >= 2 {
			outFile = args[1]
		}
		if err := pullData(c, privKey, outFile); err != nil {
			log.Fatalf("pull-data: %v", err)
		}
	case "push-data":
		inFile := ""
		if len(args) >= 2 {
			inFile = args[1]
		}
		if err := pushData(c, privKey, inFile); err != nil {
			log.Fatalf("push-data: %v", err)
		}
	case "capabilities":
		if err := showCapabilities(c, privKey); err != nil {
			log.Fatalf("capabilities: %v", err)
		}
	default:
		log.Fatalf("unknown command %q", args[0])
	}
}

// validate checks that all required API config fields are non-empty.
func (c *cfg) validate() error {
	var missing []string
	if c.endpoint == "" {
		missing = append(missing, "endpoint")
	}
	if c.keyID == "" {
		missing = append(missing, "key-id")
	}
	if c.keyFile == "" {
		missing = append(missing, "key-file")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required options: %s", strings.Join(missing, ", "))
	}
	return nil
}

// --- Key management commands ---

// genKey generates an Ed25519 key pair, writes the private key as PKCS#8 PEM
// to outFile (mode 0600), and prints the base64url public key to stdout.
func genKey(outFile string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshalling private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}

	f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outFile, err)
	}
	if err := pem.Encode(f, block); err != nil {
		f.Close()
		return fmt.Errorf("writing PEM: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", outFile, err)
	}

	fmt.Fprintf(os.Stderr, "private key written to %s\n", outFile)
	printPublicKey(pub)
	return nil
}

// pubKey loads an existing private key and prints its public key.
func pubKey(keyFile string) error {
	priv, err := auth.LoadPrivateKey(keyFile)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	printPublicKey(pub)
	return nil
}

// printPublicKey prints the base64url-encoded public key and a config snippet.
func printPublicKey(pub ed25519.PublicKey) {
	b64 := base64.RawURLEncoding.EncodeToString(pub)
	fmt.Println(b64)
	fmt.Fprintf(os.Stderr, "\nSidecar config snippet:\n  public_key: %q\n", b64)
}

// --- API / edit commands ---

// editZone downloads the YAML for zone, opens it in $EDITOR, and PUTs it back.
func editZone(c cfg, privKey ed25519.PrivateKey, zone string) error {
	path := "/zones/" + zone
	url := strings.TrimRight(c.endpoint, "/") + path

	body, notFound, err := apiGet(c, privKey, url, path)
	if err != nil {
		return err
	}
	if notFound {
		fmt.Fprintf(os.Stderr, "zone %s not found on server — starting from empty\n", zone)
		body = []byte{}
	}

	tmp, err := os.CreateTemp("", "tinydns-zone-"+zone+"-*.yml")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	tmp.Close()

	return editLoop(tmp.Name(), body, func(updated []byte) error {
		return apiRequest(c, privKey, http.MethodPut, url, path,
			"application/yaml", updated)
	})
}

// editData downloads the raw tinydns data for the key, opens it in $EDITOR,
// and POSTs it back.
func editData(c cfg, privKey ed25519.PrivateKey) error {
	path := "/data"
	url := strings.TrimRight(c.endpoint, "/") + path

	body, notFound, err := apiGet(c, privKey, url, path)
	if err != nil {
		return err
	}
	if notFound {
		fmt.Fprintln(os.Stderr, "no raw data for this key on server — starting from empty")
		body = []byte{}
	}

	tmp, err := os.CreateTemp("", "tinydns-data-*.data")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	tmp.Close()

	return editLoop(tmp.Name(), body, func(updated []byte) error {
		return apiRequest(c, privKey, http.MethodPost, url, path,
			"text/plain", updated)
	})
}

// pullZone downloads zone YAML and writes it to outFile (or stdout if empty).
func pullZone(c cfg, privKey ed25519.PrivateKey, zone, outFile string) error {
	path := "/zones/" + zone
	url := strings.TrimRight(c.endpoint, "/") + path

	body, notFound, err := apiGet(c, privKey, url, path)
	if err != nil {
		return err
	}
	if notFound {
		return fmt.Errorf("zone %s not found", zone)
	}
	return writeOutput(body, outFile)
}

// pushZone reads YAML from inFile (or stdin if empty) and PUTs it for zone.
func pushZone(c cfg, privKey ed25519.PrivateKey, zone, inFile string) error {
	if caps, err := fetchCapabilities(c, privKey); err != nil {
		return err
	} else if caps != nil && caps.Format == "raw" {
		return fmt.Errorf("server is configured for raw-only mode; use push-data instead")
	}

	body, err := readInput(inFile)
	if err != nil {
		return err
	}
	path := "/zones/" + zone
	url := strings.TrimRight(c.endpoint, "/") + path
	if err := apiRequest(c, privKey, http.MethodPut, url, path, "application/yaml", body); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "uploaded successfully")
	return nil
}

// pullData downloads raw tinydns data and writes it to outFile (or stdout if empty).
func pullData(c cfg, privKey ed25519.PrivateKey, outFile string) error {
	path := "/data"
	url := strings.TrimRight(c.endpoint, "/") + path

	body, notFound, err := apiGet(c, privKey, url, path)
	if err != nil {
		return err
	}
	if notFound {
		return fmt.Errorf("no raw data for this key on server")
	}
	return writeOutput(body, outFile)
}

// pushData reads raw data from inFile (or stdin if empty) and POSTs it.
func pushData(c cfg, privKey ed25519.PrivateKey, inFile string) error {
	if caps, err := fetchCapabilities(c, privKey); err != nil {
		return err
	} else if caps != nil && caps.Format == "yaml" {
		return fmt.Errorf("server is configured for yaml-only mode; use push-zone <zone> instead")
	}

	body, err := readInput(inFile)
	if err != nil {
		return err
	}
	if !hasRawDataLines(body) {
		return fmt.Errorf("content contains no tinydns record lines; if this is a YAML zone file use push-zone <zone> instead")
	}
	path := "/data"
	url := strings.TrimRight(c.endpoint, "/") + path
	if err := apiRequest(c, privKey, http.MethodPost, url, path, "text/plain", body); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "uploaded successfully")
	return nil
}

// hasRawDataLines reports whether data contains at least one tinydns record line.
// Mirrors the server-side zone.HasRawDataLines check.
func hasRawDataLines(data []byte) bool {
	const typeChars = ".&=+@'^CZ:36"
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) > 0 && strings.ContainsRune(typeChars, rune(line[0])) {
			return true
		}
	}
	return false
}

// capabilitiesResponse mirrors the server's capabilitiesResponse struct.
type capabilitiesResponse struct {
	KeyID          string   `yaml:"key_id"`
	Format         string   `yaml:"format"`
	AllowedZones   []string `yaml:"allowed_zones"`
	AllowReplace   bool     `yaml:"allow_replace"`
	AllowMerge     bool     `yaml:"allow_merge"`
	AllowRawUpload bool     `yaml:"allow_raw_upload"`
}

// fetchCapabilities retrieves and parses the /capabilities response.
// Returns nil without error if the endpoint is unreachable or too old —
// callers should treat a nil result as "no restriction known" and proceed.
func fetchCapabilities(c cfg, privKey ed25519.PrivateKey) (*capabilitiesResponse, error) {
	path := "/capabilities"
	url := strings.TrimRight(c.endpoint, "/") + path
	body, notFound, err := apiGet(c, privKey, url, path)
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, nil // old server without capabilities endpoint
	}
	var caps capabilitiesResponse
	if err := yaml.Unmarshal(body, &caps); err != nil {
		return nil, fmt.Errorf("parsing capabilities: %w", err)
	}
	return &caps, nil
}

// showCapabilities fetches and prints the key's permissions and format.
func showCapabilities(c cfg, privKey ed25519.PrivateKey) error {
	caps, err := fetchCapabilities(c, privKey)
	if err != nil {
		return err
	}
	if caps == nil {
		return fmt.Errorf("capabilities endpoint not found (server too old?)")
	}
	return yaml.NewEncoder(os.Stdout).Encode(caps)
}

// --- I/O helpers ---

// readInput reads from inFile if non-empty, otherwise from stdin.
func readInput(inFile string) ([]byte, error) {
	if inFile == "" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(inFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", inFile, err)
	}
	return data, nil
}

// writeOutput writes data to outFile if non-empty, otherwise to stdout.
func writeOutput(data []byte, outFile string) error {
	if outFile == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", outFile, err)
	}
	fmt.Fprintf(os.Stderr, "written to %s\n", outFile)
	return nil
}

// editLoop opens file in $EDITOR and calls upload with the new content.
// Skips upload if content is unchanged; offers re-edit on server error.
func editLoop(file string, original []byte, upload func([]byte) error) error {
	for {
		if err := openEditor(file); err != nil {
			return fmt.Errorf("editor: %w", err)
		}

		updated, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading edited file: %w", err)
		}

		if bytes.Equal(updated, original) {
			fmt.Fprintln(os.Stderr, "no changes — nothing uploaded")
			return nil
		}

		if err := upload(updated); err != nil {
			fmt.Fprintf(os.Stderr, "upload failed: %v\n", err)
			if !askYesNo("re-edit?") {
				return err
			}
			original = updated
			continue
		}

		fmt.Fprintln(os.Stderr, "uploaded successfully")
		return nil
	}
}

// apiGet performs a signed GET and returns the response body.
// notFound is true on HTTP 404.
func apiGet(c cfg, privKey ed25519.PrivateKey, url, path string) (body []byte, notFound bool, err error) {
	authHdr := auth.SignNow(privKey, c.keyID, http.MethodGet, path, nil)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", authHdr)

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("GET %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, false, nil
}

// apiRequest performs a signed PUT or POST with contentType and body.
func apiRequest(c cfg, privKey ed25519.PrivateKey, method, url, path, contentType string, body []byte) error {
	authHdr := auth.SignNow(privKey, c.keyID, method, path, body)

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", authHdr)
	req.Header.Set("Content-Type", contentType)

	resp, err := httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

// openEditor opens path in $VISUAL, $EDITOR, or vi (in that preference order).
func openEditor(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	parts := strings.Fields(editor)
	args := append(parts[1:], path)
	cmd := exec.Command(parts[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// askYesNo prints prompt and waits for y/Y; defaults to no.
func askYesNo(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func usage() {
	fmt.Fprintf(os.Stderr, `tinydns-client — manage tinydns-sidecar zones and keys

Usage:
  tinydns-client [flags] <command> [args]

Commands:
  edit-zone <zone>        Download zone YAML, open in $EDITOR, push back (PUT)
  edit-data               Download raw data, open in $EDITOR, push back (POST)
  pull-zone <zone> [file] Download zone YAML to file (stdout if no file given)
  push-zone <zone> [file] Upload zone YAML from file (stdin if no file given) via PUT
  pull-data [file]        Download raw data to file (stdout if no file given)
  push-data [file]        Upload raw data from file (stdin if no file given) via POST
  capabilities            Print the authenticated key's permissions and format
  gen-key <file>          Generate Ed25519 key pair; write private key to file (mode 0600)
  pub-key [file]          Print base64url public key derived from a private key file

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Environment variables (used when flag is not supplied):
  TINYDNS_ENDPOINT   base URL of the sidecar (e.g. https://dns.example.com:8080)
  TINYDNS_KEY_ID     key ID as configured in the sidecar
  TINYDNS_KEY_FILE   path to Ed25519 private key (PEM, PKCS#8)

gen-key and pub-key do not require endpoint or key-id.
pub-key accepts the key file as an argument or via -key-file.

Examples:
  tinydns-client gen-key ~/.config/tinydns/my-key.pem
  tinydns-client pub-key ~/.config/tinydns/my-key.pem
  tinydns-client capabilities
  tinydns-client pull-zone example.com example.com.yml
  tinydns-client push-zone example.com example.com.yml
  tinydns-client pull-data > data.txt
  tinydns-client push-data data.txt
  tinydns-client edit-zone example.com
  tinydns-client -endpoint https://dns.example.com edit-data
`)
}
