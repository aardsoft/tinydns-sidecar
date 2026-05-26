package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aardsoft/tinydns-sidecar/internal/auth"
)

// certManagerRequest is the JSON body sent by cert-manager webhook to Present/CleanUp.
type certManagerRequest struct {
	Type             string            `json:"type"`              // "present" or "cleanup"
	DNSName          string            `json:"dnsName"`           // e.g. "_acme-challenge.wachter.fi"
	Key              string            `json:"key"`               // base64 challenge token
	ResolvedZone     string            `json:"resolvedZone"`      // zone FQDN
	ResolvedFQDN     string            `json:"resolvedFQDN"`      // challenge FQDN
	AllowBareDomains bool              `json:"allowBareDomains"`  // unused
	Config           map[string]string `json:"config,omitempty"`  // solver config from Issuer
}

// certManagerResponse is the JSON body returned to cert-manager.
type certManagerResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// acmeChallengesFile is the raw data file name for ACME TXT records.
// It lives in the zones directory (next to zone YAMLs) and is included
// in the rebuild via the existing raw-data pipeline.
const acmeChallengesFile = "acme-challenges.data"

// handleACMEPresent is POST /acme/present — adds a TXT record for dns-01.
func (s *Server) handleACMEPresent(w http.ResponseWriter, r *http.Request) {
	var req certManagerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeACMError(w, http.StatusBadRequest, "parsing JSON: "+err.Error())
		return
	}

	if !s.verifyACMEToken(req.Config, req.DNSName) {
		slog.Warn("ACME present rejected: invalid auth token", "dnsName", req.DNSName)
		writeACMError(w, http.StatusUnauthorized, "invalid auth token")
		return
	}

	if req.DNSName == "" || req.Key == "" {
		writeACMError(w, http.StatusBadRequest, "dnsName and key are required")
		return
	}

	// Build a tinydns TXT line.  The value is the base64 key; colons inside
	// the value must be escaped as \072 because tinydns uses ':' as field
	// delimiter.  TTL 60s is standard for ACME challenges.
	escaped := strings.ReplaceAll(req.Key, ":", "\\072")
	line := fmt.Sprintf("'%s:%s:60::\n", req.DNSName, escaped)

	if err := s.appendACMEChallenge(line); err != nil {
		slog.Error("appending ACME challenge", "dnsName", req.DNSName, "error", err)
		writeACMError(w, http.StatusInternalServerError, "writing challenge")
		return
	}

	slog.Info("ACME challenge presented", "dnsName", req.DNSName)
	writeACMSuccess(w)
}

// handleACMECleanup is POST /acme/cleanup — removes a TXT record for dns-01.
func (s *Server) handleACMECleanup(w http.ResponseWriter, r *http.Request) {
	var req certManagerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeACMError(w, http.StatusBadRequest, "parsing JSON: "+err.Error())
		return
	}

	if !s.verifyACMEToken(req.Config, req.DNSName) {
		slog.Warn("ACME cleanup rejected: invalid auth token", "dnsName", req.DNSName)
		writeACMError(w, http.StatusUnauthorized, "invalid auth token")
		return
	}

	if req.DNSName == "" {
		writeACMError(w, http.StatusBadRequest, "dnsName is required")
		return
	}

	if err := s.removeACMEChallenge(req.DNSName); err != nil {
		slog.Error("removing ACME challenge", "dnsName", req.DNSName, "error", err)
		writeACMError(w, http.StatusInternalServerError, "removing challenge")
		return
	}

	slog.Info("ACME challenge cleaned up", "dnsName", req.DNSName)
	writeACMSuccess(w)
}

// --- helpers ---

func (s *Server) acmeChallengesPath() string {
	// The store's zonesDir is not exported, but we can derive it from the
	// config or accept that the sidecar is colocated with the data directory.
	// For now we assume the FileStore writes to {cfg.ZonesDir}/acme-challenges.data.
	// If the store interface is extended later, this can be cleaner.
	return filepath.Join(s.cfg.Storage.ZonesDir, acmeChallengesFile)
}

func (s *Server) appendACMEChallenge(line string) error {
	path := s.acmeChallengesPath()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	if err != nil {
		return err
	}

	// Sync to disk so the rebuild sees the data immediately.
	if err := f.Sync(); err != nil {
		return err
	}

	s.runRebuild()
	return nil
}

func (s *Server) removeACMEChallenge(dnsName string) error {
	path := s.acmeChallengesPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing to remove
		}
		return err
	}

	prefix := "'" + dnsName + ":"
	lines := strings.Split(string(data), "\n")
	var kept []string
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			continue // skip matching line
		}
		if strings.TrimSpace(l) != "" {
			kept = append(kept, l)
		}
	}

	if len(kept) == 0 {
		// No lines left — remove the file entirely.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		s.runRebuild()
		return nil
	}

	// Rewrite file without the removed line.
	out := strings.Join(kept, "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return err
	}

	s.runRebuild()
	return nil
}

// verifyACMEToken checks the authToken in the request config against the
// configured server token.  If no token is configured (ACMEToken is empty),
// all requests are rejected.
func (s *Server) verifyACMEToken(cfg map[string]string, dnsName string) bool {
	token := cfg["authToken"]
	if token == "" {
		return false
	}
	for _, key := range s.cfg.ACMEKeys {
		if key.Token == token {
			return auth.FQDNInAllowedZones(key.AllowedZones, dnsName)
		}
	}
	return false
}

func writeACMSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(certManagerResponse{Success: true})
}

func writeACMError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(certManagerResponse{Success: false, Error: msg})
}

// runRebuild mirrors the FileStore behaviour: trigger async rebuild.
// Duplicated here because Store interface does not expose it.
func (s *Server) runRebuild() {
	if s.cfg.Storage.RebuildCommand == "" {
		return
	}
	go func() {
		// Same logic as storage.FileStore.runRebuild
		_ = exec.Command("sh", "-c", s.cfg.Storage.RebuildCommand).Run()
	}()
}
