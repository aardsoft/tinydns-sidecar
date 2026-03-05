package api

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aardsoft/tinydns-sidecar/internal/auth"
	"github.com/aardsoft/tinydns-sidecar/internal/config"
	"github.com/aardsoft/tinydns-sidecar/internal/zone"
)

// --- Zone handlers ---

// handlePutZone is PUT /zones/{zone} — full replace.
func (s *Server) handlePutZone(w http.ResponseWriter, r *http.Request) {
	zoneName := strings.ToLower(r.PathValue("zone"))
	body := contextBody(r)
	keyID := contextKeyID(r)
	keyCfg, _ := s.keyConfigFromContext(r)

	if keyCfg.Format == "raw" {
		writeError(w, http.StatusForbidden, "key format is raw; use POST /data instead of /zones/{zone}")
		return
	}

	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "request body must not be empty")
		return
	}

	var zf zone.ZoneFile
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&zf); err != nil {
		writeError(w, http.StatusBadRequest, "parsing zone YAML: "+err.Error())
		return
	}

	if errs := zone.Validate(zf); errs != nil {
		writeError(w, http.StatusUnprocessableEntity, errs.Error())
		return
	}

	if errs := zone.ValidateZoneContainment(zf, zoneName); errs != nil {
		writeError(w, http.StatusUnprocessableEntity, errs.Error())
		return
	}

	if err := s.store.WriteZone(zoneName, zf); err != nil {
		slog.Error("writing zone", "zone", zoneName, "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "writing zone")
		return
	}

	s.cleanupRawData(keyID, keyCfg)
	slog.Info("zone replaced", "zone", zoneName, "key", keyID)
	writeYAML(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handlePatchZone is PATCH /zones/{zone} — additive merge.
func (s *Server) handlePatchZone(w http.ResponseWriter, r *http.Request) {
	zoneName := strings.ToLower(r.PathValue("zone"))
	body := contextBody(r)
	keyID := contextKeyID(r)
	keyCfg, _ := s.keyConfigFromContext(r)

	if keyCfg.Format == "raw" {
		writeError(w, http.StatusForbidden, "key format is raw; use POST /data instead of /zones/{zone}")
		return
	}

	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "request body must not be empty")
		return
	}

	var incoming zone.ZoneFile
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&incoming); err != nil {
		writeError(w, http.StatusBadRequest, "parsing zone YAML: "+err.Error())
		return
	}

	if errs := zone.Validate(incoming); errs != nil {
		writeError(w, http.StatusUnprocessableEntity, errs.Error())
		return
	}

	if errs := zone.ValidateZoneContainment(incoming, zoneName); errs != nil {
		writeError(w, http.StatusUnprocessableEntity, errs.Error())
		return
	}

	// Read existing zone; treat missing as empty.
	existing, err := s.store.ReadZone(zoneName)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("reading zone for merge", "zone", zoneName, "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "reading existing zone")
		return
	}
	base := zone.ZoneFile{}
	if existing != nil {
		base = *existing
	}

	merged, err := zone.Merge(base, incoming)
	if err != nil {
		slog.Error("merging zone", "zone", zoneName, "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "merging zone data")
		return
	}

	if err := s.store.WriteZone(zoneName, merged); err != nil {
		slog.Error("writing merged zone", "zone", zoneName, "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "writing zone")
		return
	}

	s.cleanupRawData(keyID, keyCfg)
	slog.Info("zone merged", "zone", zoneName, "key", keyID)
	writeYAML(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleGetZone is GET /zones/{zone}.
func (s *Server) handleGetZone(w http.ResponseWriter, r *http.Request) {
	zoneName := strings.ToLower(r.PathValue("zone"))
	keyID := contextKeyID(r)

	zf, err := s.store.ReadZone(zoneName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "zone not found")
			return
		}
		slog.Error("reading zone", "zone", zoneName, "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "reading zone")
		return
	}

	writeYAML(w, http.StatusOK, zf)
}

// handleDeleteZone is DELETE /zones/{zone}.
func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	zoneName := strings.ToLower(r.PathValue("zone"))
	keyID := contextKeyID(r)

	if err := s.store.DeleteZone(zoneName); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "zone not found")
			return
		}
		slog.Error("deleting zone", "zone", zoneName, "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "deleting zone")
		return
	}

	slog.Info("zone deleted", "zone", zoneName, "key", keyID)
	writeYAML(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Raw data handlers ---

// handlePostData is POST /data — stores raw tinydns data for the authenticated key.
func (s *Server) handlePostData(w http.ResponseWriter, r *http.Request) {
	keyID := contextKeyID(r)
	body := contextBody(r)
	keyCfg, _ := s.keyConfigFromContext(r)

	if keyCfg.Format == "yaml" {
		writeError(w, http.StatusForbidden, "key format is yaml; use PUT /zones/{zone} instead of /data")
		return
	}

	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "request body must not be empty")
		return
	}

	if !zone.HasRawDataLines(body) {
		writeError(w, http.StatusUnprocessableEntity, "body contains no tinydns record lines; use PUT or PATCH /zones/{zone} for YAML uploads")
		return
	}

	// Sanitise: neutralise any lines with unrecognised type characters so they
	// cannot smuggle records for domains that bypassed FQDN validation.
	sanitized, warnings := zone.SanitizeRawData(body)
	if len(warnings) > 0 {
		slog.Warn("raw data contained unrecognised lines", "key", keyID, "count", len(warnings))
	}

	// Validate that every FQDN in the sanitised data belongs to a zone this key owns.
	if fqdns := zone.ExtractRawDataFQDNs(sanitized); len(fqdns) > 0 {
		var violations []string
		for _, fqdn := range fqdns {
			if !auth.FQDNInAllowedZones(keyCfg.AllowedZones, fqdn) {
				violations = append(violations, fqdn)
			}
		}
		if len(violations) > 0 {
			msg := fmt.Sprintf("FQDNs not within allowed zones: %s", strings.Join(violations, ", "))
			slog.Warn("raw data domain violation", "key", keyID, "violations", violations)
			writeError(w, http.StatusUnprocessableEntity, msg)
			return
		}
	}

	if err := s.store.WriteRawData(keyID, sanitized); err != nil {
		slog.Error("writing raw data", "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "writing raw data")
		return
	}

	s.cleanupYAMLZones(keyID, keyCfg)
	slog.Info("raw data uploaded", "key", keyID, "bytes", len(sanitized), "sanitized_lines", len(warnings))
	writeYAML(w, http.StatusOK, struct {
		Status   string   `yaml:"status"`
		Warnings []string `yaml:"warnings,omitempty"`
	}{Status: "ok", Warnings: warnings})
}

// handleGetData is GET /data — returns the raw data for the authenticated key.
func (s *Server) handleGetData(w http.ResponseWriter, r *http.Request) {
	keyID := contextKeyID(r)

	data, err := s.store.ReadRawData(keyID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "no raw data for key")
			return
		}
		slog.Error("reading raw data", "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "reading raw data")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleDeleteData is DELETE /data — removes the raw data file for the authenticated key.
func (s *Server) handleDeleteData(w http.ResponseWriter, r *http.Request) {
	keyID := contextKeyID(r)

	if err := s.store.DeleteRawData(keyID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "no raw data for key")
			return
		}
		slog.Error("deleting raw data", "key", keyID, "error", err)
		writeError(w, http.StatusInternalServerError, "deleting raw data")
		return
	}

	slog.Info("raw data deleted", "key", keyID)
	writeYAML(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Capabilities handler ---

type capabilitiesResponse struct {
	KeyID          string   `yaml:"key_id"`
	Format         string   `yaml:"format,omitempty"` // "yaml", "raw", or absent (unrestricted)
	AllowedZones   []string `yaml:"allowed_zones"`
	AllowReplace   bool     `yaml:"allow_replace"`
	AllowMerge     bool     `yaml:"allow_merge"`
	AllowRawUpload bool     `yaml:"allow_raw_upload"`
}

// handleGetCapabilities is GET /capabilities — returns the authenticated key's
// permissions and format setting.  Used by the client to choose the right
// upload format without hardcoding it in client configuration.
func (s *Server) handleGetCapabilities(w http.ResponseWriter, r *http.Request) {
	keyID := contextKeyID(r)
	keyCfg, _ := s.keyConfigFromContext(r)
	// Server-level format overrides key-level format.
	format := keyCfg.Format
	if s.cfg.Server.Format != "" {
		format = s.cfg.Server.Format
	}
	writeYAML(w, http.StatusOK, capabilitiesResponse{
		KeyID:          keyID,
		Format:         format,
		AllowedZones:   keyCfg.AllowedZones,
		AllowReplace:   keyCfg.AllowReplace,
		AllowMerge:     keyCfg.AllowMerge,
		AllowRawUpload: keyCfg.AllowRawUpload,
	})
}

// --- Format-switch cleanup helpers ---

// cleanupRawData deletes raw/{keyID}.data when a key with format=yaml writes
// YAML.  Safe to call unconditionally; only acts when format is set.
func (s *Server) cleanupRawData(keyID string, keyCfg config.KeyConfig) {
	if keyCfg.Format != "yaml" {
		return
	}
	if err := s.store.DeleteRawData(keyID); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("cleanup raw data file", "key", keyID, "error", err)
	}
}

// cleanupYAMLZones deletes zone YAML files for exact-match zones in
// allowed_zones when a key with format=raw writes raw data.  Wildcard patterns
// are skipped because the set of matching zone files cannot be safely
// enumerated.
func (s *Server) cleanupYAMLZones(keyID string, keyCfg config.KeyConfig) {
	if keyCfg.Format != "raw" {
		return
	}
	for _, z := range keyCfg.AllowedZones {
		if strings.HasPrefix(z, "*.") {
			continue
		}
		if err := s.store.DeleteZone(z); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("cleanup yaml zone file", "zone", z, "key", keyID, "error", err)
		}
	}
}
