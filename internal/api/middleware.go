package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aardsoft/tinydns-sidecar/internal/auth"
	"github.com/aardsoft/tinydns-sidecar/internal/config"
)

type contextKey int

const (
	ctxKeyID  contextKey = iota // string: authenticated key ID
	ctxBody   contextKey = iota // []byte: buffered request body
)

var safeZoneRE = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// zoneAuthMiddleware wraps zone handlers (paths with {zone}).
// It buffers the body, validates and normalises the zone name, checks the
// timestamp window, looks up the key, enforces zone and method authorization,
// and verifies the Ed25519 signature.
func (s *Server) zoneAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Buffer body (max 1 MB enforced by server config, re-read for sig).
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		// 2. Parse Authorization header.
		parsed, err := auth.ParseAuthHeader(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid Authorization header: "+err.Error())
			return
		}

		// 3. Normalize + validate zone name.
		zoneName := strings.ToLower(r.PathValue("zone"))
		if !safeZoneRE.MatchString(zoneName) {
			writeError(w, http.StatusBadRequest, "invalid zone name")
			return
		}

		// 4. Timestamp check.
		now := time.Now().Unix()
		skew := int64(s.cfg.Server.ClockSkewSeconds)
		diff := parsed.Timestamp - now
		if diff < -skew || diff > skew {
			writeError(w, http.StatusUnauthorized, "timestamp outside allowed window")
			return
		}

		// 5. Key lookup.
		keyCfg, ok := s.cfg.Keys[parsed.KeyID]
		if !ok {
			writeError(w, http.StatusUnauthorized, "unknown key")
			return
		}

		// 6. Zone authorization.
		if !auth.ZoneAllowed(keyCfg.AllowedZones, zoneName) {
			writeError(w, http.StatusForbidden, "key not authorized for zone")
			return
		}

		// 7. Method authorization.
		switch r.Method {
		case http.MethodPut, http.MethodDelete:
			if !keyCfg.AllowReplace {
				writeError(w, http.StatusForbidden, "key does not have allow_replace")
				return
			}
		case http.MethodPatch:
			if !keyCfg.AllowMerge {
				writeError(w, http.StatusForbidden, "key does not have allow_merge")
				return
			}
		}

		// 8. Signature verification.
		// Rebuild path with normalized zone name so the canonical string matches
		// what the client signed (they should also normalize, but we sign what we receive).
		path := r.URL.Path
		ok, err = auth.Verify(keyCfg.PublicKey, parsed.Timestamp, r.Method, path, body, parsed.Signature)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "signature verification error: "+err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid signature")
			return
		}

		// 9. Inject context.
		ctx := context.WithValue(r.Context(), ctxKeyID, parsed.KeyID)
		ctx = context.WithValue(ctx, ctxBody, body)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// dataAuthMiddleware wraps /data handlers.
// No zone name or zone authorization — the key ID itself scopes the resource.
func (s *Server) dataAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Buffer body.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		// 2. Parse Authorization header.
		parsed, err := auth.ParseAuthHeader(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid Authorization header: "+err.Error())
			return
		}

		// 3. Timestamp check.
		now := time.Now().Unix()
		skew := int64(s.cfg.Server.ClockSkewSeconds)
		diff := parsed.Timestamp - now
		if diff < -skew || diff > skew {
			writeError(w, http.StatusUnauthorized, "timestamp outside allowed window")
			return
		}

		// 4. Key lookup.
		keyCfg, ok := s.cfg.Keys[parsed.KeyID]
		if !ok {
			writeError(w, http.StatusUnauthorized, "unknown key")
			return
		}

		// 5. Method authorization (POST requires allow_raw_upload; DELETE requires it too).
		switch r.Method {
		case http.MethodPost, http.MethodDelete:
			if !keyCfg.AllowRawUpload {
				writeError(w, http.StatusForbidden, "key does not have allow_raw_upload")
				return
			}
		case http.MethodGet:
			// Any key that can see its own data is fine; no extra flag required.
		}

		// 6. Signature verification.
		ok, err = auth.Verify(keyCfg.PublicKey, parsed.Timestamp, r.Method, r.URL.Path, body, parsed.Signature)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "signature verification error: "+err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid signature")
			return
		}

		// 7. Inject context.
		ctx := context.WithValue(r.Context(), ctxKeyID, parsed.KeyID)
		ctx = context.WithValue(ctx, ctxBody, body)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// contextKeyID retrieves the authenticated key ID from context.
func contextKeyID(r *http.Request) string {
	v, _ := r.Context().Value(ctxKeyID).(string)
	return v
}

// contextBody retrieves the buffered body from context.
func contextBody(r *http.Request) []byte {
	v, _ := r.Context().Value(ctxBody).([]byte)
	return v
}

// requireContentType returns a middleware that enforces the Content-Type header
// for methods that carry a body (PUT, PATCH, POST).
func requireContentType(validTypes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodPost {
				ct := r.Header.Get("Content-Type")
				// Strip parameters (e.g. "application/yaml; charset=utf-8")
				if idx := strings.IndexByte(ct, ';'); idx >= 0 {
					ct = strings.TrimSpace(ct[:idx])
				}
				allowed := false
				for _, t := range validTypes {
					if ct == t {
						allowed = true
						break
					}
				}
				if !allowed {
					writeError(w, http.StatusUnsupportedMediaType,
						"Content-Type must be one of: "+strings.Join(validTypes, ", "))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// keyConfig retrieves the full KeyConfig for the authenticated key.
func (s *Server) keyConfigFromContext(r *http.Request) (config.KeyConfig, bool) {
	id := contextKeyID(r)
	kc, ok := s.cfg.Keys[id]
	return kc, ok
}
