package api

import (
	"net/http"

	"gopkg.in/yaml.v3"
)

// writeYAML encodes v as YAML and writes it with the given status code.
func writeYAML(w http.ResponseWriter, status int, v any) {
	data, err := yaml.Marshal(v)
	if err != nil {
		http.Error(w, "internal error marshalling response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// errorResponse is the standard error body.
type errorResponse struct {
	Error string `yaml:"error"`
}

// writeError writes a YAML error body with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeYAML(w, status, errorResponse{Error: msg})
}
