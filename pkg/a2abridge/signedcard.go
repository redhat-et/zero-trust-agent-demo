package a2abridge

import (
	"log/slog"
	"net/http"
	"os"
)

// SignedCardHandler returns an http.Handler that serves a signed agent card
// from the file at path. The file is read once at startup; if it cannot be
// read, the provided fallback handler is returned instead.
func SignedCardHandler(path string, fallback http.Handler, log *slog.Logger) http.Handler {
	data, err := os.ReadFile(path)
	if err != nil {
		if log != nil {
			log.Info("No signed agent card found, serving unsigned card", "path", path, "error", err)
		}
		return fallback
	}

	if log != nil {
		log.Info("Serving signed agent card", "path", path)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
}
