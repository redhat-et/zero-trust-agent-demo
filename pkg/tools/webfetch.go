package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebFetchConfig struct {
	AllowedHosts []string
}

type webFetchTool struct {
	config WebFetchConfig
}

func NewWebFetchTool(cfg WebFetchConfig) Tool {
	return &webFetchTool{config: cfg}
}

func (t *webFetchTool) Name() string        { return "web_fetch" }
func (t *webFetchTool) Description() string {
	return "Fetch content from a URL via HTTP GET. Returns the response body as text."
}
func (t *webFetchTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "The URL to fetch",
			},
		},
		"required": []string{"url"},
	}
}

func (t *webFetchTool) Execute(ctx context.Context, args map[string]any) *ToolResult {
	rawURL, ok := args["url"].(string)
	if !ok || rawURL == "" {
		return Errorf("url is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Errorf("invalid URL: %s", err)
	}

	// Only allow HTTP and HTTPS schemes
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return Errorf("unsupported URL scheme: %s", parsed.Scheme)
	}

	if len(t.config.AllowedHosts) > 0 {
		if !t.isHostAllowed(parsed.Hostname()) {
			return Errorf("Host not allowed: %s", parsed.Hostname())
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Errorf("failed to create request: %s", err)
	}

	// Use custom client that validates redirects against allowed hosts
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(t.config.AllowedHosts) > 0 && !t.isHostAllowed(req.URL.Hostname()) {
				return fmt.Errorf("redirect to non-allowed host: %s", req.URL.Hostname())
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return Errorf("fetch failed: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100000))
	if err != nil {
		return Errorf("failed to read response: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return OK(string(body))
}

// isHostAllowed checks if a hostname matches the allowed hosts list
// using dot-boundary matching to prevent "attackerexample.com" from
// matching "example.com".
func (t *webFetchTool) isHostAllowed(host string) bool {
	host = strings.ToLower(host)
	for _, allowed := range t.config.AllowedHosts {
		allowed = strings.ToLower(allowed)
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}
