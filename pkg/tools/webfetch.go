package tools

import (
	"context"
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

	if len(t.config.AllowedHosts) > 0 {
		host := parsed.Hostname()
		allowed := false
		for _, suffix := range t.config.AllowedHosts {
			if strings.HasSuffix(host, suffix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Errorf("Host not allowed: %s", host)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Errorf("failed to create request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
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
