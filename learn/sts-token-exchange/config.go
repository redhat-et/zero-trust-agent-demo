// Package main contains configuration for token exchange.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

const (
	DefaultTokenURL = "https://keycloak-spiffe-demo.apps.ocp-beta-test.nerc.mghpcc.org/realms/spiffe-demo/protocol/openid-connect/token"
)

//
// Create a struct that holds the configuration for token exchange:
//
//	type Config struct {
//	    TokenURL     string // Keycloak token endpoint
//	    ClientID     string // Client performing the exchange
//	    ClientSecret string // Client credentials
//	}
//
// Hints:
// - The token URL should default to the local Keycloak
// - ClientID and ClientSecret should come from environment variables
// - Consider adding validation to ensure required fields are set

// Config holds the token exchange configuration.
type Config struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
}

// LoadConfig loads configuration from environment variables.
//
// Environment variables:
// - TOKEN_URL: Keycloak token endpoint (default: http://localhost:8080/realms/demo/protocol/openid-connect/token)
// - CLIENT_ID: Client ID for authentication (required)
// - CLIENT_SECRET: Client secret for authentication (required)
func LoadConfig() (*Config, error) {
	//
	// Steps:
	// 1. Read TOKEN_URL from environment, use default if not set
	// 2. Read CLIENT_ID from environment, error if not set
	// 3. Read CLIENT_SECRET from environment, error if not set
	// 4. Return populated Config struct
	tokenURL := os.Getenv("TOKEN_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	if clientID == "" {
		return nil, fmt.Errorf("CLIENT_ID is required")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("CLIENT_SECRET is required")
	}
	return &Config{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

// Validate checks that the configuration is complete.
func (c *Config) Validate() error {
	//
	// Check that:
	// - TokenURL is not empty
	// - ClientID is not empty
	// - ClientSecret is not empty
	if c.TokenURL == "" {
		return fmt.Errorf("TOKEN_URL is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("CLIENT_ID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("CLIENT_SECRET is required")
	}
	return nil
}

// GetInitialToken obtains a token using client_credentials grant.
// This token will be used as the subject_token for exchange.
//
// Hints:
// - POST to TokenURL with grant_type=client_credentials
// - Include client_id and client_secret in the request body
// - Parse the JSON response to extract access_token
func (c *Config) GetInitialToken() (string, error) {
	reqBody := url.Values{}
	reqBody.Set("grant_type", "client_credentials")
	reqBody.Set("client_id", c.ClientID)
	reqBody.Set("client_secret", c.ClientSecret)
	resp, err := http.PostForm(c.TokenURL, reqBody)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	response := make(map[string]any)
	err = json.Unmarshal(body, &response)
	if err != nil {
		return "", err
	}
	accessToken, ok := response["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access_token not found in response")
	}
	return accessToken, nil
}
