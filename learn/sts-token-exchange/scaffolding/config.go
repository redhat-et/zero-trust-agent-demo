// Package main contains configuration for token exchange.
package main

import (
	"fmt"
	"os"
)

// TODO: Task 2 - Define Config struct
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
	// TODO: Add fields
	// TokenURL     string
	// ClientID     string
	// ClientSecret string
}

// LoadConfig loads configuration from environment variables.
//
// Environment variables:
// - TOKEN_URL: Keycloak token endpoint (default: http://localhost:8080/realms/demo/protocol/openid-connect/token)
// - CLIENT_ID: Client ID for authentication (required)
// - CLIENT_SECRET: Client secret for authentication (required)
func LoadConfig() (*Config, error) {
	// TODO: Implement configuration loading
	//
	// Steps:
	// 1. Read TOKEN_URL from environment, use default if not set
	// 2. Read CLIENT_ID from environment, error if not set
	// 3. Read CLIENT_SECRET from environment, error if not set
	// 4. Return populated Config struct

	_ = os.Getenv // Remove when you use os.Getenv
	_ = fmt.Errorf // Remove when you use fmt.Errorf

	return nil, fmt.Errorf("LoadConfig not implemented")
}

// Validate checks that the configuration is complete.
func (c *Config) Validate() error {
	// TODO: Implement validation
	//
	// Check that:
	// - TokenURL is not empty
	// - ClientID is not empty
	// - ClientSecret is not empty

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
	// TODO: Implement client_credentials grant
	//
	// Request body:
	//   grant_type=client_credentials
	//   client_id=<your client>
	//   client_secret=<your secret>
	//
	// Response:
	//   {"access_token": "eyJ...", "token_type": "Bearer", ...}

	return "", fmt.Errorf("GetInitialToken not implemented")
}
