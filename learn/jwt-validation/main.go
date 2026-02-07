// Package main provides a CLI for JWT validation learning.
//
// YOUR TASK: Complete Task 8 to build a working CLI that:
// 1. Reads a JWT from file or environment
// 2. Fetches JWKS from Keycloak
// 3. Validates the signature
// 4. Checks expiration
// 5. Extracts and displays claims
// 6. Detects delegation
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// TODO: Task 8 - Implement CLI argument parsing
	//
	// Suggested flags:
	// --token-file: path to file containing JWT
	// --jwks-url: URL of the JWKS endpoint
	//
	// Also check JWT_TOKEN environment variable as fallback

	tokenFile := flag.String("token-file", "", "Path to file containing JWT")
	jwksURL := flag.String("jwks-url", "", "URL of JWKS endpoint")
	flag.Parse()

	// TODO: Read token from file or environment
	var token string
	if *tokenFile != "" {
		tokenBytes, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: Failed to read token file:", err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(tokenBytes))
	} else {
		token = os.Getenv("JWT_TOKEN")
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: No token provided")
		os.Exit(1)
	}

	// TODO: Validate JWKS URL is provided
	if *jwksURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --jwks-url is required")
		os.Exit(1)
	}

	// TODO: Call your validation functions
	// 1. ParseHeader(token) - get alg and kid
	// 2. FetchJWKS(*jwksURL) - get public keys
	// 3. VerifySignature(token, publicKey) - validate signature
	// 4. IsExpired(token) - check expiration
	// 5. Parse claims and call DetectDelegation

	expired, err := IsExpired(token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Failed to check expiration:", err)
		os.Exit(1)
	}
	fmt.Printf("Expired: %t\n", expired)

	alg, kid, err := ParseHeader(token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Failed to parse header:", err)
		os.Exit(1)
	}
	fmt.Printf("Algorithm: %s\nKey ID: %s\n", alg, kid)

	publicKeys, err := FetchJWKS(*jwksURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Failed to fetch JWKS:", err)
		os.Exit(1)
	}
	fmt.Println("Public Keys:")
	for kid, publicKey := range publicKeys {
		fmt.Printf("Kid: %s\nPublic Key N: %v\n", kid, publicKey.N.String())
	}
	publicKey, ok := publicKeys[kid]
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: Public key not found")
		os.Exit(1)
	}
	err = VerifySignature(token, publicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Failed to verify signature:", err)
		os.Exit(1)
	}
	fmt.Println("Signature verified")

	claims, err := ParseClaims(token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Failed to parse claims:", err)
		os.Exit(1)
	}
	fmt.Printf("Claims:\n%s\n", claims.String())

	delegationInfo := DetectDelegation(claims)
	if delegationInfo != nil {
		fmt.Printf("Delegation Info:\n%s\n", delegationInfo.String())
	}
}
