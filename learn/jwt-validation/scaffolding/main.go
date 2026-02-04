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
	_ = tokenFile // Remove this line when you use the variable
	_ = token     // Remove this line when you use the variable

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

	fmt.Println("JWT Validation - Task 8: Implement this CLI")
	fmt.Println("See README.md for instructions")
}
