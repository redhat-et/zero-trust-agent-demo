// Package main contains JWKS fetching utilities.
package main

// TODO: Task 5 - Implement FetchJWKS
//
// FetchJWKS retrieves the JSON Web Key Set from the given URL.
// Returns a map of kid -> public key.
//
// JWKS response structure:
//
//	{
//	  "keys": [
//	    {
//	      "kid": "i4HIakZN92dv3DHUCT84snplzshhz0-BSTjkrjmeyww",
//	      "kty": "RSA",
//	      "alg": "RS256",
//	      "use": "sig",
//	      "n": "0f_AIjTu9T64...",  // base64url encoded modulus
//	      "e": "AQAB"               // base64url encoded exponent
//	    }
//	  ]
//	}
//
// Steps:
// 1. HTTP GET the JWKS URL
// 2. Parse the JSON response
// 3. For each key with kty="RSA" and use="sig":
//    a. Decode n (modulus) from base64url to big.Int
//    b. Decode e (exponent) from base64url to int
//    c. Construct rsa.PublicKey{N: n, E: e}
// 4. Return map indexed by kid
//
// Hints:
// - Use net/http for the HTTP request
// - Use encoding/json for parsing
// - Use math/big for the modulus (it's a very large number)
// - The exponent "AQAB" decodes to 65537 (standard RSA exponent)
//
// import (
//
//	"crypto/rsa"
//	"encoding/base64"
//	"encoding/json"
//	"math/big"
//	"net/http"
//
// )
func FetchJWKS(jwksURL string) (map[string]any, error) {
	// YOUR CODE HERE
	return nil, nil
}

// jwksResponse represents the JWKS JSON structure.
// You may want to define this struct for JSON unmarshaling.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type (RSA)
	Alg string `json:"alg"` // Algorithm (RS256)
	Use string `json:"use"` // Usage (sig = signing)
	N   string `json:"n"`   // Modulus (base64url)
	E   string `json:"e"`   // Exponent (base64url)
}

// decodeBase64URL decodes a base64url string to bytes.
// This is a helper you might find useful.
//
// Hint: base64url uses - and _ instead of + and /
// You can use base64.RawURLEncoding (no padding) or handle padding yourself.
func decodeBase64URL(s string) ([]byte, error) {
	// YOUR CODE HERE
	return nil, nil
}
