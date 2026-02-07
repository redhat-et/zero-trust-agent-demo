// Package main contains JWKS fetching utilities.
package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
)

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
//  1. HTTP GET the JWKS URL
//  2. Parse the JSON response
//  3. For each key with kty="RSA" and use="sig":
//     a. Decode n (modulus) from base64url to big.Int
//     b. Decode e (exponent) from base64url to int
//     c. Construct rsa.PublicKey{N: n, E: e}
//  4. Return map indexed by kid
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
func FetchJWKS(jwksURL string) (map[string]*rsa.PublicKey, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}
	publicKeys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			n := new(big.Int)
			e := new(big.Int)
			nBytes, err := decodeBase64URL(key.N)
			if err != nil {
				return nil, err
			}
			n.SetBytes(nBytes)
			eBytes, err := decodeBase64URL(key.E)
			if err != nil {
				return nil, err
			}
			e.SetBytes(eBytes)
			if e.IsInt64() {
				publicKey := rsa.PublicKey{N: n, E: int(e.Int64())}
				publicKeys[key.Kid] = &publicKey
			}
		}
	}
	return publicKeys, nil
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
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
