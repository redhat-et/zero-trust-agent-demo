// Package main contains JWT parsing and validation utilities.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// TODO: Task 2 - Implement ParseHeader
//
// ParseHeader decodes the JWT header and returns the algorithm and key ID.
// The header contains "alg" (algorithm) and "kid" (key ID) fields.
//
// Example header (decoded):
//
//	{
//	  "alg": "RS256",
//	  "typ": "JWT",
//	  "kid": "i4HIakZN92dv3DHUCT84snplzshhz0-BSTjkrjmeyww"
//	}
//
// Hints:
// - Split the token by "."
// - The header is the first part
// - It's base64url encoded - see the example in README.md
// - Parse as JSON to extract alg and kid
func ParseHeader(tokenString string) (alg string, kid string, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", "", errors.New("invalid token")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", err
	}
	var headerMap map[string]string
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return "", "", err
	}
	alg = headerMap["alg"]
	kid = headerMap["kid"]
	return alg, kid, nil
}

// TODO: Task 4 - Implement IsExpired
//
// IsExpired checks if the token's exp claim is in the past.
// Returns true if expired, false if still valid.
//
// Hints:
// - Decode the payload (second part of the token)
// - The "exp" claim is a Unix timestamp (seconds since epoch)
// - Compare with time.Now().Unix()
// - Consider adding clock skew tolerance (e.g., 30 seconds)
func IsExpired(tokenString string) (bool, error) {
	claims, err := ParseClaims(tokenString)
	if err != nil {
		return false, err
	}
	return time.Now().Unix() > claims.Exp+30, nil // 30 seconds tolerance
}

// TODO: Task 6 - Implement VerifySignature
//
// VerifySignature validates the JWT signature using RSA-SHA256.
// Returns nil if valid, error if invalid or verification fails.
//
// RS256 algorithm steps:
// 1. Take the signed content: base64url(header) + "." + base64url(payload)
// 2. Hash it with SHA-256
// 3. Verify the signature using RSA PKCS1v15
//
// Hints:
// - The signature is the third part of the token, base64url decoded
// - Use crypto/sha256 to hash the signed content
// - Use crypto/rsa.VerifyPKCS1v15 for verification
// - The signed content is the first two parts joined by "."
//
// import (
//
//	"crypto"
//	"crypto/rsa"
//	"crypto/sha256"
//
// )
func VerifySignature(tokenString string, publicKey *rsa.PublicKey) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return errors.New("invalid token")
	}
	content := strings.Join(parts[:2], ".")
	hash := sha256.Sum256([]byte(content))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		return err
	}
	return nil
}
