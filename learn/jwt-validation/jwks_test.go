package main

import (
	"testing"
)

func TestFetchJWKS(t *testing.T) {
	jwks, err := FetchJWKS("http://localhost:8080/realms/demo/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("Failed to fetch JWKS: %v", err)
	}
	if len(jwks) == 0 {
		t.Fatalf("No public keys found")
	}
	for kid, publicKey := range jwks {
		t.Logf("Kid: %s, Public Key N: %v", kid, publicKey.N.String())
	}
}
