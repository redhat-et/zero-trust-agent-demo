package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseHeader(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpNEhJYWtaTjkyZHYzREhVQ1Q4NHNucGx6c2hoejAtQlNUamtyam1leXd3In0.eyJleHAiOjE3NzAxODExOTcsImlhdCI6MTc3MDE4MDg5NywianRpIjoidHJydGNjOjYxYmI0MGJjLTM0ODktOWZlNS1kYTEwLTUxM2ZiNDlmNGRjZCIsImlzcyI6Imh0dHA6Ly9rZXljbG9hay5sb2NhbHRlc3QubWU6ODA4MC9yZWFsbXMvZGVtbyIsImF1ZCI6InNwaWZmZTovL2xvY2FsdGVzdC5tZS9ucy9hdXRoYnJpZGdlL3NhL2FnZW50Iiwic3ViIjoiMzhlYjI5ZjEtMGYzZS00NTIzLTg4ODQtOTgzMzczZTQ5NzllIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJhY3IiOiIxIiwic2NvcGUiOiJlbWFpbCBhZ2VudC1zcGlmZmUtYXVkIHByb2ZpbGUiLCJjbGllbnRIb3N0IjoiMTI3LjAuMC4xIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtc3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJjbGllbnRBZGRyZXNzIjoiMTI3LjAuMC4xIiwiY2xpZW50X2lkIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQifQ.umNBELXXbGyOh_6Brm3YKreJ4x-Uyzw5qO1CV1IKnuZi32_N5Bi7iYKhLAhqxnWkPEf0kZ1meYQ1ipLOxRoZHhYR9Qdg-amcWQX6Ez-ZePWalhuKNTedilj4yW6LIxVI_cRSAaJtWrcUnibIUWgwGTP9cymF_ourwwzfSXiGorDcNjL-O_tdU-aMa1CeKp8OZeG6MjHb9-aZ2TLYLPEHo0gqEqbt85mzNv7T73-McyEeQ4K4tSP-Aj0RuJMWvPhPTyJFIuJaebQg9m-yn3k5RTmHHh51iJ4ryA--4T8zWue9VA58wB6cc4EsR2mG4gNKO8eejw7A7vjzk-DNkOi-xQ"
	alg, kid, err := ParseHeader(token)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if alg != "RS256" {
		t.Fatalf("Expected alg to be RS256, got %s", alg)
	}
	if kid != "i4HIakZN92dv3DHUCT84snplzshhz0-BSTjkrjmeyww" {
		t.Fatalf("Expected kid to be i4HIakZN92dv3DHUCT84snplzshhz0-BSTjkrjmeyww, got %s", kid)
	}
}

func TestWrongNumberOfParts(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpNEhJYWtaTjkyZHYzREhVQ1Q4NHNucGx6c2hoejAtQlNUamtyam1leXd3In0eyJleHAiOjE3NzAxODExOTcsImlhdCI6MTc3MDE4MDg5NywianRpIjoidHJydGNjOjYxYmI0MGJjLTM0ODktOWZlNS1kYTEwLTUxM2ZiNDlmNGRjZCIsImlzcyI6Imh0dHA6Ly9rZXljbG9hay5sb2NhbHRlc3QubWU6ODA4MC9yZWFsbXMvZGVtbyIsImF1ZCI6InNwaWZmZTovL2xvY2FsdGVzdC5tZS9ucy9hdXRoYnJpZGdlL3NhL2FnZW50Iiwic3ViIjoiMzhlYjI5ZjEtMGYzZS00NTIzLTg4ODQtOTgzMzczZTQ5NzllIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJhY3IiOiIxIiwic2NvcGUiOiJlbWFpbCBhZ2VudC1zcGlmZmUtYXVkIHByb2ZpbGUiLCJjbGllbnRIb3N0IjoiMTI3LjAuMC4xIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtc3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJjbGllbnRBZGRyZXNzIjoiMTI3LjAuMC4xIiwiY2xpZW50X2lkIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQifQ.umNBELXXbGyOh_6Brm3YKreJ4x-Uyzw5qO1CV1IKnuZi32_N5Bi7iYKhLAhqxnWkPEf0kZ1meYQ1ipLOxRoZHhYR9Qdg-amcWQX6Ez-ZePWalhuKNTedilj4yW6LIxVI_cRSAaJtWrcUnibIUWgwGTP9cymF_ourwwzfSXiGorDcNjL-O_tdU-aMa1CeKp8OZeG6MjHb9-aZ2TLYLPEHo0gqEqbt85mzNv7T73-McyEeQ4K4tSP-Aj0RuJMWvPhPTyJFIuJaebQg9m-yn3k5RTmHHh51iJ4ryA--4T8zWue9VA58wB6cc4EsR2mG4gNKO8eejw7A7vjzk-DNkOi-xQ"
	alg, kid, err := ParseHeader(token)
	if err == nil {
		t.Fatalf("Expected error, got %s and %s", alg, kid)
	}
}

func TestBadBase64(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpNEhJYWtaTjkyZHYzREhVQ1Q4NHNucGx6c2hoejAtQlNUamtyam1leXd3In0XXX.eyJleHAiOjE3NzAxODExOTcsImlhdCI6MTc3MDE4MDg5NywianRpIjoidHJydGNjOjYxYmI0MGJjLTM0ODktOWZlNS1kYTEwLTUxM2ZiNDlmNGRjZCIsImlzcyI6Imh0dHA6Ly9rZXljbG9hay5sb2NhbHRlc3QubWU6ODA4MC9yZWFsbXMvZGVtbyIsImF1ZCI6InNwaWZmZTovL2xvY2FsdGVzdC5tZS9ucy9hdXRoYnJpZGdlL3NhL2FnZW50Iiwic3ViIjoiMzhlYjI5ZjEtMGYzZS00NTIzLTg4ODQtOTgzMzczZTQ5NzllIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJhY3IiOiIxIiwic2NvcGUiOiJlbWFpbCBhZ2VudC1zcGlmZmUtYXVkIHByb2ZpbGUiLCJjbGllbnRIb3N0IjoiMTI3LjAuMC4xIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtc3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJjbGllbnRBZGRyZXNzIjoiMTI3LjAuMC4xIiwiY2xpZW50X2lkIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQifQ.umNBELXXbGyOh_6Brm3YKreJ4x-Uyzw5qO1CV1IKnuZi32_N5Bi7iYKhLAhqxnWkPEf0kZ1meYQ1ipLOxRoZHhYR9Qdg-amcWQX6Ez-ZePWalhuKNTedilj4yW6LIxVI_cRSAaJtWrcUnibIUWgwGTP9cymF_ourwwzfSXiGorDcNjL-O_tdU-aMa1CeKp8OZeG6MjHb9-aZ2TLYLPEHo0gqEqbt85mzNv7T73-McyEeQ4K4tSP-Aj0RuJMWvPhPTyJFIuJaebQg9m-yn3k5RTmHHh51iJ4ryA--4T8zWue9VA58wB6cc4EsR2mG4gNKO8eejw7A7vjzk-DNkOi-xQ"
	alg, kid, err := ParseHeader(token)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
	if alg != "" {
		t.Fatalf("Expected alg to be empty, got %s", alg)
	}
	if kid != "" {
		t.Fatalf("Expected kid to be empty, got %s", kid)
	}
}

func TestIsExpired(t *testing.T) {
	token := generateExpiredToken()
	expired, err := IsExpired(token)
	if err != nil {
		t.Fatalf("IsExpired failed: %v", err)
	}
	if !expired {
		t.Fatalf("Expected token to be expired, got %t", expired)
	}
}

func TestVerifySignature(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpNEhJYWtaTjkyZHYzREhVQ1Q4NHNucGx6c2hoejAtQlNUamtyam1leXd3In0.eyJleHAiOjE3NzAxODExOTcsImlhdCI6MTc3MDE4MDg5NywianRpIjoidHJydGNjOjYxYmI0MGJjLTM0ODktOWZlNS1kYTEwLTUxM2ZiNDlmNGRjZCIsImlzcyI6Imh0dHA6Ly9rZXljbG9hay5sb2NhbHRlc3QubWU6ODA4MC9yZWFsbXMvZGVtbyIsImF1ZCI6InNwaWZmZTovL2xvY2FsdGVzdC5tZS9ucy9hdXRoYnJpZGdlL3NhL2FnZW50Iiwic3ViIjoiMzhlYjI5ZjEtMGYzZS00NTIzLTg4ODQtOTgzMzczZTQ5NzllIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJhY3IiOiIxIiwic2NvcGUiOiJlbWFpbCBhZ2VudC1zcGlmZmUtYXVkIHByb2ZpbGUiLCJjbGllbnRIb3N0IjoiMTI3LjAuMC4xIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtc3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQiLCJjbGllbnRBZGRyZXNzIjoiMTI3LjAuMC4xIiwiY2xpZW50X2lkIjoic3BpZmZlOi8vbG9jYWx0ZXN0Lm1lL25zL2F1dGhicmlkZ2Uvc2EvYWdlbnQifQ.umNBELXXbGyOh_6Brm3YKreJ4x-Uyzw5qO1CV1IKnuZi32_N5Bi7iYKhLAhqxnWkPEf0kZ1meYQ1ipLOxRoZHhYR9Qdg-amcWQX6Ez-ZePWalhuKNTedilj4yW6LIxVI_cRSAaJtWrcUnibIUWgwGTP9cymF_ourwwzfSXiGorDcNjL-O_tdU-aMa1CeKp8OZeG6MjHb9-aZ2TLYLPEHo0gqEqbt85mzNv7T73-McyEeQ4K4tSP-Aj0RuJMWvPhPTyJFIuJaebQg9m-yn3k5RTmHHh51iJ4ryA--4T8zWue9VA58wB6cc4EsR2mG4gNKO8eejw7A7vjzk-DNkOi-xQ"
	jwks, err := FetchJWKS("http://localhost:8080/realms/demo/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("Failed to fetch JWKS: %v", err)
	}
	publicKey, ok := jwks["i4HIakZN92dv3DHUCT84snplzshhz0-BSTjkrjmeyww"]
	if !ok {
		t.Fatalf("Public key not found for kid: %s", "i4HIakZN92dv3DHUCT84snplzshhz0-BSTjkrjmeyww")
	}
	err = VerifySignature(token, publicKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
}

func generateExpiredToken() string {
	var token *jwt.Token
	var jwtKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour * 24)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Subject:   "1234567890",
	}
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}
	return tokenString
}
