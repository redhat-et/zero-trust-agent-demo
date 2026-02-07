package main

import (
	"testing"
	"time"
)

func TestParseClaims(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	token := NewTokenBuilder(t, keyPair).
		WithSubject("alice").
		WithAzp("agent-gpt4").
		WithAudience("document-service").
		WithGroups("engineering", "finance").
		WithIssuer("http://keycloak.example.com/realms/demo").
		Build()

	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims failed: %v", err)
	}

	if claims.Sub != "alice" {
		t.Errorf("Expected sub=alice, got %s", claims.Sub)
	}
	if claims.Azp != "agent-gpt4" {
		t.Errorf("Expected azp=agent-gpt4, got %s", claims.Azp)
	}
	if len(claims.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(claims.Groups))
	}
}

func TestDetectDelegation_Delegated(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	// Delegated access: user alice, agent gpt4
	token := NewTokenBuilder(t, keyPair).
		Delegated("alice", "spiffe://demo/agent/gpt4").
		WithGroups("engineering", "finance").
		Build()

	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims failed: %v", err)
	}

	delegation := DetectDelegation(claims)
	if delegation == nil {
		t.Fatal("Expected delegation to be detected, got nil")
	}
	if delegation.UserID != "alice" {
		t.Errorf("Expected UserID=alice, got %s", delegation.UserID)
	}
	if delegation.AgentID != "spiffe://demo/agent/gpt4" {
		t.Errorf("Expected AgentID=spiffe://demo/agent/gpt4, got %s", delegation.AgentID)
	}
	if len(delegation.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(delegation.Groups))
	}
}

func TestDetectDelegation_Direct(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	// Direct access: sub == azp (service account)
	token := NewTokenBuilder(t, keyPair).
		Direct("spiffe://demo/service/document-service").
		Build()

	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims failed: %v", err)
	}

	delegation := DetectDelegation(claims)
	if delegation != nil {
		t.Errorf("Expected no delegation for direct access, got %+v", delegation)
	}
}

func TestIsExpired_ValidToken(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	token := NewTokenBuilder(t, keyPair).
		ExpiresIn(time.Hour).
		Build()

	expired, err := IsExpired(token)
	if err != nil {
		t.Fatalf("IsExpired failed: %v", err)
	}
	if expired {
		t.Error("Expected token to be valid, got expired")
	}
}

func TestIsExpired_ExpiredToken(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	token := NewTokenBuilder(t, keyPair).
		Expired().
		Build()

	expired, err := IsExpired(token)
	if err != nil {
		t.Fatalf("IsExpired failed: %v", err)
	}
	if !expired {
		t.Error("Expected token to be expired, got valid")
	}
}

func TestIsExpired_WithinClockSkew(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	// Token expired 15 seconds ago - within 30s clock skew tolerance
	token := NewTokenBuilder(t, keyPair).
		WithExpiration(time.Now().Add(-15 * time.Second)).
		Build()

	expired, err := IsExpired(token)
	if err != nil {
		t.Fatalf("IsExpired failed: %v", err)
	}
	if expired {
		t.Error("Expected token within clock skew to be valid")
	}
}

func TestVerifySignature_ValidSignature(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	token := NewTokenBuilder(t, keyPair).Build()

	err := VerifySignature(token, keyPair.PublicKey)
	if err != nil {
		t.Errorf("Expected valid signature, got error: %v", err)
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	keyPair1 := GenerateTestKeyPair(t, "key1")
	keyPair2 := GenerateTestKeyPair(t, "key2")

	// Sign with key1, verify with key2
	token := NewTokenBuilder(t, keyPair1).Build()

	err := VerifySignature(token, keyPair2.PublicKey)
	if err == nil {
		t.Error("Expected signature verification to fail with wrong key")
	}
}

func TestVerifySignature_TamperedToken(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	token := NewTokenBuilder(t, keyPair).
		WithSubject("alice").
		Build()

	// Tamper with the token (change a character in the payload)
	tampered := token[:50] + "X" + token[51:]

	err := VerifySignature(tampered, keyPair.PublicKey)
	if err == nil {
		t.Error("Expected signature verification to fail for tampered token")
	}
}

func TestAudienceUnmarshal_String(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	token := NewTokenBuilder(t, keyPair).
		WithAudience("single-audience").
		Build()

	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims failed: %v", err)
	}

	if len(claims.Aud) != 1 || claims.Aud[0] != "single-audience" {
		t.Errorf("Expected single audience, got %v", claims.Aud)
	}
}

func TestAudienceUnmarshal_Array(t *testing.T) {
	keyPair := GenerateTestKeyPair(t, "test-kid")

	token := NewTokenBuilder(t, keyPair).
		WithAudience("aud1", "aud2", "aud3").
		Build()

	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims failed: %v", err)
	}

	if len(claims.Aud) != 3 {
		t.Errorf("Expected 3 audiences, got %d", len(claims.Aud))
	}
}
