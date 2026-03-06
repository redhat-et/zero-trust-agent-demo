package parser

import (
	"testing"
)

func TestParseJSONLogs(t *testing.T) {
	lines := []struct {
		line string
		wantType EventType
		wantNil  bool
	}{
		{`{"time":"2026-03-05T18:36:43Z","level":"INFO","msg":"User initiating delegation","component":"USER-SERVICE","user":"Bob"}`, EventDelegation, false},
		{`{"time":"2026-03-05T18:36:43Z","level":"INFO","msg":"-> Delegating to Agent Service","component":"USER-SERVICE"}`, EventFlow, false},
		{`{"time":"2026-03-05T18:36:43Z","level":"INFO","msg":"✅ ALLOW: Both user and agent have required access (delegation)","component":"DOC-SERVICE"}`, EventAccessDecision, false},
		{`{"time":"2026-03-05T18:36:43Z","level":"INFO","msg":"📄 [DOC-002] Returning document content","component":"DOC-SERVICE"}`, EventDocumentFetch, false},
		{`{"time":"2026-03-05T18:36:59Z","level":"INFO","msg":"Registered discovered agent","component":"AGENT-SERVICE"}`, EventUnknown, false},
		{`{"time":"2026-03-05T18:36:59Z","level":"INFO","msg":"Discovering A2A agent","component":"AGENT-SERVICE"}`, EventA2AInvoke, false},
		{`{"time":"2026-03-05T18:36:59Z","level":"INFO","msg":"","component":"AGENT-SERVICE"}`, EventUnknown, true},
	}

	for i, tt := range lines {
		ev := ParseServiceLog(tt.line, "test")
		if tt.wantNil {
			if ev != nil {
				t.Errorf("case %d: expected nil, got %s", i, ev.Type)
			}
			continue
		}
		if ev == nil {
			t.Errorf("case %d: got nil, want %s", i, tt.wantType)
			continue
		}
		if ev.Type != tt.wantType {
			t.Errorf("case %d: got type %s, want %s (msg=%q)", i, ev.Type, tt.wantType, ev.Message)
		}
	}
}
