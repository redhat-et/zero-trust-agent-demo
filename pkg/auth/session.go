package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session represents an authenticated user session
type Session struct {
	ID        string
	Username  string
	Name      string
	Email     string
	Groups    []string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SessionStore manages user sessions
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewSessionStore creates a new session store with the given TTL
func NewSessionStore(ttl time.Duration) *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
	go store.cleanup()
	return store
}

// Create creates a new session
func (s *SessionStore) Create(username, name, email string, groups []string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateSessionID()
	session := &Session{
		ID:        id,
		Username:  username,
		Name:      name,
		Email:     email,
		Groups:    groups,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.ttl),
	}
	s.sessions[id] = session
	return session
}

// Get retrieves a session by ID, returns nil if not found or expired
func (s *SessionStore) Get(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[id]
	if !ok || time.Now().After(session.ExpiresAt) {
		return nil
	}
	return session
}

// Delete removes a session
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// cleanup periodically removes expired sessions
func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		s.mu.Lock()
		for id, session := range s.sessions {
			if time.Now().After(session.ExpiresAt) {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// StateStore manages OAuth state parameters
type StateStore struct {
	mu     sync.RWMutex
	states map[string]time.Time
}

// NewStateStore creates a new state store
func NewStateStore() *StateStore {
	store := &StateStore{
		states: make(map[string]time.Time),
	}
	go store.cleanup()
	return store
}

// GenerateState generates and stores a new state
func (s *StateStore) GenerateState() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	state := generateSessionID()
	s.states[state] = time.Now().Add(10 * time.Minute)
	return state
}

// Validate checks if a state is valid and removes it
func (s *StateStore) Validate(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, ok := s.states[state]
	if !ok {
		return false
	}
	delete(s.states, state)
	return time.Now().Before(expiry)
}

func (s *StateStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		s.mu.Lock()
		for state, expiry := range s.states {
			if time.Now().After(expiry) {
				delete(s.states, state)
			}
		}
		s.mu.Unlock()
	}
}
