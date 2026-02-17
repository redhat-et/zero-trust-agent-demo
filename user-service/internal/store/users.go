package store

import "strings"

// User represents a user in the system
type User struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Departments []string `json:"departments"`
	SPIFFEID    string   `json:"spiffe_id"`
}

// UserStore is an in-memory user store
type UserStore struct {
	users map[string]*User
}

// NewUserStore creates a new user store with sample users
func NewUserStore(trustDomain string) *UserStore {
	store := &UserStore{
		users: make(map[string]*User),
	}
	store.loadSampleUsers(trustDomain)
	return store
}

func (s *UserStore) loadSampleUsers(trustDomain string) {
	// Users as defined in the design document
	s.users["alice"] = &User{
		ID:          "alice",
		Name:        "Alice",
		Departments: []string{"engineering", "finance"},
		SPIFFEID:    "spiffe://" + trustDomain + "/user/alice",
	}

	s.users["bob"] = &User{
		ID:          "bob",
		Name:        "Bob",
		Departments: []string{"finance", "admin"},
		SPIFFEID:    "spiffe://" + trustDomain + "/user/bob",
	}

	s.users["carol"] = &User{
		ID:          "carol",
		Name:        "Carol",
		Departments: []string{"hr"},
		SPIFFEID:    "spiffe://" + trustDomain + "/user/carol",
	}
}

// Get retrieves a user by ID
func (s *UserStore) Get(id string) (*User, bool) {
	user, ok := s.users[id]
	return user, ok
}

// GetOrCreate retrieves a user by ID, or creates a dynamic user if not found.
// This supports users defined externally (e.g., in Keycloak) without requiring
// hardcoded entries. The dynamic user gets a deterministic SPIFFE ID and no
// hardcoded departments — authorization relies on JWT claims from the IdP.
func (s *UserStore) GetOrCreate(id, trustDomain string) *User {
	if user, ok := s.users[id]; ok {
		return user
	}
	return &User{
		ID:          id,
		Name:        strings.Title(id), //nolint:staticcheck // simple title-casing for display
		Departments: nil,
		SPIFFEID:    "spiffe://" + trustDomain + "/user/" + id,
	}
}

// List returns all users
func (s *UserStore) List() []*User {
	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users
}

// GetIDs returns all user IDs
func (s *UserStore) GetIDs() []string {
	ids := make([]string, 0, len(s.users))
	for id := range s.users {
		ids = append(ids, id)
	}
	return ids
}
