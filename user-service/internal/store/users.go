package store

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
