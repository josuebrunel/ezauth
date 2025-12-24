package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/josuebrunel/ezauth/service"
)

type MemoryAdapter struct {
	users              map[string]*service.User
	usersByEmail       map[string]string // email -> id
	sessions           map[string]*service.Session
	accounts           map[string]*service.Account           // key: provider + providerAccountID
	verificationTokens map[string]*service.VerificationToken // key: identifier + token
	mu                 sync.RWMutex
}

func New() *MemoryAdapter {
	return &MemoryAdapter{
		users:              make(map[string]*service.User),
		usersByEmail:       make(map[string]string),
		sessions:           make(map[string]*service.Session),
		accounts:           make(map[string]*service.Account),
		verificationTokens: make(map[string]*service.VerificationToken),
	}
}

// User operations
func (m *MemoryAdapter) CreateUser(ctx context.Context, user *service.User) (*service.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[user.ID]; exists {
		return nil, errors.New("user already exists")
	}
	// copy to avoid reference issues
	u := *user
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	u.UpdatedAt = time.Now()

	m.users[u.ID] = &u
	m.usersByEmail[u.Email] = u.ID
	return &u, nil
}

func (m *MemoryAdapter) GetUser(ctx context.Context, id string) (*service.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, nil // Not found
}

func (m *MemoryAdapter) GetUserByEmail(ctx context.Context, email string) (*service.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if id, ok := m.usersByEmail[email]; ok {
		if u, ok := m.users[id]; ok {
			return u, nil
		}
	}
	return nil, nil
}

func (m *MemoryAdapter) UpdateUser(ctx context.Context, user *service.User) (*service.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[user.ID]; !ok {
		return nil, errors.New("user not found")
	}

	u := *user
	u.UpdatedAt = time.Now()
	m.users[u.ID] = &u
	// Handle email change if needed (not implemented deeply here)
	m.usersByEmail[u.Email] = u.ID

	return &u, nil
}

func (m *MemoryAdapter) DeleteUser(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u, ok := m.users[id]; ok {
		delete(m.usersByEmail, u.Email)
		delete(m.users, id)
	}
	return nil
}

// Session operations
func (m *MemoryAdapter) CreateSession(ctx context.Context, session *service.Session) (*service.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := *session
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	m.sessions[s.Token] = &s
	return &s, nil
}

func (m *MemoryAdapter) GetSession(ctx context.Context, token string) (*service.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if s, ok := m.sessions[token]; ok {
		if time.Now().After(s.ExpiresAt) {
			return nil, nil // Expired
		}
		return s, nil
	}
	return nil, nil
}

func (m *MemoryAdapter) UpdateSession(ctx context.Context, session *service.Session) (*service.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[session.Token]; ok {
		s := *session
		m.sessions[s.Token] = &s
		return &s, nil
	}
	return nil, nil
}

func (m *MemoryAdapter) DeleteSession(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
	return nil
}

func (m *MemoryAdapter) DeleteUserSessions(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for token, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, token)
		}
	}
	return nil
}

// Account operations
func (m *MemoryAdapter) CreateAccount(ctx context.Context, account *service.Account) (*service.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := account.Provider + ":" + account.ProviderAccountID
	a := *account
	a.CreatedAt = time.Now()
	a.UpdatedAt = time.Now()
	m.accounts[key] = &a
	return &a, nil
}

func (m *MemoryAdapter) GetAccount(ctx context.Context, provider, providerAccountID string) (*service.Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := provider + ":" + providerAccountID
	if a, ok := m.accounts[key]; ok {
		return a, nil
	}
	return nil, nil
}

func (m *MemoryAdapter) LinkAccount(ctx context.Context, account *service.Account) error {
	_, err := m.CreateAccount(ctx, account)
	return err
}

// Verification Token
func (m *MemoryAdapter) CreateVerificationToken(ctx context.Context, token *service.VerificationToken) (*service.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := token.Identifier + ":" + token.Token
	t := *token
	t.CreatedAt = time.Now()
	m.verificationTokens[key] = &t
	return &t, nil
}

func (m *MemoryAdapter) GetVerificationToken(ctx context.Context, identifier, token string) (*service.VerificationToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := identifier + ":" + token
	if t, ok := m.verificationTokens[key]; ok {
		if time.Now().After(t.ExpiresAt) {
			return nil, nil // Expired
		}
		return t, nil
	}
	return nil, nil
}

func (m *MemoryAdapter) DeleteVerificationToken(ctx context.Context, identifier, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := identifier + ":" + token
	delete(m.verificationTokens, key)
	return nil
}
