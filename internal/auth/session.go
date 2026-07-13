package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	SessionCookieName = "ep_admin_session"
	SessionTTL        = 12 * time.Hour
)

type Session struct {
	Token     string
	Key       string
	ExpiresAt time.Time
}

type sessionRecord struct {
	ExpiresAt time.Time
	FamilyKey string
	Active    bool
}

func (c *Checker) createSession() (Session, error) {
	session, err := c.newSession()
	if err != nil {
		return Session{}, err
	}
	c.mu.Lock()
	c.cleanupSessionsLocked(c.currentTime())
	c.sessions[session.Key] = sessionRecord{
		ExpiresAt: session.ExpiresAt,
		FamilyKey: session.Key,
		Active:    true,
	}
	c.mu.Unlock()
	return session, nil
}

func (c *Checker) newSession() (Session, error) {
	token, err := randomURLToken(32)
	if err != nil {
		return Session{}, err
	}
	return Session{
		Token:     token,
		Key:       tokenHash(token),
		ExpiresAt: c.currentTime().Add(SessionTTL),
	}, nil
}

func (c *Checker) replaceAllSessionsWith(session Session, familyKey string) {
	now := c.currentTime()
	c.mu.Lock()
	for key, record := range c.sessions {
		if record.FamilyKey == familyKey {
			if record.ExpiresAt.Before(session.ExpiresAt) {
				record.ExpiresAt = session.ExpiresAt
			}
		} else if !now.Before(record.ExpiresAt) {
			delete(c.sessions, key)
			continue
		}
		record.Active = false
		c.sessions[key] = record
	}
	c.sessions[session.Key] = sessionRecord{
		ExpiresAt: session.ExpiresAt,
		FamilyKey: familyKey,
		Active:    true,
	}
	c.setups = map[string]pendingSetup{}
	c.mu.Unlock()
}

func (c *Checker) Logout(r *http.Request) {
	if c == nil || r == nil {
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return
	}
	key := tokenHash(cookie.Value)
	c.authStateMu.Lock()
	defer c.authStateMu.Unlock()

	c.mu.Lock()
	record, ok := c.sessions[key]
	if !ok || !c.currentTime().Before(record.ExpiresAt) {
		delete(c.sessions, key)
		for setupID, setup := range c.setups {
			if setup.SessionKey == key {
				delete(c.setups, setupID)
			}
		}
		c.mu.Unlock()
		return
	}
	familyKey := record.FamilyKey
	for sessionKey, current := range c.sessions {
		if current.FamilyKey != familyKey {
			continue
		}
		current.Active = false
		c.sessions[sessionKey] = current
	}
	for setupID, setup := range c.setups {
		setupRecord, exists := c.sessions[setup.SessionKey]
		if exists && setupRecord.FamilyKey == familyKey {
			delete(c.setups, setupID)
		}
	}
	c.mu.Unlock()
}

func (c *Checker) checkSession(r *http.Request) Result {
	if c == nil || r == nil {
		return Result{}
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return Result{}
	}
	key := tokenHash(cookie.Value)
	_, ok := c.activeSessionFamily(key)
	if !ok {
		return Result{}
	}
	return Result{OK: true, UID: "admin", Role: "admin", SessionKey: key, AuthMethod: "session"}
}

func (c *Checker) activeSessionFamily(key string) (string, bool) {
	key = strings.TrimSpace(key)
	if c == nil || key == "" {
		return "", false
	}
	now := c.currentTime()
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.sessions[key]
	if ok && !now.Before(record.ExpiresAt) {
		delete(c.sessions, key)
		ok = false
	}
	if now.UnixNano()&63 == 0 {
		c.cleanupSessionsLocked(now)
		c.cleanupSetupsLocked(now)
	}
	if !ok || !record.Active {
		return "", false
	}
	return record.FamilyKey, true
}

func (c *Checker) cleanupSessionsLocked(now time.Time) {
	for key, record := range c.sessions {
		if !now.Before(record.ExpiresAt) {
			delete(c.sessions, key)
		}
	}
}

func SetSessionCookie(w http.ResponseWriter, r *http.Request, session Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    session.Token,
		Path:     "/admin",
		Expires:  session.ExpiresAt,
		MaxAge:   int(SessionTTL / time.Second),
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/admin",
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func requestIsSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(forwarded, "https")
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomURLToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
