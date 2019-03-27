package acl

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// HostPattern is a pattern for matching against IPs or host names.
// Two patterns are supported:
// - CIDRs (e.g. "192.168.0.0/16")
// - Host names (e.g. "google.com") are matched exactly
type HostPattern struct {
	v interface{}
}

func (h *HostPattern) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return err
		}
		h.v = ipNet
	} else {
		h.v = s
	}
	return nil
}

func (h *HostPattern) String() string {
	switch v := h.v.(type) {
	case *net.IPNet:
		return v.String()
	case string:
		return v
	default:
		return ""
	}
}

// Match return true if the given host name/IP matches the pattern
func (h *HostPattern) Match(host string) bool {
	switch v := h.v.(type) {
	case *net.IPNet:
		return v.Contains(net.ParseIP(host))
	case string:
		return host == v
	default:
		return false
	}
}

// Rule associates a set of groups with a set of host patterns
// such that any user belonging to any of the groups is allowed
// to connect to hosts matching any of the host patterns.
type Rule struct {
	Groups       []string      `json:"groups"`
	HostPatterns []HostPattern `json:"host_patterns"`
}

// BcryptPassword is bcrypt hash of a plain text password
type BcryptPassword []byte

func (p *BcryptPassword) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = []byte(v)
	return nil
}

// Verify returns true of the given plain text password has
// the same hash as the BcryptPassword.
func (p *BcryptPassword) Verify(password []byte) bool {
	return bcrypt.CompareHashAndPassword(*p, password) == nil
}

// PublicKey represents the public part of private/public key pair
type PublicKey struct {
	ssh.PublicKey
}

func (k *PublicKey) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v))
	if err != nil {
		return err
	}
	k.PublicKey = pk
	return nil
}

// User represents a user and their associated groups, public keys
// and passwords.
type User struct {
	Groups    []string         `json:"groups"`
	Keys      []*PublicKey     `json:"keys"`
	Passwords []BcryptPassword `json:"passwords"`
}

// ACL is a set of rules and associations that define
// which users are allowed to connect to which hosts.
type ACL struct {
	mu    sync.Mutex
	Rules map[string]Rule `json:"rules"`
	Users map[string]User `json:"users"`
}

// Load replaces the current ACL with one from the given JSON file.
// If an error occurs, the existing ACL is not replaced.
func (a *ACL) Load(r io.Reader) error {
	newACL := ACL{}
	if err := json.NewDecoder(r).Decode(&newACL); err != nil {
		return err
	}
	a.mu.Lock()
	a.Users = newACL.Users
	a.Rules = newACL.Rules
	a.mu.Unlock()
	return nil
}

// IsValidPassword returns true if a matching user and password is found.
func (a *ACL) IsValidPassword(user string, password []byte) bool {
	a.mu.Lock()
	users := a.Users
	a.mu.Unlock()

	u, ok := users[user]
	if !ok {
		return false
	}
	for _, p := range u.Passwords {
		if p.Verify(password) {
			return true
		}
	}
	return false
}

// IsValidKey returns true if a matching user and key is found.
func (a *ACL) IsValidKey(user string, key ssh.PublicKey) bool {
	a.mu.Lock()
	users := a.Users
	a.mu.Unlock()

	u, ok := users[user]
	if !ok {
		return false
	}
	for _, k := range u.Keys {
		if k.Type() == key.Type() && subtle.ConstantTimeCompare(k.Marshal(), key.Marshal()) == 1 {
			return true
		}
	}
	return false
}

// IsAllowedHostAccess returns true if user is allowed to connect to host.
func (a *ACL) IsAllowedHostAccess(user, host string) bool {
	a.mu.Lock()
	users := a.Users
	rules := a.Rules
	a.mu.Unlock()

	ugroups := users[user].Groups
	for _, r := range rules {
		// TODO this runs in O(n*m) - can use some speed up
		for _, rg := range r.Groups {
			for _, ug := range ugroups {
				if ug == rg {
					goto MatchedRuleGroup
				}
			}
		}
		continue

	MatchedRuleGroup:
		for _, hp := range r.HostPatterns {
			if hp.Match(host) {
				return true
			}
		}
	}

	return false
}
