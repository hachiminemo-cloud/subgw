// Package banlist 内存里维护 IP / token_hash 黑名单,启动从 store 加载,运行时增量更新。
package banlist

import (
	"context"
	"sync"
	"time"

	"github.com/example/subgw/internal/store"
)

type entry struct {
	expires time.Time // 零值 = 永久
	reason  string
}

type List struct {
	mu     sync.RWMutex
	ips    map[string]entry
	tokens map[string]entry
	st     *store.Store
}

func New(st *store.Store) *List {
	return &List{
		ips:    map[string]entry{},
		tokens: map[string]entry{},
		st:     st,
	}
}

// LoadFromStore 启动时调用。
func (l *List) LoadFromStore(ctx context.Context) error {
	bans, err := l.st.ListActiveBans(ctx)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range bans {
		e := entry{reason: b.Reason}
		if b.ExpiresTS != nil {
			e.expires = *b.ExpiresTS
		}
		switch b.Kind {
		case "ip":
			l.ips[b.Target] = e
		case "token":
			l.tokens[b.Target] = e
		}
	}
	return nil
}

// CheckIP 检查 IP 是否封禁,返回 (banned, reason)。过期会被惰性清理。
func (l *List) CheckIP(ip string) (bool, string) {
	l.mu.RLock()
	e, ok := l.ips[ip]
	l.mu.RUnlock()
	return l.check(ok, e, func() {
		l.mu.Lock()
		delete(l.ips, ip)
		l.mu.Unlock()
	})
}

func (l *List) CheckToken(tokenHash string) (bool, string) {
	if tokenHash == "" {
		return false, ""
	}
	l.mu.RLock()
	e, ok := l.tokens[tokenHash]
	l.mu.RUnlock()
	return l.check(ok, e, func() {
		l.mu.Lock()
		delete(l.tokens, tokenHash)
		l.mu.Unlock()
	})
}

func (l *List) check(ok bool, e entry, expire func()) (bool, string) {
	if !ok {
		return false, ""
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		expire()
		return false, ""
	}
	return true, e.reason
}

// AddIP 立即在内存生效并落库。
func (l *List) AddIP(ip, reason string, ttl time.Duration, ruleTags []string, createdBy string) error {
	return l.add("ip", ip, reason, ttl, ruleTags, createdBy)
}

func (l *List) AddToken(tokenHash, reason string, ttl time.Duration, ruleTags []string, createdBy string) error {
	return l.add("token", tokenHash, reason, ttl, ruleTags, createdBy)
}

func (l *List) add(kind, target, reason string, ttl time.Duration, ruleTags []string, createdBy string) error {
	now := time.Now()
	e := entry{reason: reason}
	var expPtr *time.Time
	if ttl > 0 {
		e.expires = now.Add(ttl)
		expPtr = &e.expires
	}
	l.mu.Lock()
	switch kind {
	case "ip":
		l.ips[target] = e
	case "token":
		l.tokens[target] = e
	}
	l.mu.Unlock()
	return l.st.AddBan(store.Ban{
		Kind:      kind,
		Target:    target,
		Reason:    reason,
		RuleTags:  ruleTags,
		CreatedTS: now,
		ExpiresTS: expPtr,
		CreatedBy: createdBy,
	})
}

func (l *List) RemoveIP(ip string) error {
	l.mu.Lock()
	delete(l.ips, ip)
	l.mu.Unlock()
	return l.st.RemoveBan("ip", ip)
}

func (l *List) RemoveToken(tokenHash string) error {
	l.mu.Lock()
	delete(l.tokens, tokenHash)
	l.mu.Unlock()
	return l.st.RemoveBan("token", tokenHash)
}

// Snapshot 给 webui 用。
type Entry struct {
	Kind    string    `json:"kind"`
	Target  string    `json:"target"`
	Reason  string    `json:"reason"`
	Expires time.Time `json:"expires"`
}

func (l *List) Snapshot() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.ips)+len(l.tokens))
	for k, e := range l.ips {
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "ip", Target: k, Reason: e.reason, Expires: e.expires})
	}
	for k, e := range l.tokens {
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "token", Target: k, Reason: e.reason, Expires: e.expires})
	}
	return out
}
