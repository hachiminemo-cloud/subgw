// Package store 提供 SQLite 持久化:events / incidents / bans。
// 写入是异步的:外部调用 Submit*() 入 channel,后台 goroutine 批量落盘。
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    tenant      TEXT NOT NULL,
    client_ip   TEXT NOT NULL,
    ua          TEXT,
    token_hash  TEXT,
    flag        TEXT,
    path        TEXT,
    status      INTEGER,
    action      TEXT,
    rule_tags   TEXT,
    upstream_ms INTEGER,
    resp_size   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_ts          ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_token       ON events(token_hash, ts);
CREATE INDEX IF NOT EXISTS idx_events_ip          ON events(client_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_action_ts   ON events(action, ts);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts   ON events(tenant, ts);

CREATE TABLE IF NOT EXISTS bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    target     TEXT NOT NULL,
    reason     TEXT,
    rule_tags  TEXT,
    created_ts INTEGER NOT NULL,
    expires_ts INTEGER,
    created_by TEXT,
    UNIQUE(kind, target)
);
CREATE INDEX IF NOT EXISTS idx_bans_target ON bans(kind, target);
CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_ts);

CREATE TABLE IF NOT EXISTS incidents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    tenant     TEXT,
    severity   TEXT,
    client_ip  TEXT,
    token_hash TEXT,
    rule_tags  TEXT,
    action     TEXT,
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(ts);
CREATE INDEX IF NOT EXISTS idx_incidents_severity_ts ON incidents(severity, ts);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);

CREATE TABLE IF NOT EXISTS cloud_cidrs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr       TEXT NOT NULL,
    provider   TEXT NOT NULL,
    updated_ts INTEGER NOT NULL,
    UNIQUE(cidr)
);
CREATE INDEX IF NOT EXISTS idx_cloud_provider ON cloud_cidrs(provider);

CREATE TABLE IF NOT EXISTS ua_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,         -- 'blacklist' | 'whitelist'
    pattern    TEXT NOT NULL,         -- 正则(black) 或 前缀(white)
    note       TEXT,
    created_ts INTEGER NOT NULL,
    UNIQUE(kind, pattern)
);
CREATE INDEX IF NOT EXISTS idx_ua_kind ON ua_rules(kind);

CREATE TABLE IF NOT EXISTS ip_whitelist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL UNIQUE,  -- IP 或 CIDR
    note       TEXT,
    created_ts INTEGER NOT NULL
);
`

// Event 一行请求记录。
type Event struct {
	TS         time.Time
	Tenant     string
	ClientIP   string
	UA         string
	TokenHash  string
	Flag       string
	Path       string
	Status     int
	Action     string
	RuleTags   []string
	UpstreamMS int64
	RespSize   int64
}

// Incident 命中规则的事件。
type Incident struct {
	TS        time.Time
	Tenant    string
	Severity  string
	ClientIP  string
	TokenHash string
	RuleTags  []string
	Action    string
	Note      string
}

// Ban 封禁记录。
type Ban struct {
	ID        int64
	Kind      string // "ip" | "token"
	Target    string
	Reason    string
	RuleTags  []string
	CreatedTS time.Time
	ExpiresTS *time.Time
	CreatedBy string
}

type Store struct {
	db *sql.DB

	eventCh    chan Event
	incidentCh chan Incident
	flushSize  int
	flushEvery time.Duration

	wg     sync.WaitGroup
	stopCh chan struct{}
}

func Open(path string, flushEvery time.Duration, flushSize int) (*Store, error) {
	// 启用 WAL,journal_mode 必须在 connect 后设置一次
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	// modernc 不支持并行写,单 writer 串行化
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	s := &Store{
		db:         db,
		eventCh:    make(chan Event, 1024),
		incidentCh: make(chan Incident, 256),
		flushSize:  flushSize,
		flushEvery: flushEvery,
		stopCh:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *Store) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	return s.db.Close()
}

// ----- 异步入队 -----

func (s *Store) SubmitEvent(e Event) {
	select {
	case s.eventCh <- e:
	default:
		// channel 满了直接丢,避免阻塞主路径。
	}
}

func (s *Store) SubmitIncident(in Incident) {
	select {
	case s.incidentCh <- in:
	default:
	}
}

// ----- 后台写 -----

func (s *Store) writer() {
	defer s.wg.Done()
	t := time.NewTicker(s.flushEvery)
	defer t.Stop()
	var (
		events    []Event
		incidents []Incident
	)
	flush := func() {
		if len(events) > 0 {
			if err := s.insertEvents(events); err != nil {
				// 不让一次失败导致丢全量,这里只能丢日志
				fmt.Printf("store: insert events failed: %v\n", err)
			}
			events = events[:0]
		}
		if len(incidents) > 0 {
			if err := s.insertIncidents(incidents); err != nil {
				fmt.Printf("store: insert incidents failed: %v\n", err)
			}
			incidents = incidents[:0]
		}
	}
	for {
		select {
		case e := <-s.eventCh:
			events = append(events, e)
			if len(events) >= s.flushSize {
				flush()
			}
		case in := <-s.incidentCh:
			incidents = append(incidents, in)
			if len(incidents) >= s.flushSize {
				flush()
			}
		case <-t.C:
			flush()
		case <-s.stopCh:
			// 排空再退出
			for {
				select {
				case e := <-s.eventCh:
					events = append(events, e)
				case in := <-s.incidentCh:
					incidents = append(incidents, in)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *Store) insertEvents(es []Event) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO events
        (ts,tenant,client_ip,ua,token_hash,flag,path,status,action,rule_tags,upstream_ms,resp_size)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range es {
		tags, _ := json.Marshal(e.RuleTags)
		if _, err := stmt.Exec(
			e.TS.UnixMilli(), e.Tenant, e.ClientIP, e.UA, e.TokenHash, e.Flag,
			e.Path, e.Status, e.Action, string(tags), e.UpstreamMS, e.RespSize,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) insertIncidents(ins []Incident) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO incidents
        (ts,tenant,severity,client_ip,token_hash,rule_tags,action,note)
        VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, in := range ins {
		tags, _ := json.Marshal(in.RuleTags)
		if _, err := stmt.Exec(
			in.TS.UnixMilli(), in.Tenant, in.Severity, in.ClientIP, in.TokenHash,
			string(tags), in.Action, in.Note,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ----- bans 同步 API -----

func (s *Store) AddBan(b Ban) error {
	if b.Kind != "ip" && b.Kind != "token" {
		return errors.New("ban kind must be ip|token")
	}
	tags, _ := json.Marshal(b.RuleTags)
	var exp interface{}
	if b.ExpiresTS != nil {
		exp = b.ExpiresTS.UnixMilli()
	}
	_, err := s.db.Exec(`INSERT INTO bans (kind,target,reason,rule_tags,created_ts,expires_ts,created_by)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(kind,target) DO UPDATE SET
		  reason=excluded.reason,
		  rule_tags=excluded.rule_tags,
		  created_ts=excluded.created_ts,
		  expires_ts=excluded.expires_ts,
		  created_by=excluded.created_by`,
		b.Kind, b.Target, b.Reason, string(tags), b.CreatedTS.UnixMilli(), exp, b.CreatedBy)
	return err
}

func (s *Store) RemoveBan(kind, target string) error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE kind=? AND target=?`, kind, target)
	return err
}

func (s *Store) ListActiveBans(ctx context.Context) ([]Ban, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,kind,target,reason,rule_tags,created_ts,expires_ts,created_by
		 FROM bans
		 WHERE expires_ts IS NULL OR expires_ts > ?
		 ORDER BY created_ts DESC`, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var tags sql.NullString
		var exp sql.NullInt64
		var reason, createdBy sql.NullString
		var createdMs int64
		if err := rows.Scan(&b.ID, &b.Kind, &b.Target, &reason, &tags, &createdMs, &exp, &createdBy); err != nil {
			return nil, err
		}
		b.CreatedTS = time.UnixMilli(createdMs)
		if tags.Valid {
			_ = json.Unmarshal([]byte(tags.String), &b.RuleTags)
		}
		if exp.Valid {
			t := time.UnixMilli(exp.Int64)
			b.ExpiresTS = &t
		}
		b.Reason = reason.String
		b.CreatedBy = createdBy.String
		out = append(out, b)
	}
	return out, rows.Err()
}

// ----- 查询 API(给 Web UI) -----

type EventFilter struct {
	Tenant    string
	ClientIP  string
	TokenHash string
	Action    string
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

func (s *Store) QueryEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	q := `SELECT ts,tenant,client_ip,ua,token_hash,flag,path,status,action,rule_tags,upstream_ms,resp_size
		FROM events WHERE 1=1`
	args := []any{}
	if f.Tenant != "" {
		q += " AND tenant=?"
		args = append(args, f.Tenant)
	}
	if f.ClientIP != "" {
		q += " AND client_ip=?"
		args = append(args, f.ClientIP)
	}
	if f.TokenHash != "" {
		q += " AND token_hash=?"
		args = append(args, f.TokenHash)
	}
	if f.Action != "" {
		q += " AND action=?"
		args = append(args, f.Action)
	}
	if !f.Since.IsZero() {
		q += " AND ts>=?"
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		q += " AND ts<=?"
		args = append(args, f.Until.UnixMilli())
	}
	q += " ORDER BY ts DESC"
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		var tags sql.NullString
		var ua, tokenHash, flag, path, action sql.NullString
		if err := rows.Scan(&ts, &e.Tenant, &e.ClientIP, &ua, &tokenHash, &flag,
			&path, &e.Status, &action, &tags, &e.UpstreamMS, &e.RespSize); err != nil {
			return nil, err
		}
		e.TS = time.UnixMilli(ts)
		e.UA = ua.String
		e.TokenHash = tokenHash.String
		e.Flag = flag.String
		e.Path = path.String
		e.Action = action.String
		if tags.Valid {
			_ = json.Unmarshal([]byte(tags.String), &e.RuleTags)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type IncidentFilter struct {
	Tenant   string
	Severity string
	Since    time.Time
	Limit    int
	Offset   int
}

func (s *Store) QueryIncidents(ctx context.Context, f IncidentFilter) ([]Incident, error) {
	q := `SELECT ts,tenant,severity,client_ip,token_hash,rule_tags,action,note FROM incidents WHERE 1=1`
	args := []any{}
	if f.Tenant != "" {
		q += " AND tenant=?"
		args = append(args, f.Tenant)
	}
	if f.Severity != "" {
		q += " AND severity=?"
		args = append(args, f.Severity)
	}
	if !f.Since.IsZero() {
		q += " AND ts>=?"
		args = append(args, f.Since.UnixMilli())
	}
	q += " ORDER BY ts DESC"
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		var ts int64
		var tags, tenant, severity, clientIP, tokenHash, action, note sql.NullString
		if err := rows.Scan(&ts, &tenant, &severity, &clientIP, &tokenHash, &tags, &action, &note); err != nil {
			return nil, err
		}
		in.TS = time.UnixMilli(ts)
		in.Tenant = tenant.String
		in.Severity = severity.String
		in.ClientIP = clientIP.String
		in.TokenHash = tokenHash.String
		in.Action = action.String
		in.Note = note.String
		if tags.Valid {
			_ = json.Unmarshal([]byte(tags.String), &in.RuleTags)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// Stats 概要统计(过去 window 内)
type Stats struct {
	TotalEvents     int64            `json:"total_events"`
	PassCount       int64            `json:"pass"`
	SlowCount       int64            `json:"slow"`
	FakeCount       int64            `json:"fake"`
	DenyCount       int64            `json:"deny"`
	UniqueIPs       int64            `json:"unique_ips"`
	UniqueTokens    int64            `json:"unique_tokens"`
	TopIPs          []KeyCount       `json:"top_ips"`
	TopTokens       []KeyCount       `json:"top_tokens"`
	IncidentByLevel map[string]int64 `json:"incident_by_level"`
}

type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

func (s *Store) Summary(ctx context.Context, tenant string, since time.Time) (*Stats, error) {
	out := &Stats{IncidentByLevel: map[string]int64{}}
	args := []any{since.UnixMilli()}
	tenantClause := ""
	if tenant != "" {
		tenantClause = " AND tenant=?"
		args = append(args, tenant)
	}
	// 总数
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM events WHERE ts>=?"+tenantClause, args...).Scan(&out.TotalEvents); err != nil {
		return nil, err
	}
	// 按 action 拆
	rows, err := s.db.QueryContext(ctx,
		"SELECT action,COUNT(*) FROM events WHERE ts>=?"+tenantClause+" GROUP BY action", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a string
		var n int64
		if err := rows.Scan(&a, &n); err != nil {
			rows.Close()
			return nil, err
		}
		switch a {
		case "pass":
			out.PassCount = n
		case "slow":
			out.SlowCount = n
		case "fake":
			out.FakeCount = n
		case "deny":
			out.DenyCount = n
		}
	}
	rows.Close()
	// unique
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT client_ip) FROM events WHERE ts>=?"+tenantClause, args...).Scan(&out.UniqueIPs); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT token_hash) FROM events WHERE ts>=? AND token_hash<>''"+tenantClause, args...).Scan(&out.UniqueTokens); err != nil {
		return nil, err
	}
	// top ips
	rows, err = s.db.QueryContext(ctx,
		"SELECT client_ip,COUNT(*) c FROM events WHERE ts>=?"+tenantClause+
			" GROUP BY client_ip ORDER BY c DESC LIMIT 10", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k KeyCount
		if err := rows.Scan(&k.Key, &k.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.TopIPs = append(out.TopIPs, k)
	}
	rows.Close()
	// top tokens
	rows, err = s.db.QueryContext(ctx,
		"SELECT token_hash,COUNT(*) c FROM events WHERE ts>=? AND token_hash<>''"+tenantClause+
			" GROUP BY token_hash ORDER BY c DESC LIMIT 10", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k KeyCount
		if err := rows.Scan(&k.Key, &k.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.TopTokens = append(out.TopTokens, k)
	}
	rows.Close()
	// incident by level
	rows, err = s.db.QueryContext(ctx,
		"SELECT severity,COUNT(*) FROM incidents WHERE ts>=?"+tenantClause+" GROUP BY severity", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out.IncidentByLevel[sev] = n
	}
	rows.Close()
	return out, nil
}

// Retention 清理
func (s *Store) Vacuum(ctx context.Context, eventsRetention, incidentsRetention time.Duration) error {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM events WHERE ts<?", now.Add(-eventsRetention).UnixMilli()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM incidents WHERE ts<?", now.Add(-incidentsRetention).UnixMilli()); err != nil {
		return err
	}
	// 只删过期超过 7 天的 bans,保留近期作为审计
	cutoff := now.Add(-7 * 24 * time.Hour).UnixMilli()
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM bans WHERE expires_ts IS NOT NULL AND expires_ts<?", cutoff); err != nil {
		return err
	}
	return nil
}

// ----- meta key/value -----

// SetMeta upsert.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO meta (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		key, value)
	return err
}

// GetMeta 不存在返回 ("", nil)
func (s *Store) GetMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) DeleteMeta(key string) error {
	_, err := s.db.Exec(`DELETE FROM meta WHERE k=?`, key)
	return err
}

// AllMeta 一次返回所有 k/v
func (s *Store) AllMeta() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT k,v FROM meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ----- cloud_cidrs -----

type CloudCIDR struct {
	CIDR      string
	Provider  string
	UpdatedTS time.Time
}

// ReplaceCloudCIDRs 原子替换。如果传入空切片,清空表。
func (s *Store) ReplaceCloudCIDRs(items []CloudCIDR) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM cloud_cidrs`); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO cloud_cidrs (cidr,provider,updated_ts) VALUES (?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, it := range items {
		if _, err := stmt.Exec(it.CIDR, it.Provider, it.UpdatedTS.UnixMilli()); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListCloudCIDRs() ([]CloudCIDR, error) {
	rows, err := s.db.Query(`SELECT cidr,provider,updated_ts FROM cloud_cidrs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudCIDR
	for rows.Next() {
		var c CloudCIDR
		var ts int64
		if err := rows.Scan(&c.CIDR, &c.Provider, &ts); err != nil {
			return nil, err
		}
		c.UpdatedTS = time.UnixMilli(ts)
		out = append(out, c)
	}
	return out, rows.Err()
}

// CloudStats 返回 provider → count + 最新更新时间
func (s *Store) CloudStats() (map[string]int, time.Time, error) {
	rows, err := s.db.Query(`SELECT provider, COUNT(*), MAX(updated_ts) FROM cloud_cidrs GROUP BY provider`)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()
	out := map[string]int{}
	var maxTS int64
	for rows.Next() {
		var p string
		var n int
		var ts int64
		if err := rows.Scan(&p, &n, &ts); err != nil {
			return nil, time.Time{}, err
		}
		out[p] = n
		if ts > maxTS {
			maxTS = ts
		}
	}
	var t time.Time
	if maxTS > 0 {
		t = time.UnixMilli(maxTS)
	}
	return out, t, rows.Err()
}

// ----- ua_rules -----

type UARule struct {
	ID        int64
	Kind      string // blacklist|whitelist
	Pattern   string
	Note      string
	CreatedTS time.Time
}

func (s *Store) AddUARule(r UARule) error {
	if r.Kind != "blacklist" && r.Kind != "whitelist" {
		return errors.New("kind must be blacklist|whitelist")
	}
	_, err := s.db.Exec(
		`INSERT INTO ua_rules (kind,pattern,note,created_ts) VALUES (?,?,?,?)
		 ON CONFLICT(kind,pattern) DO UPDATE SET note=excluded.note`,
		r.Kind, r.Pattern, r.Note, time.Now().UnixMilli())
	return err
}

func (s *Store) DeleteUARule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ua_rules WHERE id=?`, id)
	return err
}

func (s *Store) ListUARules(kind string) ([]UARule, error) {
	q := `SELECT id,kind,pattern,COALESCE(note,''),created_ts FROM ua_rules`
	args := []any{}
	if kind != "" {
		q += ` WHERE kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UARule
	for rows.Next() {
		var r UARule
		var ts int64
		if err := rows.Scan(&r.ID, &r.Kind, &r.Pattern, &r.Note, &ts); err != nil {
			return nil, err
		}
		r.CreatedTS = time.UnixMilli(ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ----- ip_whitelist -----

type IPWhitelistEntry struct {
	ID        int64
	Target    string // IP 或 CIDR
	Note      string
	CreatedTS time.Time
}

func (s *Store) AddIPWhitelist(target, note string) error {
	_, err := s.db.Exec(
		`INSERT INTO ip_whitelist (target,note,created_ts) VALUES (?,?,?)
		 ON CONFLICT(target) DO UPDATE SET note=excluded.note`,
		target, note, time.Now().UnixMilli())
	return err
}

func (s *Store) DeleteIPWhitelist(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ip_whitelist WHERE id=?`, id)
	return err
}

func (s *Store) ListIPWhitelist() ([]IPWhitelistEntry, error) {
	rows, err := s.db.Query(
		`SELECT id,target,COALESCE(note,''),created_ts FROM ip_whitelist ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPWhitelistEntry
	for rows.Next() {
		var e IPWhitelistEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Target, &e.Note, &ts); err != nil {
			return nil, err
		}
		e.CreatedTS = time.UnixMilli(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
