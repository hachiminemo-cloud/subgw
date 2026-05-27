// Package notifier 走 Telegram Bot API 发告警。
//
// 设计:Notifier 一定存在(从不返回 nil),配置可热更新。
// 启动时用 config.yml 的初值,运行时 Web UI 修改后持久化到 store.meta,下次启动自动加载。
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/example/subgw/internal/config"
)

type Notifier struct {
	mu       sync.RWMutex
	enabled  bool
	botToken string
	chatID   string
	throttle time.Duration

	sentMu   sync.Mutex
	lastSent map[string]time.Time

	hc     *http.Client
	logger *slog.Logger
}

func New(cfg config.TelegramCfg, logger *slog.Logger) *Notifier {
	return &Notifier{
		enabled:  cfg.Enabled,
		botToken: cfg.BotToken,
		chatID:   cfg.ChatID,
		throttle: cfg.Throttle.Std(),
		lastSent: map[string]time.Time{},
		hc:       &http.Client{Timeout: 8 * time.Second},
		logger:   logger,
	}
}

// Configure 原子更新配置(线程安全,可热生效)。
func (n *Notifier) Configure(enabled bool, botToken, chatID string, throttle time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.enabled = enabled
	n.botToken = botToken
	n.chatID = chatID
	n.throttle = throttle
}

// Snapshot 当前配置(给 Web UI 回显用)。
func (n *Notifier) Snapshot() (enabled bool, botToken, chatID string, throttle time.Duration) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.enabled, n.botToken, n.chatID, n.throttle
}

// IsEnabled 快速判断。
func (n *Notifier) IsEnabled() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.enabled
}

// NotifyBan 封禁事件。
func (n *Notifier) NotifyBan(tenant, ip, tokenHash string, tags []string, note string) {
	if !n.IsEnabled() {
		return
	}
	key := "ban:" + tenant + ":" + ip
	if !n.allow(key) {
		return
	}
	msg := fmt.Sprintf("🚨 *自动封禁*\ntenant: `%s`\nip: `%s`\ntoken: `%s`\ntags: %s\nnote: %s",
		escape(tenant), escape(ip), escape(tokenHashShort(tokenHash)), escape(strings.Join(tags, ",")), escape(note))
	n.send(msg)
}

// NotifyIncident 普通命中(频率高建议关掉)
func (n *Notifier) NotifyIncident(tenant, severity, ip, tokenHash string, tags []string) {
	if !n.IsEnabled() {
		return
	}
	key := "incident:" + tenant + ":" + severity + ":" + ip
	if !n.allow(key) {
		return
	}
	msg := fmt.Sprintf("⚠️ *%s* tenant=`%s` ip=`%s` token=`%s` tags=%s",
		escape(severity), escape(tenant), escape(ip), escape(tokenHashShort(tokenHash)), escape(strings.Join(tags, ",")))
	n.send(msg)
}

// NotifyTest 测试连通性
func (n *Notifier) NotifyTest() error {
	if !n.IsEnabled() {
		return fmt.Errorf("telegram disabled")
	}
	return n.sendErr("✅ subgw 网关启动通知测试")
}

func (n *Notifier) allow(key string) bool {
	n.mu.RLock()
	throttle := n.throttle
	n.mu.RUnlock()
	if throttle <= 0 {
		return true
	}
	n.sentMu.Lock()
	defer n.sentMu.Unlock()
	now := time.Now()
	if last, ok := n.lastSent[key]; ok && now.Sub(last) < throttle {
		return false
	}
	n.lastSent[key] = now
	for k, t := range n.lastSent {
		if now.Sub(t) > 24*time.Hour {
			delete(n.lastSent, k)
		}
	}
	return true
}

func (n *Notifier) send(msg string) {
	if err := n.sendErr(msg); err != nil {
		n.logger.Warn("telegram send failed", "err", err)
	}
}

func (n *Notifier) sendErr(msg string) error {
	n.mu.RLock()
	bot := n.botToken
	chat := n.chatID
	n.mu.RUnlock()
	if bot == "" || chat == "" {
		return fmt.Errorf("telegram bot_token / chat_id not configured")
	}
	url := "https://api.telegram.org/bot" + bot + "/sendMessage"
	body, _ := json.Marshal(map[string]any{
		"chat_id":    chat,
		"text":       msg,
		"parse_mode": "MarkdownV2",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		buf := make([]byte, 512)
		nb, _ := resp.Body.Read(buf)
		return fmt.Errorf("telegram %d: %s", resp.StatusCode, string(buf[:nb]))
	}
	return nil
}

// MarkdownV2 转义
func escape(s string) string {
	specials := []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!", "\\"}
	for _, c := range specials {
		s = strings.ReplaceAll(s, c, "\\"+c)
	}
	return s
}

func tokenHashShort(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}
