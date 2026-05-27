// subgw: V2Board 订阅前置网关
//
// 用法:
//
//	subgw -c /etc/subgw/config.yml
//	subgw hashpwd <password>   # 生成 admin.password_hash 用
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/example/subgw/internal/banlist"
	"github.com/example/subgw/internal/cloudip"
	"github.com/example/subgw/internal/config"
	"github.com/example/subgw/internal/detector"
	"github.com/example/subgw/internal/faker"
	"github.com/example/subgw/internal/notifier"
	"github.com/example/subgw/internal/proxy"
	"github.com/example/subgw/internal/rules"
	"github.com/example/subgw/internal/slidingwin"
	"github.com/example/subgw/internal/store"
	"github.com/example/subgw/internal/token"
	"github.com/example/subgw/internal/webui"
)

var Version = "0.1.0"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "hashpwd":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: subgw hashpwd <password>")
				os.Exit(2)
			}
			h, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), bcrypt.DefaultCost)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			fmt.Println(string(h))
			return
		case "version":
			fmt.Println(Version)
			return
		case "help", "-h", "--help":
			printHelp()
			return
		}
	}

	var cfgPath string
	fs := flag.NewFlagSet("subgw", flag.ExitOnError)
	fs.StringVar(&cfgPath, "c", "/etc/subgw/config.yml", "配置文件路径")
	_ = fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepathDir(cfg.Storage.SQLitePath), 0750); err != nil {
		logger.Error("mkdir storage", "err", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepathDir(cfg.HMACSaltFile), 0750); err != nil {
		logger.Error("mkdir salt dir", "err", err)
		os.Exit(1)
	}

	salt, err := token.LoadOrCreateSalt(cfg.HMACSaltFile)
	if err != nil {
		logger.Error("load salt", "err", err)
		os.Exit(1)
	}
	hasher := token.NewHasher(salt)

	st, err := store.Open(cfg.Storage.SQLitePath, cfg.Storage.BatchFlushInterval.Std(), cfg.Storage.BatchFlushSize)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	bans := banlist.New(st)
	if err := bans.LoadFromStore(context.Background()); err != nil {
		logger.Error("load banlist", "err", err)
		os.Exit(1)
	}

	det, err := detector.New(&cfg.Detector)
	if err != nil {
		logger.Error("init detector", "err", err)
		os.Exit(1)
	}

	stopCh := make(chan struct{})
	slidingwin.RunGC(stopCh, time.Minute, det.GCTargets()...)

	// 云 IP 匹配器 + 后台更新器
	cloudMatcher := cloudip.NewMatcher()
	cloudFetcher := cloudip.NewFetcher(cloudMatcher, st, logger)
	det.SetCloudLookup(cloudMatcher.Match)
	ctxFetch, cancelFetch := context.WithCancel(context.Background())
	cloudFetcher.RunPeriodic(ctxFetch, 7*24*time.Hour)

	// 动态规则(UA 黑/白名单 + IP 白名单)
	rulesMgr := rules.NewManager(st)
	if err := rulesMgr.Reload(); err != nil {
		logger.Error("load dynamic rules", "err", err)
		os.Exit(1)
	}
	det.SetDynamicProviders(
		rulesMgr.UAWhitelisted,
		rulesMgr.UABlacklisted,
		rulesMgr.IPWhitelisted,
	)

	fk := faker.New(cfg.Faker.BlackholeIPs, cfg.Faker.NodeCount)

	notif := notifier.New(cfg.Notifier.Telegram, logger)
	// 启动时把 store.meta 里的 Telegram 配置合并覆盖(Web UI 修改的优先于 yaml)
	applyNotifierMeta(notif, st, cfg, logger)

	autoBan := proxy.AutoBanCfg{
		OnRed:    true,
		IPTTL:    24 * time.Hour,
		TokenTTL: 24 * time.Hour,
	}

	gw, err := proxy.NewGateway(cfg, hasher, st, bans, det, fk, notif, autoBan, logger)
	if err != nil {
		logger.Error("init gateway", "err", err)
		os.Exit(1)
	}

	// 反代 server
	subMux := http.NewServeMux()
	subMux.HandleFunc("/healthz", proxy.Healthz)
	subMux.Handle("/", gw)
	subSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           subMux,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	// admin server
	ui := webui.NewServer(cfg, st, bans, hasher, notif, cloudMatcher, cloudFetcher, rulesMgr, logger)
	adminSrv := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           ui.Handler(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("subscription gateway listening", "addr", cfg.Listen)
		if err := subSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("sub server", "err", err)
			os.Exit(1)
		}
	}()

	go func() {
		logger.Info("admin web UI listening", "addr", cfg.AdminListen)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server", "err", err)
			os.Exit(1)
		}
	}()

	// 定时 vacuum
	go runVacuum(stopCh, st, cfg, logger)

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutdown signal received", "sig", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = subSrv.Shutdown(ctx)
	_ = adminSrv.Shutdown(ctx)
	cancelFetch()
	close(stopCh)
	time.Sleep(200 * time.Millisecond) // 让异步 writer flush
	logger.Info("bye")
}

func runVacuum(stop <-chan struct{}, st *store.Store, cfg *config.Config, logger *slog.Logger) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := st.Vacuum(ctx, cfg.Storage.Retention.Events.Std(), cfg.Storage.Retention.Incidents.Std())
			cancel()
			if err != nil {
				logger.Warn("vacuum failed", "err", err)
			}
		}
	}
}

func filepathDir(p string) string {
	// 极简版 filepath.Dir,避免引入额外包(其实 stdlib 已经有,这里用 stdlib)
	if p == "" {
		return "."
	}
	i := len(p) - 1
	for i >= 0 && p[i] != '/' {
		i--
	}
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func printHelp() {
	fmt.Println(`subgw - V2Board 订阅前置网关

用法:
  subgw -c <config.yml>        启动服务(反代 + Web UI)
  subgw hashpwd <password>     生成 bcrypt 密码哈希(填到 admin.password_hash)
  subgw version                打印版本
  subgw help                   本帮助`)
}

// applyNotifierMeta 把 store.meta 里的 Telegram 配置合并到 notifier 里(meta 覆盖 yaml)
func applyNotifierMeta(notif *notifier.Notifier, st *store.Store, cfg *config.Config, logger *slog.Logger) {
	metas, err := st.AllMeta()
	if err != nil {
		logger.Warn("load meta failed, keep yaml notifier config", "err", err)
		return
	}
	enabled := cfg.Notifier.Telegram.Enabled
	bot := cfg.Notifier.Telegram.BotToken
	chat := cfg.Notifier.Telegram.ChatID
	throttle := cfg.Notifier.Telegram.Throttle.Std()
	if v, ok := metas["tg_enabled"]; ok {
		enabled = v == "true"
	}
	if v, ok := metas["tg_bot_token"]; ok && v != "" {
		bot = v
	}
	if v, ok := metas["tg_chat_id"]; ok && v != "" {
		chat = v
	}
	if v, ok := metas["tg_throttle"]; ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			throttle = d
		}
	}
	notif.Configure(enabled, bot, chat, throttle)
}
