// Command bridge runs the Tangled <-> Graft bridge: it mirrors Graft issue
// notes to Tangled issues (auto-creating the repo on first use), and new
// comments on those Tangled issues back to Graft as ActivityPub replies.
package main

import (
	"context"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"flag"

	"grafttangled/internal/ap"
	"grafttangled/internal/appviewdb"
	"grafttangled/internal/bridge"
	"grafttangled/internal/config"
	"grafttangled/internal/graft"
	"grafttangled/internal/netguard"
	"grafttangled/internal/state"
	"grafttangled/internal/tangled"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to the JSON config file")
	once := flag.Bool("once", false, "run a single pass and exit")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	st, err := state.Load(cfg.StateFile)
	if err != nil {
		log.Error("load state", "err", err)
		os.Exit(1)
	}

	actor, priv, err := ensureActor(cfg, st)
	if err != nil {
		log.Error("ensure actor", "err", err)
		os.Exit(1)
	}
	signFn := func(req *http.Request, body []byte) error {
		return ap.SignRequest(req, body, actor.KeyID(), priv)
	}

	// Graft is reached over the public internet, same reasoning as
	// graft-discourse: no private addresses, HTTPS only.
	graftPolicy := netguard.Options{AllowPrivate: false, AllowHTTP: false}
	graftHost := hostOf(cfg.Graft.BaseURL)
	gc := graft.New(graft.Config{
		BaseURL:  cfg.Graft.BaseURL,
		ActorURL: actor.ActorURL(),
		KeyID:    actor.KeyID(),
		HTTP:     graftPolicy.Client(),
		Sign:     signFn,
		Validate: graftPolicy.Validate,
	})

	appPassword, err := config.ReadToken(cfg.Tangled.AppPasswordFile)
	if err != nil {
		log.Error("read tangled app password", "err", err)
		os.Exit(1)
	}
	tc := tangled.New(tangled.Config{PDSBaseURL: cfg.Tangled.PDSBaseURL, Handle: cfg.Tangled.Handle})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := tc.Login(ctx, appPassword); err != nil {
		log.Error("tangled login", "err", err)
		os.Exit(1)
	}
	log.Info("logged in to tangled pds", "handle", cfg.Tangled.Handle, "did", tc.DID())

	adb, err := appviewdb.Open(cfg.Tangled.AppviewDBPath)
	if err != nil {
		log.Error("open appview db", "err", err)
		os.Exit(1)
	}
	defer adb.Close()

	series := make([]bridge.SeriesConfig, 0, len(cfg.Graft.Series))
	seriesNames := make([]string, 0, len(cfg.Graft.Series))
	for _, s := range cfg.Graft.Series {
		series = append(series, bridge.SeriesConfig{
			Series: s.Series, Knot: s.Knot, Source: s.Source, Description: s.Description,
		})
		seriesNames = append(seriesNames, s.Series)
	}

	b := &bridge.Bridge{
		GraftHost:         graftHost,
		Series:            series,
		TangledWebBaseURL: cfg.Tangled.WebBaseURL,
		TangledHandle:     cfg.Tangled.Handle,
		Opts: bridge.Options{
			MaxContentRunes:      cfg.MaxContentRunes,
			MaxDeliveriesPerPass: cfg.MaxDeliveriesPerPass,
		},
		Graft:     gc,
		Tangled:   tc,
		AppviewDB: adb,
		State:     st,
		Log:       log,
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           newMux(actor),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	go func() {
		log.Info("serving bridge actor", "listen", cfg.Listen, "actor", actor.ActorURL())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("actor server", "err", err)
		}
	}()

	runPass := func() {
		pctx, cancel := context.WithTimeout(ctx, cfg.PassTimeout.D())
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				log.Error("sync pass panicked", "panic", r)
			}
		}()
		if err := b.RunOnce(pctx); err != nil {
			log.Error("sync pass", "err", err)
		}
	}

	if *once {
		runPass()
		shutdown(srv, log)
		return
	}

	interval := cfg.PollInterval.D()
	log.Info("bridge started", "interval", interval.String(), "series", strings.Join(seriesNames, ","))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		runPass()
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			shutdown(srv, log)
			return
		case <-ticker.C:
		}
	}
}

func shutdown(srv *http.Server, log *slog.Logger) {
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(cctx); err != nil {
		log.Error("actor server shutdown", "err", err)
	}
}

func ensureActor(cfg *config.Config, st *state.State) (*ap.ActorServer, *rsa.PrivateKey, error) {
	kp, ok := st.KeyPair(cfg.ActorName)
	if !ok {
		privPEM, pubPEM, err := ap.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		kp = state.KeyPair{PrivatePEM: privPEM, PublicPEM: pubPEM}
		if err := st.SetKeyPair(cfg.ActorName, kp); err != nil {
			return nil, nil, err
		}
	}
	priv, err := ap.ParsePrivateKey(kp.PrivatePEM)
	if err != nil {
		return nil, nil, err
	}
	actor := &ap.ActorServer{
		BaseURL:   strings.TrimRight(cfg.PublicBaseURL, "/"),
		Name:      cfg.ActorName,
		PublicPEM: kp.PublicPEM,
		RepoURL:   cfg.RepoURL,
	}
	return actor, priv, nil
}

func newMux(actor *ap.ActorServer) http.Handler {
	mux := http.NewServeMux()
	actor.Register(mux)
	return mux
}

func hostOf(base string) string {
	s := base
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
