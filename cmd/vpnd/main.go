// Command vpnd is the VPN server daemon: it loads the config, applies the
// desired network state, and serves the admin REST API until SIGTERM.
//
// Privilege note (ADR-006): mutating operations need CAP_NET_ADMIN. This
// binary never shells out; all mutations go through wgctrl/netlink/iptables
// with absolute semantics.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/api"
	"github.com/devansh1012007/VPN_GOlang/internal/auth"
	"github.com/devansh1012007/VPN_GOlang/internal/config"
	"github.com/devansh1012007/VPN_GOlang/internal/logging"
	"github.com/devansh1012007/VPN_GOlang/internal/network"
	"github.com/devansh1012007/VPN_GOlang/internal/server"
	"github.com/devansh1012007/VPN_GOlang/internal/store"
	"github.com/devansh1012007/VPN_GOlang/internal/version"
	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

func main() {
	var (
		cfgPath     = flag.String("config", "/etc/vpnd/server.json", "path to server config JSON")
		logLevel    = flag.String("log-level", "info", "debug|info|warn|error")
		dryRun      = flag.Bool("dry-run", false, "print the plan (firewall rules, link, peers) and exit without mutating anything")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	lvl, err := logging.ParseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	log := logging.Stderr(lvl)
	logging.SetDefault(log)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "path", *cfgPath, "err", err.Error())
		os.Exit(1)
	}
	log.Info("config loaded", "path", *cfgPath, "interface", cfg.Interface.Name)

	if *dryRun {
		if err := dryRunPlan(cfg, log); err != nil {
			log.Error("dry run", "err", err.Error())
			os.Exit(1)
		}
		return
	}

	// real collaborators (the only place where netlink/iptables are touched)
	devMgr, err := wireguard.NewManager()
	if err != nil {
		log.Error("wgctrl", "err", err.Error())
		os.Exit(1)
	}
	defer devMgr.Close()

	peerStore, err := store.NewFileStore(cfg.Store.Path)
	if err != nil {
		log.Error("peer store", "err", err.Error())
		os.Exit(1)
	}

	srv, err := server.New(cfg, peerStore, server.Options{
		Logger:   log,
		Devices:  devMgr,
		Links:    network.NewNetlinkLinkManager(),
		FwRunner: execIptables{},
		Sysctl:   &network.Sysctl{},
	})
	if err != nil {
		log.Error("orchestrator", "err", err.Error())
		os.Exit(1)
	}

	if err := srv.Apply(); err != nil {
		log.Error("apply desired state", "err", err.Error())
		os.Exit(1)
	}
	log.Info("desired state applied",
		"interface", cfg.Interface.Name, "subnet", cfg.Network.Address)

	// admin API
	var apiServer *api.Server
	if cfg.API.Enabled {
		token, err := auth.LoadToken(cfg.API.TokenPath)
		if err != nil {
			log.Error("load api token", "path", cfg.API.TokenPath, "err", err.Error())
			os.Exit(1)
		}
		authn, err := auth.NewTokenAuthenticator(token)
		if err != nil {
			log.Error("authenticator", "err", err.Error())
			os.Exit(1)
		}
		readT, writeT, idleT := cfg.API.Timeouts()
		apiServer, err = api.NewServer(api.ServerConfig{
			Addr:          fmt.Sprintf("%s:%d", cfg.API.ListenAddress, cfg.API.ListenPort),
			Authenticator: authn,
			Backend:       srv,
			ReadTimeout:   readT,
			WriteTimeout:  writeT,
			IdleTimeout:   idleT,
			Logger:        log,
		})
		if err != nil {
			log.Error("api server", "err", err.Error())
			os.Exit(1)
		}
		go func() {
			if err := apiServer.Start(); err != nil {
				log.Error("api serve", "err", err.Error())
			}
		}()
	}

	// signal handling: SIGHUP → reload+reapply; SIGTERM/SIGINT → teardown.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			log.Info("reload requested")
			// config reload + re-apply desired state (peers unchanged in
			// store; only config-derived settings re-derive)
			if err := srv.Apply(); err != nil {
				log.Error("reapply", "err", err.Error())
			}
		case syscall.SIGINT, syscall.SIGTERM:
			log.Info("shutting down", "signal", sig.String())
			if apiServer != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := apiServer.Shutdown(ctx); err != nil {
					log.Warn("api shutdown", "err", err.Error())
				}
				cancel()
			}
			if err := srv.TearDown(); err != nil {
				log.Error("teardown", "err", err.Error())
				os.Exit(1)
			}
			log.Info("stopped")
			return
		}
	}
}

// dryRunPlan prints what Apply would do — zero mutation (runbook §provision).
func dryRunPlan(cfg *config.Server, log *logging.Logger) error {
	fmt.Println("== vpnd dry run (no changes will be made) ==")
	fmt.Printf("interface:  %s (listen UDP/%d, mtu %d)\n",
		cfg.Interface.Name, cfg.Interface.ListenPort, cfg.Network.MTU)
	fmt.Printf("vpn subnet: %s (server address %s)\n",
		cfg.Network.Address, cfg.ServerIP().String())
	fmt.Printf("forwarding: sysctl net/ipv4/ip_forward=1\n")
	if cfg.Firewall.Enabled {
		fw, err := network.NewFirewall(network.FirewallSpec{
			Interface:    cfg.Interface.Name,
			Subnet:       cfg.Network.Address,
			EgressIfaces: cfg.Network.AllowedEgress,
			ServerIP:     cfg.ServerIP().String(),
			ChainTag:     cfg.Firewall.ChainTag,
		}, denyRunner{})
		if err != nil {
			return err
		}
		fmt.Println("firewall rules (iptables):")
		for _, r := range fw.Render() {
			fmt.Println("  " + r)
		}
	}
	peers, err := store.NewFileStore(cfg.Store.Path)
	if err != nil {
		return err
	}
	list, err := peers.List()
	if err != nil {
		return fmt.Errorf("read peer store: %w", err)
	}
	fmt.Printf("peers:      %d registered\n", len(list))
	for i, p := range list {
		fmt.Printf("  #%d %s %s %s\n", i+1, p.ID, p.Name, p.Address)
	}
	return nil
}

// denyRunner refuses to run anything: dry-run must never mutate (ADR-006).
type denyRunner struct{}

func (denyRunner) Run(name string, args ...string) error {
	return fmt.Errorf("dry run: refusing to execute %s", name)
}

// execIptables runs the real iptables binary with a fixed absolute path
// (no PATH lookups — ADR-006 "no shell-outs" applies to interpreters; iptables
// itself is the documented firewall backend and is invoked with absolute
// path and fixed argv).
type execIptables struct{}

func (execIptables) Run(name string, args ...string) error {
	if name != "iptables" {
		return fmt.Errorf("unexpected runner target %q", name)
	}
	return runCommand("/usr/sbin/iptables", args...)
}

// runCommand executes an absolute-path binary with fixed argv (no shell, no
// PATH lookup — ADR-006). Output is captured for error reporting.
func runCommand(path string, args ...string) error {
	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", path, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
