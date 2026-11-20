// Command vpnctl is the operator CLI: it initializes server and client
// configs (generating keys through wgtypes — never custom crypto), renders
// wg-quick-compatible client files, and registers peers against the admin API.
//
// vpnctl never mutates local network state; it only reads/writes files and
// (optionally) calls the REST API.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/auth"
	"github.com/devansh1012007/VPN_GOlang/internal/config"
	"github.com/devansh1012007/VPN_GOlang/internal/version"
	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

const usage = `vpnctl — VPN platform operator CLI

Usage:
  vpnctl init-server [flags]        create a server config with fresh keys + admin token
  vpnctl init-client [flags]         create a client keypair and wg-quick config
  vpnctl register [flags]            register a client peer on a server via the admin API
  vpnctl show [flags]                print a client config (safe: shows private key only to the owner's terminal)
  vpnctl version                     print build info

Environment:
  VPND_TOKEN   admin token (alternative to --token-file)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init-server":
		err = cmdInitServer(os.Args[2:])
	case "init-client":
		err = cmdInitClient(os.Args[2:])
	case "register":
		err = cmdRegister(os.Args[2:])
	case "show":
		err = cmdShow(os.Args[2:])
	case "version":
		fmt.Println("vpnctl", version.String())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnctl:", err)
		os.Exit(1)
	}
}

// ---- init-server ----

func cmdInitServer(args []string) error {
	fs := flag.NewFlagSet("init-server", flag.ExitOnError)
	out := fs.String("output", "/etc/vpnd/server.json", "server config path")
	network_ := fs.String("network", "10.100.0.0/24", "VPN subnet (CIDR)")
	iface := fs.String("interface", "wg0", "WireGuard interface name")
	port := fs.Int("listen-port", 51820, "UDP listen port")
	tokenPath := fs.String("token-path", "/etc/vpnd/token", "admin token file path")
	storePath := fs.String("store", "/var/lib/vpnd/peers.json", "peer store path")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s exists (use -force to overwrite)", *out)
		}
	}

	priv, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	token, err := auth.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	if err := auth.SaveToken(*tokenPath, token); err != nil {
		return fmt.Errorf("save token: %w", err)
	}

	cfg := config.DefaultServer()
	cfg.Interface.Name = *iface
	cfg.Interface.PrivateKey = priv
	cfg.Interface.ListenPort = *port
	cfg.Network.Address = *network_
	cfg.Store.Path = *storePath
	cfg.API.TokenPath = *tokenPath
	if err := config.Save(*out, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	pub, err := wireguard.PublicKeyOf(priv)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	fmt.Printf("server config written: %s\n", *out)
	fmt.Printf("admin token written:  %s (mode 0600)\n", *tokenPath)
	fmt.Printf("server public key:     %s\n", pub)
	fmt.Printf("next: vpnd --config %s --dry-run   (plan only, no changes)\n", *out)
	return nil
}

// ---- init-client ----

func cmdInitClient(args []string) error {
	fs := flag.NewFlagSet("init-client", flag.ExitOnError)
	out := fs.String("output", "vpn-client.conf", "client config path (wg-quick compatible)")
	name := fs.String("name", "", "peer name (required)")
	server := fs.String("server-endpoint", "", "server address[:port] (e.g. 203.0.113.7:51820)")
	serverKey := fs.String("server-public-key", "", "server public key (required)")
	serverVPNIP := fs.String("server-vpn-ip", "10.100.0.1", "server address inside the VPN")
	routes := fs.String("allowed-ips", "0.0.0.0/0", "AllowedIPs for the client (default all traffic)")
	force := fs.Bool("force", false, "overwrite existing file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *server == "" || *serverKey == "" {
		return fmt.Errorf("--name, --server-endpoint and --server-public-key are required")
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s exists (use -force to overwrite)", *out)
		}
	}

	priv, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}
	pub, err := wireguard.PublicKeyOf(priv)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "# generated by vpnctl at %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\n", priv)
	fmt.Fprintf(&b, "# PublicKey = %s (share this with the server operator)\n", pub)
	fmt.Fprintf(&b, "# server VPN address: %s (use as Address after registration)\n", *serverVPNIP)
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", *serverKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", serverKeyEndpoint(*server))
	fmt.Fprintf(&b, "AllowedIPs = %s\n", *routes)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	if err := os.WriteFile(*out, b.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("client config written: %s (mode 0600)\n", *out)
	fmt.Printf("client public key:     %s\n", pub)
	fmt.Printf("register with:\n  vpnctl register --api http://127.0.0.1:8080 --name %q --public-key %s\n", *name, pub)
	return nil
}

// serverKeyEndpoint defaults the port to 51820 when the operator omitted it.
func serverKeyEndpoint(s string) string {
	if strings.Contains(s, ":") {
		return s
	}
	return s + ":51820"
}

// ---- register ----

func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	api := fs.String("api", "http://127.0.0.1:8080", "admin API base URL")
	name := fs.String("name", "", "peer name (required)")
	pub := fs.String("public-key", "", "client public key (required)")
	tokenFile := fs.String("token-file", "", "path to admin token file (or set VPND_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *pub == "" {
		return fmt.Errorf("--name and --public-key are required")
	}
	token := os.Getenv("VPND_TOKEN")
	if token == "" && *tokenFile != "" {
		t, err := auth.LoadToken(*tokenFile)
		if err != nil {
			return fmt.Errorf("load token: %w", err)
		}
		token = t
	}
	if token == "" {
		return fmt.Errorf("no token: set VPND_TOKEN or pass --token-file")
	}

	body := map[string]string{"name": *name, "public_key": *pub}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimRight(*api, "/") + "/api/v1/peers"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("call API: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusCreated {
		return fmt.Errorf("API answered %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var peer struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal(raw, &peer); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("peer registered: id=%s address=%s\n", peer.ID, peer.Address)
	fmt.Printf("add to the client config: Address = %s\n", strings.Split(peer.Address, "/")[0])
	return nil
}

// ---- show ----

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	file := fs.String("file", "", "client config file (wg-quick format)")
	redact := fs.Bool("redact", false, "redact the private key in output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("--file is required")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if *redact {
		out := string(data)
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "PrivateKey = ") {
				out = strings.Replace(out, line, "PrivateKey = REDACTED", 1)
			}
		}
		fmt.Print(out)
		return nil
	}
	fmt.Print(string(data))
	return nil
}
