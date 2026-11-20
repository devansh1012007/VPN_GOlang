// Gated integration test for live WireGuard + firewall paths.
//
// These tests MUTATE network state on the host running them. They are hard-
// gated behind RUN_INTEGRATION=1 (AGENTS.md rule 5) and additionally check
// that the environment actually has the wireguard kernel module and
// iptables; otherwise they skip with an explicit message.
package integration

import (
        "os"
        "os/exec"
        "strings"
        "testing"
)

func integrationAllowed(t *testing.T) bool {
        t.Helper()
        if os.Getenv("RUN_INTEGRATION") != "1" {
                t.Skip("integration test: set RUN_INTEGRATION=1 on a disposable VM")
                return false
        }
        if _, err := exec.LookPath("iptables"); err != nil {
                t.Skip("iptables not present on this host")
        }
        return true
}

func TestWireGuardKernelModuleOrUserspace(t *testing.T) {
        if !integrationAllowed(t) {
                return
        }
        if _, err := os.Stat("/sys/module/wireguard"); err != nil {
                if _, err2 := exec.LookPath("wireguard-go"); err2 != nil {
                        t.Fatalf("neither kernel module nor wireguard-go userspace found: %v", err)
                } else {
                        t.Log("using wireguard-go userspace implementation")
                }
        } else {
                t.Log("kernel WireGuard module present")
        }
}

func TestIPTablesBackendAvailable(t *testing.T) {
        if !integrationAllowed(t) {
                return
        }
        out, err := exec.Command("iptables", "--version").CombinedOutput()
        if err != nil {
                t.Fatalf("iptables --version: %v: %s", err, out)
        }
        t.Logf("iptables backend: %s", out)
}

// TestVpndDryRunIsMutationFree runs the real binary's --dry-run and asserts
// it exits zero WITHOUT creating any link or rule. This runs even without
// RUN_INTEGRATION because dry-run never mutates — it validates constraint #2
// mechanically.
func TestVpndDryRunIsMutationFree(t *testing.T) {
        if _, err := exec.LookPath("go"); err != nil {
                t.Skip("go toolchain needed to build the binary")
        }
        bin := t.TempDir() + "/vpnd"
        out, err := exec.Command("go", "build", "-o", bin,
                "github.com/devansh1012007/VPN_GOlang/cmd/vpnd").CombinedOutput()
        if err != nil {
                t.Fatalf("build vpnd: %v: %s", err, out)
        }
        ctl := t.TempDir() + "/vpnctl"
        out, err = exec.Command("go", "build", "-o", ctl,
                "github.com/devansh1012007/VPN_GOlang/cmd/vpnctl").CombinedOutput()
        if err != nil {
                t.Fatalf("build vpnctl: %v: %s", err, out)
        }
        dir := t.TempDir()
        cfg := dir + "/server.json"
        if out, err = exec.Command(ctl, "init-server", "--output", cfg,
                "--interface", "wg-dry0", "--network", "10.253.0.0/24",
                "--token-path", dir+"/token", "--store", dir+"/peers.json",
                "--force").CombinedOutput(); err != nil {
                t.Fatalf("init-server: %v: %s", err, out)
        }
        // dry-run must exit 0 and print the plan
        out, err = exec.Command(bin, "--config", cfg, "--dry-run").CombinedOutput()
        if err != nil {
                t.Fatalf("vpnd --dry-run: %v: %s", err, out)
        }
        if want := "dry run (no changes will be made)"; !strings.Contains(string(out), want) {
                t.Fatalf("dry-run banner missing: %s", out)
        }
        // and no interface was created
        if _, err := os.Stat("/sys/class/net/wg-dry0"); err == nil {
                t.Fatalf("dry run created a live interface (constraint #2 violated)")
        }
}
