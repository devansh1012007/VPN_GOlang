package network

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

// LinkManager creates/removes the WireGuard link (the "ip link add" part that
// wgctrl deliberately does not cover — ADR-002/ADR-006). Real implementation
// uses netlink directly; no shell-outs.
type LinkManager interface {
	// EnsureLink creates the wg link if missing, sets its VPN address and MTU,
	// and brings it up. Idempotent.
	EnsureLink(name, cidr string, mtu int) error
	// RemoveLink deletes the link if it exists. Idempotent.
	RemoveLink(name string) error
}

// NetlinkLinkManager is the production LinkManager (requires CAP_NET_ADMIN
// for mutations; EnsureLink/RemoveLink are the mutating entry points only).
type NetlinkLinkManager struct{}

// NewNetlinkLinkManager builds the netlink-backed link manager.
func NewNetlinkLinkManager() *NetlinkLinkManager { return &NetlinkLinkManager{} }

// EnsureLink makes name exist as an up WireGuard link with cidr and mtu.
func (m *NetlinkLinkManager) EnsureLink(name, cidr string, mtu int) error {
	lnk, err := netlink.LinkByName(name)
	if _, notfound := err.(netlink.LinkNotFoundError); notfound {
		wg := &netlink.Wireguard{LinkAttrs: netlink.NewLinkAttrs()}
		wg.LinkAttrs.Name = name
		if err := netlink.LinkAdd(wg); err != nil {
			return fmt.Errorf("link add %s: %w", name, err)
		}
		if lnk, err = netlink.LinkByName(name); err != nil {
			return fmt.Errorf("link lookup after add: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("link lookup %s: %w", name, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("link addr %s: %w", cidr, err)
	}
	hasAddr, err := linkHasAddr(lnk, addr)
	if err != nil {
		return fmt.Errorf("link addrs %s: %w", name, err)
	}
	if !hasAddr {
		if err := netlink.AddrAdd(lnk, addr); err != nil {
			// Another process may have raced us; re-check before failing.
			if lnk2, err2 := netlink.LinkByName(name); err2 == nil {
				if has, _ := linkHasAddr(lnk2, addr); has {
					return nil
				}
			}
			return fmt.Errorf("addr add %s to %s: %w", cidr, name, err)
		}
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(lnk, mtu); err != nil {
			return fmt.Errorf("set mtu %d on %s: %w", mtu, name, err)
		}
	}
	if err := netlink.LinkSetUp(lnk); err != nil {
		return fmt.Errorf("link up %s: %w", name, err)
	}
	return nil
}

// RemoveLink deletes the link; absent links are a no-op.
func (m *NetlinkLinkManager) RemoveLink(name string) error {
	lnk, err := netlink.LinkByName(name)
	if _, notfound := err.(netlink.LinkNotFoundError); notfound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("link lookup %s: %w", name, err)
	}
	if err := netlink.LinkDel(lnk); err != nil {
		return fmt.Errorf("link del %s: %w", name, err)
	}
	return nil
}

// linkHasAddr reports whether the link already carries the address
// (idempotence check for EnsureLink).
func linkHasAddr(lnk netlink.Link, addr *netlink.Addr) (bool, error) {
	addrs, err := netlink.AddrList(lnk, netlink.FAMILY_ALL)
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if a.IPNet.String() == addr.IPNet.String() {
			return true, nil
		}
	}
	return false, nil
}
