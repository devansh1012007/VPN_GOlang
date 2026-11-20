# ADR-002: wgctrl for the control plane

Status: accepted (2026-11-20)

## Context

`vpnd` must configure a WireGuard interface from Go: create the link, set the
private key, listen port, add/remove peers with allowed IPs. Options: shell out
to `wg(8)`; parse `wg show` output; or use a netlink library.

## Decision

Use **`golang.zx2c4.com/wireguard/wgctrl`** as the single control-plane client.
All device and peer mutations go through `wgtypes` types.

## Rationale

- `wgctrl` is maintained by the WireGuard author's ecosystem; it speaks both
  generic netlink (kernel) and the UAPI socket (wireguard-go) behind one interface.
- Typed API (`wgtypes.Key`) makes key handling compile-time safe — keys never
  travel as raw strings.
- Shelling out to `wg` would mean parsing human output and running a subprocess as
  root — both unnecessary attack surface.

## Consequences

- `internal/wireguard.DeviceManager` is an interface; the wgctrl implementation is
  one adapter, so unit tests use a fake client (`fakeClient_test.go`) — tests never
  touch a live interface (constraint: no dev-machine network mutation).
- Link creation (the `ip link add` part) is *not* covered by wgctrl; it is done by
  the `network` package using netlink (`ip link add type wireguard`) — see ADR-006.
