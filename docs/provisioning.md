# VyOS provisioning

The scopes below describe behavior on UniFi OS Server 6.0.21 RC,
Network 11.0.104-37279-1 and VyOS 2026.11.22-0018-rolling with zone-based
firewall policy. Most native UI results are from the UXG Pro profile. The tracker
records the model and verification method for each result.
[Enterprise firewall verification](verification.md#enterprise-directed-adoption-and-firewall)
The bridge supports single-family TCP Block or Reject between two explicitly mapped
prefixes in the Internal zone, with one destination port and optional Syslog Logging. The
native policy editor created, edited and deleted Block rules for both IPv4 and IPv6 while
live VyOS forwarding followed each edit. Set `ipv6_interfaces` in `[vyos_firewall]` to
opt in to IPv6 policy. The router must already have the mapped IPv6 prefixes on the two
LANs. IPv4 and IPv6 have separate reserved firewall chains and ownership records.

For IPv4 or IPv6 TCP Allow in the same scope, the bridge uses the stock named chain
`UNIFI_LAN_<rule_base>` in the rule's address family. A matching Allow ends evaluation of the
managed rules and resumes the router's forward chain, where operator rules still apply.
Auto Allow Return Traffic adds a separate reversed rule with the original service port as its
TCP source port and `established`/`related` matches. Its priority follows the order sent by
UniFi. Reserve the named chain for the bridge and leave any operator references outside it.

The bridge maps the observed New, Invalid, Established and Related selectors on TCP
Block, Reject and Allow to VyOS conntrack matches. Stateful rules preserve the router's
existing order and are rejected when a matching global state verdict, flow offload or a
connection-tracking exclusion can preempt them.

IPv4 UDP Block supports the same mapped Internal prefixes with one destination port
or one inclusive destination range, Connection State set to All, and Syslog Logging off.

To opt in, enable `[vyos_firewall]`, provide the mapped LAN prefixes and interfaces, and
reserve 32 consecutive rules starting at `rule_base` in the IPv4 forward filter. The enrollment loader keeps `firewall.json` beside the private
gateway state file. Store both on persistent storage. The gateway first logs the
baseline fingerprint. Review the saved `system_cfg` with managed VPNs disabled and make sure the parts outside
the managed LAN policy are handled by the operator. Set `unmanaged_baseline_sha256` to approve
that baseline. An omitted fingerprint keeps the gateway in capture mode. A change outside the
approved scope or a policy with unsupported matches is reported as a provisioning error.

Enable `[vyos_dhcp]` to manage one already configured IPv4 VLAN. Configure the
controller bridge, its VyOS Ethernet VLAN interface, and a unique Kea shared-network name and
subnet ID. Native pool creation, lease and DNS changes, out-of-pool MAC reservations, and
pool removal were verified with real DHCP clients. Existing router DHCP resources must have
distinct scopes. Reconciliation stops when an operator change overlaps the managed scope.
The built-in NTP Server setting maps one or two IPv4 addresses, in UI order, to Kea
Option 42. Fresh DHCP clients requesting Option 42 received the ordered values in OFFER
and ACK. Removing the option kept the pool and reservation in place. Other advanced DHCP
options and client-class overrides have separate qualification. Domain Name publishes
Option 15 and the controller discovery A record when the suffix matches the configured
`[vyos_dns]` zone. Standalone TFTP publishes an IPv4 address or DNS hostname as Option 66.
Network Boot accepts a unicast IPv4 server and portable relative filename up to 127 bytes.
Stock VyOS supplies the BOOTP server and file, and sends Options 66 and 67 when requested.
A client can use the advertised boot file over TFTP after obtaining its lease.
The bridge rejects conflicting standalone and boot server addresses.

`[vyos_static_routes]` scopes nondefault IPv4 and IPv6 static routes to explicit
destination prefixes. Paths for the same prefix can use different pinned next hops,
pinned interfaces, or a blackhole, with distinct distances. VyOS selects the lowest
eligible distance. The bridge verifies the selected path and the FRR alternatives before
acknowledging a change. `interface_ids` maps Network's compiled interface IDs to mapped VyOS Ethernet
ports or VLANs for Interface routes and IPv6 link-local gateways. Pin link-local next hops
with their VyOS interface in `next_hops`, for example `{"fe80::17%eth3.220":"eth3.220"}`.
`next_hops` can be empty for Interface and blackhole routes.
A scope can include an aggregate and more-specific prefixes. An existing journal accepts
additional prefixes and pins while preserving its original mappings. The daemon verifies
the installed route and its distance, checks that withdrawn entries disappear from FRR,
and verifies that distance 255 keeps the entry configured with forwarding inactive.
The bridge withdraws paused routes, and Network sends the same route ID on Resume.
Enabling this scope adds its verified static paths to the live Routing Table. The bridge
reports observed standby and installed paths with their original Network route IDs.
The inform route table carries mapped, installed IPv4 and IPv6 connected and static routes.

| Scope | Verified native workflow |
| --- | --- |
| `[vyos_dns]` | Create and remove explicit-TTL A and AAAA records in one forwarding zone, and edit an A record's address and TTL. DNS queries returned the configured answers. The operator's separate zone kept serving. |
| `[vyos_source_nat]` | Create masquerade and edit to a static source address for a scoped IPv4 TCP flow. The receiver measured the translated source before removal and the original source afterward. |
| `[vyos_wireguard]` | Create, edit the listening port and remove one IPv4 WireGuard server and peer. The peer handshook on the mapped WAN and reached the configured TCP service. Probes to the previous port and alternate WAN failed. |
| `[vyos_port_forward]` | Create, edit and remove one IPv4 TCP forward from a pinned WAN peer. The receiver observed the peer's original address. The old port, a second WAN and direct bypass attempts failed the packet checks. |
| `[vyos_vlan]` | Create and remove one pinned routed IPv4 VLAN on an existing trunk. The client reached the gateway and routed TCP after creation. UniFi reported the logical interface and kept the four physical port rows. |
| `[vyos_mdns]` | Configure Custom IPv4 discovery on two pinned LANs and disable it from the native UI. Specific service scope passed with AirPlay and a custom DNS-SD type. An unselected WAN received no discovery traffic. The stock engine rejects selections exceeding its Avahi filter line limit. |
| `[vyos_ospf]` | Create and delete one OSPFv2 area-0 interface, and edit its cost. The peer reached Full adjacency, the learned route carried traffic, and removal withdrew it. With `report_routes = true`, UniFi displayed the installed route and Full neighbor. |
| `[vyos_ipsec]` | Create and remove one policy-based IPv4 IKEv2 tunnel, and edit its ESP lifetime. Packet captures confirmed ESP in both directions. The UI showed Established while the child SA was up and Not Established after termination. |

WireGuard requires an explicitly mapped WAN, one approved tunnel prefix and peer, and a
reserved guard range before the managed LAN policy. Its verified forwarding scope is one TCP
service. The reconciliation journal stores a digest of the server key. The gateway removes VPN
secrets from its saved controller snapshot and keeps its adoption and broker credentials in a
mode-`0600` file. The sample configuration illustrates the required mappings.
Port forwarding reserves one DNAT rule and a separate ingress and forwarding guard range.
WireGuard and port forwarding have been verified individually.
The VLAN test disabled DHCP and IPv6 for the new network. DNS listeners remain
operator-managed. The logical VLAN mapping has no `port_idx`. With the separate mDNS
scope enabled, the test also created and removed a VLAN outside the relay selection.
The IPv4 mDNS scope accepts Off and Custom on the exact two configured LANs. The
default engine uses the stock VyOS `allow-service` setting. Selected service answers
cross the VLANs, and unselected answers stay local. Avahi also reflects queries for
unselected services between the selected LANs.

For larger lists, build the [reflector image](../containers/vyos-mdns/Dockerfile) and
preload it in VyOS. For a registry image, use the digest reference with the stock
`add container image` command. Set `engine = container`, `container_image` to the
preloaded local tag or registry digest reference, and `container_image_id` to the
full image ID from `show container image json`. The bridge reserves
`uxg-mdns-reflector` and checks the image, running configuration and multicast
memberships before confirming. Apply Off and verify withdrawal before switching
engines on an existing enrollment.
[VyOS container commands](https://docs.vyos.io/en/rolling/configuration/container/index.html#operation-commands)

The OSPF scope is for one explicitly mapped transit VLAN and uses no
redistribution or default announcement. Its route query reports installed, single-hop IPv4
OSPF routes through the mapped interface and observed Full neighbors. In the tested Network
build the Metric column showed the administrative distance of 110. VyOS showed the actual
interface and path cost change from 1 to 23. The bridge also reconciles the controller
router ID, hello and dead timers, and the interface's passive setting. It checks the active
FRR values before acknowledging a revision. Router ID edits require the current neighbors
to be withdrawn because this stock build can retain the original ID during adjacency.
Keep the original `router_id` option on existing enrollments to retain the provisioning
journal's scope. New enrollments take the router ID from Network.

This scope accepts native Off, plain text and MD5 interface authentication. Use
keys of up to 8 bytes for plain text or 16 bytes for MD5. The supported key
characters are ASCII letters, numbers and `._~!@%+=,:?-`. The bridge checks
the active mode and configured credentials before acknowledging the change.
Back up the generated `firewall.json.ospf-proof-key` with the provisioning
journal when relocating or restoring the bridge.

The IPsec scope owns one previously empty VyOS IPsec configuration, one WAN peer, one IPv4
host pair, a host route, and reserved IPv4 input, forward, and output guard slots. Its pinned
IKEv2 and ESP profile uses AES-256, SHA-256, MODP-2048, and a 48-character hexadecimal
pre-shared key. The verified ESP lifetimes are 3600 and 4200 seconds. The scoped route
allows only protected forwarding for the approved pair. The guard rules drop traffic from other VLANs and from the router itself. Source NAT, WireGuard, port forwarding,
preemptive firewall policy, and flow offload must be inactive while this scope applies IPsec.

The OpenVPN scope imports one native IPv4 TLS **VPN Client** profile for `vtun246`. The profile accepts a single WAN peer at
`198.18.210.2`, UDP ports 19443 and 19444, and inline CA, client certificate,
and key material. Set `[vyos_openvpn] server_name` to the exact common name
on the server certificate, for example `vpn.example.net`. The imported profile
must specify `verify-x509-name vpn.example.net name` with the same spelling
and case. Use up to 64 ASCII characters in DNS-style labels. Wildcards are
rejected. The journal binds the pin to the enrollment. Withdraw the
client and retire the managed scope before enrolling a different peer identity.
[Accepted OpenVPN directives](../provisioners/uxg_openvpn.py)

VyOS uses the pinned tunnel address and skips pushed routes and DNS. The required guard rules allow only the router's ICMP probe to the tunnel peer.
They drop tunneled forwarding, peer-initiated traffic, and access to the router's tunnel IP
from other interfaces. Install and verify those rules on all six IPv4 and IPv6 chains before
enabling `[vyos_openvpn]`. `plan_openvpn_guards` defines the precise rule set. Native
provisioning leaves the guards in place when the VPN client is removed.

The verified native edits cover the peer port and password. Network showed
**Established** only after the daemon verified the installed tunnel route and got a reply
from the peer. It showed **Connecting** after peer shutdown. VyOS did not report the
session start time, so the inform payload omits it. Native removal withdrew the live tunnel
and deleted its saved configuration and dedicated PKI. The pinned VyOS build left three
mode-`0600` runtime PEM files, which were removed separately after confirming the service
was inactive. On this build, keep the
dedicated peer offline until VyOS creates the TUN device on a first activation. Cold boot
with a live peer, routed VPN client networks, and OpenVPN site-to-site are unverified.

The current dual-WAN scope accepts one native **Failover Only** configuration on WAN 210 and
WAN 220. It uses VyOS IPv4 failover defaults and reserves NAT rules `80180` through `80183`
to masquerade only VLANs 110 and 120 on the selected WAN. It needs exclusive ownership of
IPv4 routing protocol 111, the two fixed next hops, and an independent management path.
Enable `[vyos_wan_failover]` only in that topology. The packaged SSH observer supplies the
WAN and policy snapshots. An existing `fib_command` can use an absolute path to a read-only
executable taking zero arguments. Its WAN JSON contains the fixed `probe`, the full
`routes` inventory from `ip -j -4 route show table all proto 111`, and `lookup` from
`ip -j -4 route get fibmatch 198.19.210.242 from 192.168.120.2 iif eth3.120`. A verified
unreachable probe has a null `lookup`. [Routing observer setup](#routing-observations-over-ssh)

Native priority and probe-loss transitions changed real egress and source NAT for both LANs.
Network showed the observed active uplink and each WAN's Online or Offline state. The
reported durations start at the first matching observation. VyOS uses its own binary
ICMP checks for the pinned native SLA profile. Exact UniFi SLA windows, public Auto probes,
latency and availability percentages, IPv6, load balancing, and combined VPN, OSPF or other
NAT use remain outside this scope.

Before removing WAN2, set WAN1 as primary with the approved SLAs and wait for WAN1 to be
the acknowledged active uplink. Then remove WAN2 and return the single WAN1 SLA to Auto.
Withdrawal removes the two defaults and all four managed NAT rules. The single
WAN baseline retains the operator's existing routing and NAT state.

## BGP

The bridge accepts a limited FRR configuration from Network’s Enterprise BGP
upload. Enable `[vyos_firewall]` and `[vyos_restart] recover_provisioning`
before enabling `[vyos_bgp]`. Configure the permitted peer addresses and exact
import and export prefixes in the site file. For peers carrying both address
families, also configure `dual_stack_peers`. The enrollment sample gives the
IPv4 and IPv6 transport requirements. Enable `advertise` to expose the BGP
capability to Network on an enrollment prepared for native qualification.

Verify the actual session, accepted prefixes, selected next hop and routed
traffic at both ends after an edit. Direct stock VyOS tests cover mixed-family
sessions and withdrawal. Native Enterprise upload and UI reporting remain open.
[Sample settings](../conf/uxg-enterprise.sample.conf) · [BGP evidence](verification.md#bgp)

## Scoped IPv4 policy-based routing

The same fixed dual-WAN configuration supports one native **Policy-Based Route** with **Kill Switch** enabled.
It matches VLAN 110 and one exact destination, `198.19.210.243` or `198.19.210.244`, and
selects WAN 210. The bridge stages the `UNIFI_PBR` ingress policy on `eth3.110`
after it prepares, verifies and saves reserved VyOS table 179 in a separate transaction.
It accepts an existing table if its configuration and forwarding state match the scope.
The table has two host routes through `198.18.210.2` on `eth3.210` and a covering
`198.19.210.240/29` blackhole at distance 254.

Reserve IPv4 forwarding rules 1 and 2 for the two destinations. The bridge saves guards
for the old and proposed policy before it changes the selector. Each guard drops traffic
for its destination on any egress other than WAN 210. The bridge verifies and saves the
selector before it removes the old guard and acknowledges the Network revision. This
scope requires a forwarding path without a global state policy or flow offload.
It also uses stock configuration history to recover a lost commit confirmation. Configure
`[vyos_restart]` with `recover_provisioning = true` and the restricted commit proof
reader. The native Restart action can stay disabled. [Commit proof setup](#provisioning-confirmation-recovery)

The covering blackhole stays installed even when the host routes are present. It catches
matched traffic if WAN 210 loses its routes. Keep table 179 reserved for this scope. Set
`[vyos_policy_route]` to use the packaged observer or an existing zero-argument
`fib_command`. The
[`vyos-routing-observer.py`](../scripts/vyos-routing-observer.py) script emits the
required IPv4 and IPv6 routing rules, table 179, the policy nftables table, and the compiled
IPv4 forward chain. Update an existing reader with the current script before applying a
policy. Run it through a restricted read-only path that can list nftables on VyOS.

The bridge verifies the compiled ingress match, packet mark, routing rules and blackhole
before it acknowledges the controller revision. Removing the policy withdraws the selector
and its guard and leaves the reserved table available for reuse. Wait for the acknowledged
withdrawal before disabling the scope or removing table 179. The verified profile is pinned
to WAN 210 and WAN 220, VLAN 110, and IPv4 host destinations. External captures verified cold
boot with the selected WAN available and administratively disabled. Partial boot
configuration failure remains unverified. [Cold-boot packet evidence](verification.md#policy-routing)

## Routing observations over SSH

Use a dedicated ED25519 key and the same literal IPv4 management address as `[vyos] api_url`.
Install the packaged `vyos-routing-observer.py` on the router at
`/config/scripts/vyos-routing-observer.py`, owned by root with mode `0755`.
Render its source-restricted key using the packaged bootstrap tool and apply the generated
VyOS commands with `commit-confirm`. Confirm and save once the new key can read routing
state and independent management still works.

```sh
python3 /usr/share/unifi-gateway/tools/vyos-inspection-ssh-bootstrap.py \
  --routing-observer --user vyos --source-ip 192.0.2.2 --public-key routing-ssh.pub
```

The WAN request only reads kernel routes. For policy routing, the router account needs
non-interactive access to these two fixed nftables reads.

```text
/usr/sbin/nft -j list table ip vyos_mangle
/usr/sbin/nft -j list chain ip vyos_filter VYOS_FORWARD_filter
```

For the packaged service, put the private key and independently pinned host key at
`/etc/unifi-gateway/vyos.routing-ssh-key` and
`/etc/unifi-gateway/vyos.routing-ssh-known-hosts`. Install the packaged
`vyos-routing-ssh.conf` example under
`/etc/systemd/system/unifi-gateway.service.d/` for an Enterprise enrollment, then reload systemd and restart the
bridge. Set `[vyos_routing_ssh] enabled = true` and `ssh_user` in the site configuration.
The enabled WAN and policy scopes use SSH when they omit `fib_command`.

## Scoped IPv4 QoS speed limits

The native **QoS → Limit** profile sets upload and download rates between VLAN 110 and the
pinned WAN 210 IPv4 peer `198.18.210.2`. It attaches two VyOS HTB shapers to `eth3.210` and
`eth3.110` and reserves IPv4 forwarding rule numbers 1 and 2. Those rules mark the exact
address and interface matches, then continue through the existing firewall policy.
The bridge owns `UNIFI_QOS_UP` and `UNIFI_QOS_DOWN` and their recorded interface assignments.

Enable `[vyos_qos]` only when the interfaces, peer and VLAN match this topology. Use an absolute,
zero-argument `kernel_command` that reads the router's queue and nftables state through a
restricted path. [The QoS observer](../scripts/vyos-qos-observer.py) shows the expected commands
and output. VyOS reapplies queues across the router on a QoS commit. The bridge checks that
other interfaces have their stock default queues before applying a change. The profile
requires an unoccupied QoS configuration, the two marker slots, and a path without NAT,
other packet-marking policies or flow offload.

To unwind verified rules, remove them in the native UI and wait for acknowledged provisioning
before disabling the corresponding scope. Keep independent VyOS console access. A failed
staged change waits for VyOS commit-confirm rollback and restores the last saved configuration.

## Native security event delivery

The broker transport was verified against Network 11.0.104 using one actual Suricata alert
and one actual inline drop. Both appeared in the native security log and Flows. Install
Pika 1.5 for the optional publisher, enable `[vyos_security_events]`, and configure the
broker address, site UUID, TLS hostname, independently obtained CA pin, and private journal
path. Review the updated baseline when enabling the broker capability.

With the stock inspection runner below, set `automatic_drop_delivery = true` to deliver
final drop alerts for the pinned IPv4 TCP scope. The runner includes Suricata's counters
at the verdict and withholds payload, packet and application data. The bridge can also
pair a drop with its completed flow within the same engine run. Use a service-owned
private directory for the delivery journal and its adjacent source checkpoint. The
worker resumes at that checkpoint and uses broker confirmations to suppress replay.
An ambiguous publication stays in the journal for review before any resend.
[Automatic stock Block evidence](verification.md#inspection)

Automatic Notify is separately opt-in with `automatic_notify_delivery = true` and
the router kit's `--observe-notify` option. Its observer retains scoped TCP header
metadata to verify egress for the packet associated with the Suricata alert. Delivery
also requires completed counters from the same Suricata run.

For a separate observation producer, run `python -m inspection.event_delivery` with
newline-delimited records on standard input. Each record has an `eve` alert with real
flow counters and a boolean `forwarding_observed` from an independent observation.

## Native inspection control

`[vyos_inspection]` opt-in translates native **Off**, **Notify**, and **Notify and Block**
to an explicitly configured actuator. The daemon pins the selected bridge pair and the
observed controller controls digest. It verifies the actuator's result before acknowledging
the revision and checks active inspection health independently of provisioning.

The stock integration installs the inline queue through the VyOS zone firewall,
checks both forwarding directions, and uses commit-confirm to roll back an
unverified change. Existing firewall denies take effect before inspection.
[Stock queue evidence](verification.md#inspection)

The current stock path is opt-in through `stock_queue` in `[vyos_inspection]`.
Its JSON contains `queue`, `server_port`, `rule_id`, `passthrough_chain`,
`topology_sha256`, and `initiator` and `responder` objects. Each endpoint specifies
its `interface`, IPv4 `host`, `zone`, and outgoing named `chain`. The fingerprint
pins those zone bindings, the complete directional chains, and the IPv4 and IPv6
passthrough chains. The ordinary base forwarding filter remains separately managed.
Set `"engine_only": true` in the root-owned runner configuration. Its pinned engine
scope must match the queue tuple. The bridge stages and saves the queue through VyOS
and verifies the listener. Native Off, Notify, and Block passed for one IPv4 TCP scope.
The Debian package includes the router kit at
`/usr/share/unifi-gateway/tools/vyos-inspection.pyz`. After verifying the package, copy the kit to the router over the
management path and install it once from the VyOS console as root.

```bash
python3 -I ./vyos-inspection.pyz install --controls-sha256 APPROVED_CONTROLS_SHA256
```

Use the same approved hash as in `[vyos_inspection]`. Installation creates
`/opt/unifi-gateway-vyos-inspection/run` and records the router's current
hostname in its root-owned approval. The launcher checks that hostname on every
request. Withdraw inspection before renaming the router. Move the previous kit
to a root-only backup and re-enroll from its console afterward.

For a direct management path, generate a dedicated ED25519 bridge key. The
packaged `vyos-inspection-ssh-bootstrap.py` renders VyOS console commands for
an existing management account. It binds the key to the bridge's management
source address and forces the inspection launcher. Apply the commands with
`commit-confirm`. Verify the forced launcher and independent management access
before confirming and saving. Keep SSH on the private management path.

Set `ssh_host`, `ssh_port`, and `ssh_user` in `[vyos_inspection]` in place of
`command`. The host must match the IPv4 address in `[vyos] api_url`. Pin the
router's ED25519 host key obtained through independent management. Use one
known-hosts entry for the literal address, or `[address]:port` for a custom
port. For the packaged service, install the private key and pin as
`/etc/unifi-gateway/vyos.inspection-ssh-key` and
`/etc/unifi-gateway/vyos.inspection-ssh-known-hosts` with mode `0600`. Install
the packaged `vyos-inspection-ssh.conf` example as a drop-in for
the enrolled service, then reload systemd and restart the unit. For source or container enrollment, place `inspection-ssh-key` and
`inspection-ssh-known-hosts` beside the site file.

Prepare the approved forwarding scope through VyOS config before enabling
inspection in UniFi. Use native Off to withdraw the queue before changing
the launcher or withdrawing the key.
[Native stock inspection evidence](verification.md#inspection)

The packaged reference runner installs one benign IPv4 TCP signature
(SID 1000043). It can validate the native
workflow. A general-purpose intrusion ruleset still needs integration. In Notify
mode the matching flow passed and generated an alert. In Block mode the matching
flow was dropped and the native System Log received a block event. The observed
engine-loss policy bypassed the queue and Network reported a configuration
failure. Other traffic patterns and IPv6 need separate verification.

`python -m inspection.eve_source` converts genuine Suricata EVE stream records with an
explicit final drop verdict to that publisher's input. Use `--same-engine-flows` on a stream
from one Suricata process to correlate alerts with its later completed flow counters.
Supply `--forwarded-event-id` only after independently observing delivery of the corresponding
passive alert flow. Automatic Notify delivery, IPv6 inspection, and production signature
management still need qualification.

`python -m inspection.event_delivery --completed-flows` accepts paired conntrack and routed
packet evidence. One verified ordinary TCP flow appeared in Network Insights with the same
directional packet and byte counts as the independent capture. `python -m inspection.conntrack_source`
turns a bounded, trusted capture window with conntrack DESTROY records, both routed egress
captures, and endpoint receipts into that paired input. Continuous capture, NAT correlation
and Live Flows still need separate verification.

## Router restart

Restart requires adopted AES-GCM informs, an enabled `[vyos_firewall]`
scope, and `[vyos_restart] enabled = true`. Keep the bridge and
controller clocks within 60 seconds. Coordinate independent VyOS writers
during maintenance. The stock saved-state guard and reboot request are
separate operations.

Install the packaged `vyos-restart-preflight.vbash` on VyOS as
`/config/scripts/vyos-restart-preflight.vbash` with root ownership and
mode `0755`. Use `vyos-inspection-ssh-bootstrap.py --restart-preflight`
with a dedicated ED25519 key, the bridge's management IPv4 address, and
an existing non-root account in `vyattacfg`. Review the generated VyOS
commands and use `commit-confirm`. Confirm and save once the pinned
SSH probe and independent management access work. The forced key runs
only the read-only preflight.

Provide a fixed `forwarding_probe` executable on the bridge that
exits zero after an independent test through the router's data path.
For source and container deployments, place `restart-ssh-key` and
`restart-ssh-known-hosts` beside the site file. Packaged deployments use the `vyos-restart-ssh.conf`
credential drop-in and the same pin format as the WAN probe.

Keep the adoption and provisioning journal in place during recovery.
An ambiguous reboot response keeps the bridge waiting for a new boot,
the saved configuration and a passing forwarding probe. If VyOS stayed
on the original boot, use its console to inspect for pending changes
and safely restart it during maintenance.
[Restart qualification](verification.md#recovery)

## Provisioning confirmation recovery

Set `recover_provisioning = true` in `[vyos_restart]` to use the same
pinned read-only SSH helper for lost commit confirmations. The router
helper must support the staged and completed commit probes. This option
works with Restart disabled, and needs no forwarding probe for Restart.
Keep VyOS local commit archives enabled and install the current helper
before configuring recovery.

The bridge first checks for a clean saved baseline. It records the
fingerprint of the verified stage before calling
`confirm`. After an ambiguous response, it checks for the same configuration
in the completed archive with no active or queued rollback. Recovery also
rechecks the configured scopes and their runtime state before saving.
Coordinate independent configuration writers during this process. Stock
VyOS exposes separate proof and save operations.
[Provisioning recovery evidence](verification.md#recovery)

## Prepare the Shadow Mode router helpers

Use the independent management path on each stock VyOS router. Copy these
files from `/usr/share/unifi-gateway/tools` and install them with root
ownership.

| Packaged file | Router path | Mode |
| --- | --- | --- |
| `vyos-shadow-peer.py` | `/config/scripts/vyos-shadow-peer.py` | `0755` |
| `vyos-restart-preflight.vbash` | `/config/scripts/vyos-restart-preflight.vbash` | `0755` |
| `vyos-restart-preflight.vbash` | `/config/unifi-gateway-shadow/preflight.vbash` | `0700` |
| `vyos-shadow-policy-eligible.py` | `/config/scripts/unifi-gateway-shadow-policy-eligible.py` | `0755` |
| `vyos-shadow-policy-eligible.py` | `/config/unifi-gateway-shadow/policy.py` | `0700` |

Create `/config/unifi-gateway-shadow` as a root-owned directory with mode
`0700`. Generate a separate ED25519 key for each helper on each router.
Use the packaged `vyos-inspection-ssh-bootstrap.py` with the bridge's
management source and an existing non-root VyOS account. Select
`--restart-preflight` for saved and staged commit proofs,
`--shadow-interconnect` for the physical interconnect and pinned LAN
observations, and `--shadow-receipt-control` for the fixed receipt command.
The receipt command requires noninteractive sudo for that exact command.
Apply the rendered key configuration with commit-confirm and verify the
forced operations and independent access before confirming and saving.

Install a root-owned mode-0600 `/config/unifi-gateway-shadow/policy-scope.json`
with a `paths` array of VyOS configuration paths. Include the reserved
`UXGSHADOW` VRRP group, `UXGHA` sync group, conntrack sync, the mapped
interconnect and bridge interfaces, and the managed forwarding chains.
The receipt manager starts with an empty slot. Admission verifies scope
coverage and the private saved-state proof on each router. Use direct
management addresses on interfaces outside the gateway port mappings.
Native pairing and the full recovery workflow are tracked under
[DEP-12](coverage.md#deployment-and-recovery).

## WAN verification

The bridge can measure WAN reachability and latency over the existing VyOS
management path. Generate a dedicated Ed25519 key per WAN. Use the packaged
SSH bootstrap tool to render a source-restricted key for the mapped VyOS
interface and its probe target. Apply the rendered commands in a stock
commit-confirm transaction and confirm after checking management access and
the measured probe. The probe runs as the selected VyOS user without sudo.

```sh
python3 /usr/share/unifi-gateway/tools/vyos-inspection-ssh-bootstrap.py \
  --user vyos --source-ip 192.0.2.2 --public-key ./wan1.pub \
  --wan-group WAN --wan-interface eth1 --wan-target 192.0.2.10
```

For the Debian service, install the `vyos-wan-ssh.conf` example as a drop-in
and place the key and one verified SSH host pin at the paths it names. Limit
the credentials to mode `0600` and add the corresponding credential entries
for additional WANs. The SSH address comes from `[vyos] api_url` and must be a
literal IPv4 address. Set `ssh_port` if the router uses a management port
other than 22.

```ini
[vyos_wan_health]
enabled = true
ssh_user = vyos
probes = {"eth0":{"target":"192.0.2.10","ssh_key_file":"wan1-ssh-key"}}
```

The JSON key is the UniFi-facing `ifname` from the port mapping. The bridge
verifies the interface and target returned by ping and records replies and
mean RTT. A complete sample with zero replies reports loss without a latency
value. The bridge withdraws the monitor when the interface or measurement
source is unavailable. Choose a peer that represents the connectivity you
intend to measure. A private peer measures reachability within that path.

The enrollment loader resolves each `ssh_key_file` credential beside the
site file. To use a local measurement helper, configure an absolute `command` instead of an SSH key. That command takes no arguments and emits the JSON reported by
`python3 backends/vyos_wan_ping.py INTERFACE IPV4_TARGET`.

## Speed Test

The VyOS bridge runs an operator-provided measurement executable for the
native **ISP Speed Test** button. Point it at a trusted executable that measures
the intended WAN path and is runnable by the bridge service account.

```ini
[vyos_speedtest]
enabled = true
command = /usr/local/libexec/unifi-gateway/wan-speedtest
timeout = 45
server_provider = Example Network
server_location = Paris
```

The bridge passes no arguments. The executable returns a final JSON object on
stdout with positive `download_bps`, `upload_bps`, and `latency_ms` values
and a `timestamp` in Unix seconds. For live progress, flush two JSON lines
before the final object. The first contains `"phase":"download"`,
`download_bps`, `latency_ms`, and `timestamp` after the first measured
download sample. The second contains `"phase":"upload"` and all four
measurement fields after the first measured upload sample. Use the same run
timestamp for all three records. A runner that emits only the final object
continues to work and reports its samples after the measurement finishes.

Set both `server_provider` and `server_location` to the runner's actual
endpoint. On Network `11.0.104`, the live card needs both values to leave
**Connecting…** when the first measurement arrives. Replace the example provider and location with the actual
measurement endpoint. To test an Internet uplink, run the measurement over that path.
If the runner fails, the bridge sends the native terminal failure status
with the run timestamp. The log retains the specific error.
