# Gateway verification record

These results were measured on stock VyOS `2026.11.22-0018-rolling`. The
controller workflows used UniFi OS Server `6.0.21 RC` and Network
`11.0.104-37279-1`. The record identifies the model and how each workflow was
driven. Use the [coverage tracker](coverage.md) for outstanding acceptance checks.

## Enterprise directed adoption and firewall

The Enterprise candidate reported `UXGENT` and firmware reference `6.0.17`.
Network adopted it through directed inform, negotiated AES-GCM, and showed
Online with the same MAC after a bridge restart. The isolated site used two
mapped physical ports and prepared VLANs 110 and 120. Router reads and writes
used certificate-verified HTTPS.

In the native Policy Table an operator created a logged IPv4 TCP deny from
VLAN 110 to VLAN 120, changed its port, and deleted the rule. The controller
showed matching desired and applied revisions. Independent clients opened a
fresh connection to each port after each action.

| Native action | Verified revision | TCP/8443 | TCP/8444 |
| --- | --- | --- | --- |
| Deny 8443 | `8b3cfc79428f5f40` | Timed out | Delivered |
| Change deny to 8444 | `692621ddddc2be68` | Delivered | Timed out |
| Delete | `e105a15e9fefef63` | Delivered | Delivered |

VyOS running and saved configuration agreed at slot 80200 and both showed
the slot absent after deletion. The source archive used for the test had
SHA-256 `8a14c1edbfe8d3367d414016c3dec1044232a31e153a79b2b63d2a2bfecda63a`.
Same-VLAN adoption, all six port roles, and installation from the current
package need their own checks.

## High availability

Two stock routers used separate WAN, LAN, management and sync networks.
One-second VRRP on the LAN selected the VIP owner. The dedicated interconnect
replicated conntrack state. After its loss both peer probes failed, but the
primary retained the VIPs while the LAN election path was intact. A hard
primary failure transferred both VIPs to the standby. An established NAT and
firewall TCP/8443 session continued through the promoted router. The WAN peer
saw one TCP accept. The original primary returned as backup.

Separate tests introduced a saved policy mismatch on the standby. The node
stayed in FAULT across primary loss and its own cold boot. Packet captures
showed no standby VIP claims until repair. With matching running and saved
policy the repaired node took the VIPs and forwarded a new connection.

The initial paired-election source archive had SHA-256
`418ac3535be2343351ef8752ca494c67163b005871031173d9fe80276f6fce35`.
Later maintenance checks exercised receipt revocation, exact configuration
withdrawal, and preservation of operator LAN aliases and VRRP ancestors.
Native pairing, election-LAN partition behavior, forced promotion, unpairing
and controller-visible recovery remain open. [Shadow policy compiler](../provisioners/vyos_shadow_complete.py)

## BGP

Two stock VyOS routers with FRR 10.7.1 established BGP sessions and exchanged
approved routes. Import and export filters excluded decoy prefixes. IPv4 and
IPv6 unicast ran over one IPv6 transport with extended next hop. The IPv4 FIB
reported the link-local IPv6 next hop on the expected interface and both
families carried traffic. An IPv4 import edit changed IPv4 reachability;
the IPv6 session counters and forwarding remained stable. Withdrawal removed
the IPv4 family and capability while IPv6 kept forwarding. The routers' final
saved configuration matched baseline after the scope was disabled.

The pinned controller writer uses `routes/bgp/raw:1` and Base64 FRR text. The
stock tests exercised the reconciler directly. The native Enterprise upload
and routing-table view remain open. [BGP decoder and planner](../provisioners/vyos_bgp.py)

## Routing

Stock FRR and HTTPS read-back confirmed scoped IPv4 and IPv6 routes, including
blackhole, interface and next-hop forwarding, same-prefix route preference and
withdrawal. Observer traffic and captured egress distinguished the active
route from alternatives. The bridge reported ECMP next hops for operator routes.
Main-table and table 117 routes to identical destinations appeared with
different table IDs in the encrypted bridge reply.

OSPFv2 tests on a paired area-0 VLAN exercised timers, passive state,
authentication and key withdrawal. Changing the Router ID while Full left
the running adjacency on its original ID until an OSPF restart. The bridge
must verify effective state before acknowledging such a change. Native UI
coverage with the Enterprise identity remains open. [Route tests](../tests/test_vyos_routes.py) · [OSPF tests](../tests/test_vyos_ospf.py)

## Policy routing

The policy applied to VLAN 110 and one of two IPv4 hosts. VyOS saved table
179 before installing the ingress selector. Forward guards restricted the
destination to WAN210 over transitions and loss. Tests compared packet
captures on both uplinks across withdrawal, cold boot, and a conflicting
main-table route. The restricted SSH observer read the real WAN default and
reported an unreachable lookup after withdrawal. General selectors and an
induced boot configuration failure remain open. [Original native policy workflow](uxg-pro-qualification.md#policy-routing) · [Observer](../scripts/vyos-routing-observer.py)

## Recovery

A stock VyOS preflight read running versus saved configuration and checked
commit-confirm status. An opt-in recovery test bound an ambiguous confirmation
to the completed configuration fingerprint before saving. Pending timers,
changed running state and overlapping commits failed the recovery checks.
Restart tests used a separate data-plane probe. These tests covered the tested
scope and helpers. A simultaneous cold boot of controller, bridge and router
using the greenfield package remains open. [Restart preflight](../scripts/vyos-restart-preflight.vbash)

## LAN policy and discovery

Earlier Pro UI captures exercised IPv4 UDP Block on a single port or one
inclusive port range, state set to All and logging off. Outside controls and
withdrawal were checked separately. IPv4 mDNS tests selected two mapped
networks and checked discovery on selected networks and isolation outside
them. Stock service and container reflector limits are tracked separately.
[Firewall packet tests](uxg-pro-qualification.md#firewall) · [mDNS results](uxg-pro-qualification.md#vlans-and-multicast-dns)

## Inspection

Stock VyOS used Suricata 7.0.10 with one harmless reference signature. Queue
placement preserved earlier firewall denies. A permitted nonmatching flow
passed; the selected marker produced a drop verdict and no application
delivery in Block mode. Notify and Off passed traffic. Stopping the listener
exercised the configured bypass behavior. Older native Pro tests linked the
mode change and actual EVE verdict to a security-log event. Direct SSH tests
withdrew the prior healthy acknowledgement on a router power cycle, then
verified enforcement on recovery. New hostname/owner enrollment, broader
traffic, production rulesets and current Enterprise event ingestion require
fresh packet and native UI checks. [Native reference evidence](uxg-pro-qualification.md#inspection)

## WAN measurements

The earlier native Pro UI stored the result from a configured two-way
measurement. A later runner streamed actual download and upload samples before
the final result; one measured run reported 845.85 Mbps down and 719.75 Mbps up.
The server provider and location are part of the running-status contract in
Network 11.0.104. The current Enterprise UI needs a timed test of progress,
failure, and recorded history with an independently measured path.
