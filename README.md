# UniFi Gateway for VyOS

This fork connects stock VyOS to self-hosted UniFi Network. The bridge adopts as a
UXG Enterprise, sends observations from the router, and translates supported
Network settings into verified VyOS configuration. VyOS forwards the traffic.
The bridge runs on a separate management host.

## Interoperability and licensing

This independent project implements the gateway side of a protocol so that
UniFi Network and stock VyOS can exchange configuration and status.

French and EU copyright law protect specific acts of interoperability work.
A lawful user may observe, study or test a program during operations they are
entitled to perform. When necessary interface information is not readily
available, the law also permits limited decompilation by or on behalf of a
lawful user where it is indispensable to make an independently created program
interoperate. The exception limits which parts may be examined and how the
information may be used or shared. Contract terms contrary to these statutory
exceptions are void. [French Intellectual Property Code, Article L122-6-1](https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000044365559) · [Directive 2009/24/EC, Articles 5(3), 6 and 8](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024)

The bridge source is distributed under the MIT license and retains the upstream
copyright notice. Ubiquiti separately states that UniFi OS Server may manage
only genuine Ubiquiti products. That restriction directly concerns deployment
with a VyOS router. The statutory exceptions above address particular acts of
software development and do not establish permission for every deployment.
[Bridge license](LICENSE) · [UniFi OS Server terms, Schedule 3](https://www.ui.com/legal/unifi-os-server/)

## Feature coverage

The Enterprise verification used UniFi OS Server 6.0.21 RC, Network
11.0.104-37279-1 and VyOS 2026.11.22-0018-rolling. Results labeled Pro are historical protocol and packet evidence from an earlier
identity on the same builds. Each Enterprise control requires its own native UI test.

| Feature | Verified scope | Still open |
| --- | --- | --- |
| Enterprise adoption and firewall | Directed adoption, adopted identity across a bridge restart, and native create/edit/delete of a logged IPv4 TCP deny between two mapped VLANs. Traffic and applied revision followed each edit. | All six physical port positions in Network, clean installation, migration, and broader Enterprise firewall controls. |
| Interfaces and LAN services | Pro native workflows for one routed IPv4 VLAN, DHCPv4 leases and reservations, A/AAAA forwarding records, and mDNS across two selected LANs. | General interface remapping, IPv6 address assignment, and broader DHCP and DNS controls. |
| Routing, NAT and QoS | Pro native workflows for static routes, scoped OSPFv2, source NAT and port forwarding. Failover, a policy route with Kill Switch, and a bidirectional speed limit each passed on specific WANs, VLANs and peers. | Arbitrary topologies for failover, policy routing and QoS, plus their combined operation. BGP has stock router verification and still needs a native Enterprise upload. |
| VPN | Pro native workflows for one constrained WireGuard server/peer, policy-based IPsec tunnel, and OpenVPN TLS client. The OpenVPN scope uses a fixed remote endpoint and its guards restrict traffic to router-originated probes. | General peer enrollment, routed OpenVPN clients, and broader protocol combinations. |
| Inspection and accounting | Pro native Notify, Block, and Off for a single IPv4 TCP signature. A verified event reached the security log. One completed TCP flow matched independent packet and byte counts. | Production signature management, IPv6 inspection, continuous flow accounting, DPI, and Live Flows. |
| WAN reporting | Measured counters and SSH-based reachability on mapped interfaces. The native Pro speed test saved the result of a configured two-way measurement. | Enterprise UI verification of speed-test progress and failure, scheduling, and WAN history. |
| Shadow Mode | Two stock VyOS nodes demonstrated VIP ownership, state replication, and failover of an established NAT/firewall TCP session. | Native Enterprise pairing, failover status, unpairing, and end-to-end recovery. |

Optional provisioning scopes are disabled by default. Check the relevant
scope before enabling it, especially for WAN, VPN, QoS and inspection.
The [coverage tracker](docs/coverage.md) records the evidence,
limits and remaining acceptance checks for each control.

## Install the management bridge

Run the bridge on a Linux management host that can reach the controller inform
endpoint and VyOS over HTTPS. Use a management interface independent of the WAN
and LAN interfaces that UniFi will manage.

For a source install, use Python 3.11–3.13 and the enrollment steps below.

```sh
git clone https://github.com/maiko/unifi-gateway.git
cd unifi-gateway
python3 -m venv venv
. venv/bin/activate
python -m pip install -r requirements.txt
```

For systemd deployment, use a Debian package built from this repository.
[Package build](.github/workflows/release.yml) · [Example enrollment](conf/uxg-enterprise.sample.conf)

## Enrollment

Start with a fresh Enterprise enrollment and state directory. The bridge requires
a versioned provisioning journal. Before replacing a development deployment,
back up its state and reconcile the router rules it owns. Deleting a journal
while its rules are active loses the ownership record.

### Set up the VyOS management endpoint

Use the router's independent console and a management IPv4 address already assigned
and reachable from the bridge. Reserve a TCP port and the PKI entries
`unifi-gateway-ca` and `unifi-gateway-https`. This bootstrap is for a router with
an empty `service https` subtree and unused PKI names. For an existing endpoint,
use your operator-managed configuration and verify its listener, client restriction
and TLS identity before enrolling the bridge.
Apply listener or certificate changes from the independent console. Check the
new HTTPS endpoint from the bridge before saving the router configuration.

1. On the management host, prepare a directory containing `ca.pem`,
   `router.pem`, `router-key.pem` and `vyos-api-key`. The server certificate must
   be signed by that CA and include the router's management IP as a SAN. The CA
   certificate must include the `keyCertSign` usage. Keep the CA signing key
   offline. The two key files must be owned by the invoking user
   with mode `0600` or `0400`. Generate the API key with
   `openssl rand -hex 32`.
2. Use Python 3 and OpenSSL 3 to prepare a new private configuration fragment.
   Pass the bridge source address as VyOS sees it.

   ```bash
   python3 /usr/share/unifi-gateway/tools/vyos-https-bootstrap.py \
     192.0.2.15 192.0.2.2 8443 ./credentials ./uxg-https.config
   ```

3. Transfer the fragment over your trusted administrative path and keep both
   copies mode `0600`. On the independent VyOS console, check that the running
   and saved configurations agree and that
   `service https` and the two reserved PKI entries are absent from both. Run
   `configure`, `merge /path/to/uxg-https.config` and `commit-confirm 5`. Use a
   trusted VyOS administrator session during the merge. Stock VyOS configuration
   tooling can place secret values in local process arguments while applying the
   fragment.
4. From the bridge's management address, verify the pinned certificate and use
   the dedicated key to read an innocuous configuration property.

   ```bash
   tr -d '\r\n' < ./credentials/vyos-api-key |
     curl --noproxy '*' --cacert ./credentials/ca.pem --silent --show-error --fail \
       --data-urlencode key@- \
       --data-urlencode 'data={"op":"showConfig","path":["system","host-name"]}' \
       https://192.0.2.15:8443/retrieve
   ```

5. After the probe returns a successful response with the router's name, run
   `confirm` and `save` on the console. Use the verified HTTPS origin, CA and API
   key in the bridge enrollment. Remove the working fragment from both hosts
   after saving and store the enrollment credentials securely.

[VyOS HTTPS service](https://docs.vyos.io/en/rolling/configuration/service/https.html) ·
[VyOS commit-confirm](https://docs.vyos.io/en/rolling/cli.html#configuration-mode)

### Debian enrollment

On a Debian or Ubuntu management host, install the `unifi-gateway` Debian package
and configure `unifi-gateway.service`.
Install the APT recommendations when using WAN or inspection SSH. OpenSSH needs
`libnss-systemd` to resolve the packaged service's dynamic user on minimal images.
If you install with `--no-install-recommends`, install `libnss-systemd` and
`openssh-client` explicitly before enabling those SSH features.

1. For a fresh Enterprise enrollment, copy
   `/usr/share/unifi-gateway/examples/uxg-enterprise.sample.conf` to
   `/etc/unifi-gateway/uxg-enterprise.conf`.
   Set the controller's inform URL, the routed LAN address and the VyOS interface
   mapping. Keep the enrollment file root-owned and mode `0600`.
2. Set `api_url` to the router's HTTPS management origin. Install its CA at
   `/etc/unifi-gateway/uxg-enterprise.vyos-ca.pem` and the dedicated API key at
   `/etc/unifi-gateway/uxg-enterprise.vyos-api-key`. Keep the key root-owned and mode `0600`.
3. Run `sudo systemctl enable --now unifi-gateway.service` and adopt the gateway
   in Network's **Devices** view. Inspect startup with
   `sudo journalctl -u unifi-gateway.service`.

For optional SSH features, install the feature's credential drop-in under
`/etc/systemd/system/unifi-gateway.service.d/`. Keep each
`LoadCredential` name and set the source path to the Enterprise enrollment's
key or host pin. Reload systemd and restart the enrolled unit.

The packaged unit generates a locally administered MAC when enrollment omits
`lan_mac`. It keeps the MAC, adoption key and reconciliation journal under
`/var/lib/unifi-gateway`. Back up the contents as root, following the link
into `/var/lib/private` if systemd creates one. Include the enrollment and
credentials. Changing a bound model, controller, router origin or MAC requires a
separate enrollment and a separate adoption in Network. Preserve independent access to the management
interface and the router console.

For a packaged Shadow Mode pair, stop `unifi-gateway-shadow.service` before
copying its state. Keep both role directories from `/var/lib/unifi-gateway-shadow`
together with both enrollment and credential directories under
`/etc/unifi-gateway/shadow`. Restore them with their original permissions and keep
each role's `gateway.conf`, `firewall.json` and any adjacent proof keys together.
The launcher checks both roles before starting either worker. Keep the router
and controller backups from the same maintenance window.

To decommission the bridge, withdraw its managed policies from Network and verify
their removal on VyOS. Then disable the unit and remove the package. Keep the
enrollment, credentials and private state together in a root-only backup.

### Running the bridge directly

A source install can use the same enrollment loader as the Debian service. Run
the following as the dedicated bridge account. Keep the enrollment, credentials
and writable state outside the source checkout.

```sh
umask 077
mkdir -p "$HOME/.config/unifi-gateway" "$HOME/.local/state/unifi-gateway"
cp conf/uxg-enterprise.sample.conf "$HOME/.config/unifi-gateway/site.conf"
```

Set the controller inform URL, LAN address, port mappings, and VyOS HTTPS origin
in `site.conf`. The example selects `device = UXGENT` and `platform = vyos`.
Beside `site.conf`, install the trusted CA as `vyos-ca.pem` and the dedicated
API key as `vyos-api-key`. Keep the key readable only by the service account.
VyOS API keys have full router permissions. Restrict access to the management
network. Start the bridge and select **Devices → Adopt** in Network.

```sh
export UNIFI_GW_SITE_CONFIG="$HOME/.config/unifi-gateway/site.conf"
export UNIFI_GW_CONFIG="$HOME/.local/state/unifi-gateway/gateway.conf"
python unifi_gateway.py run
```

Keep the generated state file across restarts. The Enterprise profile reports
vendor release `6.0.17` for controller compatibility.

The collector reads live administrative and link state, addresses, traffic counters, uptime,
neighbors, DHCPv4 leases, and installed IPv4 and IPv6 connected and static routes on mapped ports.
The adopted profile answers Network's live Routing Table query with connected routes,
installed operator static routes, and the observed paths for any enabled provisioning scopes.
It also reports installed IPv4 and IPv6 paths from configured VyOS static tables 1–177
with their observed table numbers. Network's pinned logical network allocator starts at 178.
Set a unique `port_idx` on each mapped physical port to publish its observation.
Leave logical interfaces such as `br0` unnumbered.
The profile omits measurements that VyOS could not provide and declines UniFi firmware updates.

### Docker Compose

Create an `enrollment/` directory beside `docker-compose.yml`. Supply
`site.conf`, `vyos-ca.pem`, and `vyos-api-key` as described above. The bridge
runs as UID and GID 10001. Grant that account access to the enrollment
directory and files, keep the API key mode `0600`, and use the same account
for private SSH credentials. Compose mounts the directory read-only and
keeps writable gateway state in a named volume.

```sh
docker compose up --build -d
docker compose logs -f unifi-gateway
```

## Configure features

The enrollment reports real router state by default. To let UniFi change a
managed feature, configure its `vyos_*` section in `site.conf` and restart the
bridge. The sample lists the options, reserved resources and supported port
mappings. Start by enabling the firewall scope and reviewing the unmanaged
baseline before approving the first change.

- [Provisioning, ownership and recovery](docs/provisioning.md)
- [WAN probes and native speed tests](docs/provisioning.md#wan-verification)
- [Shadow Mode setup and current limits](docs/provisioning.md#prepare-the-shadow-mode-router-helpers)
- [Feature coverage and acceptance checks](docs/coverage.md)

## Source layout

| Path | Responsibility |
| --- | --- |
| `unifi_gateway.py`, `unifi_protocol.py` | Discovery, adoption, inform exchange and controller command handling |
| `gateway_profiles/` | Enterprise enrollment, port roles, state reports and native device actions |
| `backends/`, `collectors/` | Authenticated management operations and observed VyOS telemetry |
| `provisioners/` | Decode controller intent, stage owned changes and verify running and saved state |
| `inspection/` | Suricata control, verdict read-back and security event delivery |

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

This fork builds on the following projects.

- [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway) — gateway daemon, packaging and router integrations
- [stephanlascar/unifi-gateway](https://github.com/stephanlascar/unifi-gateway) — original UniFi Gateway emulator
- [qvr/unifi-gateway](https://github.com/qvr/unifi-gateway) — Python 3 port, FreeBSD support, AES-GCM encryption

Protocol documentation:

- [jk-5/unifi-inform-protocol](https://github.com/jk-5/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)
