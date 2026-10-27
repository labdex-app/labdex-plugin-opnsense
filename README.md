# OPNsense

A [labdex](https://github.com/labdex-app/labdex) plugin. Keeps firewall aliases in sync with the inventory, adds hosts to your own aliases, shows the rules that concern a host and which declared access has no rule. Imports the ARP table into Discovery.

**Version** 1.3 · **Works with** labdex >=1.3,<2 · **Plugin id** `opnsense`

> [!WARNING]
> Built with AI, for home labs only: labdex and its plugins were written largely with an AI
> coding assistant (Claude), directed and reviewed by a human. They haven't had an independent
> security audit and may contain security problems. Run them on a trusted home network.

## Install

It ships with labdex: **Plugins › Marketplace**, then *Install* (nothing is downloaded). Updates arrive through the official Marketplace (signed with the labdex project key).

## Settings

| Setting | Notes |
| --- | --- |
| URL | e.g. https://opnsense.mgmt.example.net |
| API key |  |
| API secret |  |
| Verify TLS certificate |  |
| CA bundle path | For an internal CA; leave empty for the system store |
| Delete aliases that left the inventory | Only aliases in the category automation:labdex (or tagged [labdex] by older versions) |
| Take over existing aliases with the same name |  |
| Add members to existing aliases | For aliases you made by hand on the firewall. A member can be an address, a CIDR, another alias, or an inventory host name (its H_ alias is added). labdex only ever removes members it added itself. |
| WAN interface (port forwards) |  |
| Forward traffic to | wanip = the WAN address; or an alias / address for a second public IP |
| Manage Kea DHCP reservations | Hosts with a MAC and an IPv4 address get a reservation in the matching Kea subnet. Only reservations labdex created ([labdex]) are changed. |

## Actions

- **Test connection** (run)
- **Sync aliases** (plan): Compare the firewall's aliases with the inventory and apply the difference
- **Sync policy rules** (plan): Pass rules from the zone matrix and services' 'allow from', in the category automation:labdex (your own rules are never touched)
- **Sync port forwards** (plan): A port forward (with its filter rule) for every service marked public; only the forwards labdex made are changed
- **Check declared access** (run): For every service with 'allow from', look for a pass rule that allows it
- **Import the firewall's aliases** (run): Your own aliases on the firewall become custom aliases in labdex, under their names (nothing is renamed). labdex's and OPNsense's built-in ones are skipped.
- **Import ARP and NDP tables** (run): Adds the IPv4 (ARP) and IPv6 (NDP) neighbours the firewall knows to Discovery
- **Import DHCP leases** (run): Kea DHCPv4 and DHCPv6 leases (address, MAC, hostname) into Discovery
- **Sync DHCP reservations** (plan): Kea DHCPv4 reservations from the inventory's MAC/IP pairs
- **Read delegated IPv6 prefixes** (run): Reads the prefix each WAN interface received (DHCPv6-PD) and moves networks with a delegated prefix to it; DNS and aliases follow

## Releasing

Bump `version` in `plugin.yaml`, add a `## <version>` section to `CHANGELOG.md`, commit, then
publish a GitHub release tagged `v<version>` (web UI, or `gh release create v<version> --target main --notes ""`).
The release workflow signs the plugin with the `LABDEX_SIGNING_KEY` secret, attaches the zip and
`CHANGELOG.md` to the release and puts that version's CHANGELOG section into its description.
Files listed in `.releaseignore` stay out of the zip.
