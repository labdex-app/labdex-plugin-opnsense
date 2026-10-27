"""OPNsense: alias sync, alias membership, rule view and access check.

API privileges the key needs: "Services: Kea DHCP" (leases, reservations), "Firewall: Alias: Edit" (sync), "Firewall: Rules"
read access (rule view, access check; OPNsense 24.7+ MVC rules, all rules
from 26.1), "Diagnostics: ARP Table" (import_arp).
Endpoints used: firewall/alias/{export,addItem,setItem,delItem,reconfigure},
firewall/filter/search_rule, diagnostics/interface/getArp.
"""
import ipaddress
import re
from fnmatch import fnmatchcase

from labdex.generators.opnsense import CATEGORY, MARKER, export as alias_export
from labdex.plugins.base import Change, Plugin as Base, PluginError

ANY4, ANY6 = ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")


def _norm(content) -> list:
    if isinstance(content, str):
        content = content.replace(",", "\n").split("\n")
    return sorted(c.strip() for c in content if c and c.strip())


def _split(v) -> list:
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").replace("\n", ",").split(",") if x.strip()]


class Plugin(Base):
    @property
    def api(self):
        s = self.settings
        return self.ctx.http(s["url"].rstrip("/") + "/api", auth=(s["api_key"], s["api_secret"]))

    def test(self):
        data = self._existing()
        return f"Connected; {len(data)} aliases on the firewall"

    # ------------------------------------------------------------- category
    def _category_uuid(self, create: bool = False) -> str:
        """The firewall category labdex tags its objects with (automation:labdex)."""
        if getattr(self, "_cat", None):
            return self._cat
        try:
            rows = self._search("firewall/category/search_item")
        except PluginError:
            rows = []
        hit = next((r for r in rows if r.get("name") == CATEGORY), None)
        if hit is None and create:
            r = self.api.post("firewall/category/add_item", json={"category": {"name": CATEGORY, "auto": "0", "color": "7c3aed"}}).json()
            if r.get("result") != "saved":
                raise PluginError(f"couldn't create the category {CATEGORY}: {r}")
            self.log(f"created category {CATEGORY}")
            hit = {"uuid": r.get("uuid", "")}
        self._cat = hit["uuid"] if hit else ""
        return self._cat

    def _managed(self, cur: dict) -> bool:
        cats = cur.get("categories") or ""
        cats = cats if isinstance(cats, list) else [c.strip() for c in str(cats).split(",")]
        cat = self._category_uuid()
        return (CATEGORY in cats) or (bool(cat) and cat in cats) or MARKER in (cur.get("description") or "")

    def _existing(self) -> dict:
        r = self.api.get("firewall/alias/export").json()
        rows = (r.get("aliases") or {}).get("alias") or {}
        if not isinstance(rows, dict):
            raise PluginError("unexpected answer from firewall/alias/export")
        return {v["name"]: {"uuid": uuid, **v} for uuid, v in rows.items() if isinstance(v, dict) and v.get("name")}

    # ------------------------------------------------------- alias membership
    def _host_alias_names(self) -> dict:
        """inventory host name and fun name → its H_ alias name (hosts with addresses)."""
        out = {}
        for a in self.ctx.inventory.aliases():
            if a["kind"] == "host" and a["name"].startswith("H_"):
                out[a["source"]] = a["fw_id"]
        for h in self.ctx.inventory.hosts(include_offline=True):
            if h.get("fun") and h["name"] in out:
                out[h["fun"]] = out[h["name"]]
        return out

    def desired_members(self) -> dict:
        """alias on the firewall → {member: why}"""
        hmap = self._host_alias_names()
        want: dict[str, dict] = {}
        for row in self.settings.get("extend_aliases") or []:
            member = hmap.get(row["member"], row["member"])
            want.setdefault(row["alias"], {})[member] = "settings"
        for h in self.ctx.hosts():
            target = hmap.get(h["name"])
            for alias in h["module_settings"].get("member_of") or []:
                if target:
                    want.setdefault(alias, {})[target] = f"host {h['name']}"
                else:
                    self.log(f"{h['name']}: has no addresses, so no alias to add to {alias}")
        return want

    def _membership_changes(self, existing: dict) -> list:
        want = self.desired_members()
        tracked = {k: set(v) for k, v in (self.ctx.state.get("added") or {}).items()}
        changes = []
        for alias in sorted(set(want) | set(tracked)):
            cur = existing.get(alias)
            if cur is None:
                if alias in want:
                    self.log(f"skip members for {alias}: no such alias on the firewall")
                continue
            if self._managed(cur):
                self.log(f"skip members for {alias}: labdex manages that alias; use a custom alias in the inventory instead")
                continue
            content = set(_norm(cur.get("content") or ""))
            desired = set(want.get(alias, {}))
            add = sorted(desired - content)
            remove = sorted((tracked.get(alias, set()) - desired) & content)
            if add or remove:
                parts = ([f"add {', '.join(add)}"] if add else []) + ([f"remove {', '.join(remove)}"] if remove else [])
                after = sorted((content | set(add)) - set(remove))
                changes.append(Change("update", "alias members", alias, "; ".join(parts), sorted(content), after,
                                      {"alias": alias, "add": add, "remove": remove}))
        return changes

    # ----------------------------------------------------------- plan / apply
    def plan_sync_aliases(self, params):
        desired = alias_export()["aliases"]["alias"]  # dependency order
        existing = self._existing()
        changes, order = [], []
        for entry in desired.values():
            name = entry["name"]
            order.append(name)
            entry = {**entry, "description": entry["description"].replace(MARKER, "").strip()}
            want = {"type": entry["type"], "content": _norm(entry["content"]), "description": entry["description"], "enabled": "1"}
            cur = existing.get(name)
            if cur is None:
                changes.append(Change("create", "alias", name, f"create {entry['type']} alias", None, want, {"entry": entry}))
                continue
            managed = self._managed(cur)
            if not managed and not self.settings.get("adopt_existing"):
                self.log(f"skip {name}: exists on the firewall but isn't managed by labdex (enable 'take over' to adopt it)")
                continue
            have = {"type": cur.get("type"), "content": _norm(cur.get("content") or ""), "description": cur.get("description", ""), "enabled": str(cur.get("enabled", "1"))}
            tagged = self._is_managed(cur)
            if have != want or not tagged:
                diff = [k for k in want if have.get(k) != want[k]] or ["category"]
                changes.append(Change("update", "alias", name, f"update {', '.join(diff)}" + ("" if managed else " (take over)"),
                                      have, want, {"entry": entry, "uuid": cur["uuid"]}))
        changes += self._membership_changes(existing)
        if self.settings.get("allow_delete", True):
            wanted = set(order)
            doomed = [c for n, c in existing.items() if n not in wanted and self._managed(c)]
            for cur in reversed(doomed):
                changes.append(Change("delete", "alias", cur["name"], "no longer in the inventory",
                                      {"type": cur.get("type"), "content": _norm(cur.get("content") or "")}, None, {"uuid": cur["uuid"]}))
        if not changes:
            self._settle_tracking(existing)
        return changes

    def _settle_tracking(self, existing):
        """Forget tracked members that are gone or no longer wanted (nothing to apply)."""
        want = self.desired_members()
        tracked = self.ctx.state.get("added") or {}
        new = {a: sorted(set(m) & set(want.get(a, {})) & set(_norm((existing.get(a) or {}).get("content") or "")))
               for a, m in tracked.items()}
        new = {a: m for a, m in new.items() if m}
        if new != tracked:
            self.ctx.set_state("added", new)

    def apply_sync_aliases(self, changes, params):
        api, errors, done = self.api, [], 0
        tracked = {k: set(v) for k, v in (self.ctx.state.get("added") or {}).items()}
        if any(c.op in ("create", "update") and c.kind == "alias" for c in changes):
            self._category_uuid(create=True)
        for c in changes:
            try:
                if c.kind == "alias members":
                    cur = self._existing().get(c.data["alias"])  # re-read: don't clobber edits made meanwhile
                    if cur is None:
                        raise PluginError("alias disappeared")
                    content = (set(_norm(cur.get("content") or "")) | set(c.data["add"])) - set(c.data["remove"])
                    r = api.post(f"firewall/alias/setItem/{cur['uuid']}", json={"alias": {
                        "enabled": str(cur.get("enabled", "1")), "name": cur["name"], "type": cur.get("type"),
                        "content": "\n".join(sorted(content)), "description": cur.get("description", "")}}).json()
                    self._check(r, c)
                    t = (tracked.get(c.data["alias"], set()) | set(c.data["add"])) - set(c.data["remove"])
                    tracked[c.data["alias"]] = t
                elif c.op == "create":
                    r = api.post("firewall/alias/addItem", json={"alias": self._payload(c.data["entry"])}).json()
                    self._check(r, c)
                elif c.op == "update":
                    r = api.post(f"firewall/alias/setItem/{c.data['uuid']}", json={"alias": self._payload(c.data["entry"])}).json()
                    self._check(r, c)
                elif c.op == "delete":
                    r = api.post(f"firewall/alias/delItem/{c.data['uuid']}").json()
                    if r.get("result") not in ("deleted", "saved"):
                        raise PluginError(f"{r}")
                done += 1
                self.log(f"{c.op} {c.name}: ok")
            except PluginError as exc:
                errors.append(f"{c.op} {c.name}: {exc}")
                self.log(f"{c.op} {c.name}: FAILED {exc}")
        self.ctx.set_state("added", {a: sorted(m) for a, m in tracked.items() if m})
        r = api.post("firewall/alias/reconfigure").json()
        self.log(f"reconfigure: {r.get('status', r)}")
        if errors:
            raise PluginError(f"{len(errors)} of {len(changes)} change(s) failed: " + "; ".join(errors[:5]))
        return {"applied": done}

    def _payload(self, entry: dict) -> dict:
        return {"enabled": "1", "name": entry["name"], "type": entry["type"], "content": entry["content"],
                "description": entry["description"].replace(MARKER, "").strip(), "categories": self._category_uuid()}

    @staticmethod
    def _check(r: dict, c):
        if r.get("result") != "saved":
            details = r.get("validations") or r
            raise PluginError(f"rejected: {details}")

    # ------------------------------------------------------------------ rules
    def _rules(self) -> list:
        try:
            return self._search("firewall/filter/search_rule")
        except PluginError as exc:
            raise PluginError(f"{exc} (needs OPNsense 24.7 or later)") from exc

    def _is_managed(self, row: dict) -> bool:
        """Rules and aliases carry category UUIDs (comma separated); old setups may show names."""
        cats = str(row.get("categories") or "")
        uuid = self._category_uuid()
        return bool(uuid and uuid in cats.split(",")) or CATEGORY in cats

    class _Resolver:
        def __init__(self, aliases: dict):
            self.aliases = aliases

        def nets(self, token: str, seen=None) -> list:
            token = (token or "").strip()
            if token in ("", "any", "*"):
                return [ANY4, ANY6]
            seen = seen or set()
            if token in self.aliases and token not in seen:
                seen.add(token)
                out = []
                for m in _norm(self.aliases[token].get("content") or ""):
                    out += self.nets(m, seen)
                return out
            try:
                return [ipaddress.ip_network(token, strict=False)]
            except ValueError:
                return []  # interface macros (lan, wan_ip), hostnames: not resolvable here

        def ports(self, token: str, seen=None):
            """None = any port, else a list of (lo, hi)."""
            token = (token or "").strip()
            if token in ("", "any", "*"):
                return None
            seen = seen or set()
            if token in self.aliases and token not in seen:
                seen.add(token)
                out = []
                for m in _norm(self.aliases[token].get("content") or ""):
                    p = self.ports(m, seen)
                    if p is None:
                        return None
                    out += p
                return out
            out = []
            for part in token.split(","):
                part = part.strip().replace(":", "-")
                try:
                    lo, _, hi = part.partition("-")
                    out.append((int(lo), int(hi or lo)))
                except ValueError:
                    pass  # named ports like 'https' aren't resolved
            return out

    @staticmethod
    def _f(rule, *keys):
        for k in keys:
            if rule.get(k) not in (None, ""):
                return rule[k]
        return ""

    def _rule_sides(self, rule, res):
        src = _split(self._f(rule, "source_net", "source"))
        dst = _split(self._f(rule, "destination_net", "destination"))
        return ([n for t in (src or ["any"]) for n in res.nets(t)], [n for t in (dst or ["any"]) for n in res.nets(t)], src or ["any"], dst or ["any"])

    @staticmethod
    def _covers(nets, ip) -> bool:
        return any(ip.version == n.version and ip in n for n in nets)

    @staticmethod
    def _inbound(rule) -> bool:
        """Access to a host is decided where traffic enters the firewall. Rules with direction 'out'
        (e.g. the built-in "let out anything from firewall host itself", which has no source and so
        looks like any → any) only pass traffic leaving an interface and never let a client in."""
        return str(rule.get("direction") or "in").lower() in ("in", "any", "both")

    def _allowed(self, rule, res, src_nets, host_ips, port, proto) -> bool:
        if str(rule.get("enabled", "1")) not in ("1", "true", "True"):
            return False
        if not self._inbound(rule):
            return False
        if str(rule.get("action", "pass")).lower() != "pass":
            return False
        if str(rule.get("source_not", "0")) == "1" or str(rule.get("destination_not", "0")) == "1":
            return False
        rproto = str(rule.get("protocol") or "any").lower()
        if rproto not in ("any", "", proto, "tcp/udp"):
            return False
        rs, rd, _, _ = self._rule_sides(rule, res)
        if not any(self._covers(rd, ip) for ip in host_ips):
            return False
        for sn in src_nets:
            if not any(sn.version == n.version and sn.subnet_of(n) for n in rs):
                return False
        ports = res.ports(self._f(rule, "destination_port"))
        return ports is None or port is None or any(lo <= port <= hi for lo, hi in ports)

    def _source_nets(self, token: str, res, networks: list, host_versions: set):
        if token.lower() == "any":
            nets = [ANY4, ANY6]
        else:
            zone_nets = [n for n in networks if fnmatchcase(n["zone"], token.upper())]
            named = [n for n in networks if n["name"] == token]
            picked = zone_nets or named
            if picked:
                nets = [ipaddress.ip_network(p["prefix"]) for n in picked for p in n.get("prefixes") or [] if p.get("prefix")] \
                    or [ipaddress.ip_network(p) for n in picked for p in (n.get("prefix4"), n.get("prefix6")) if p]
            else:
                nets = res.nets(token) if token in res.aliases else []
                if not nets:
                    try:
                        nets = [ipaddress.ip_network(token, strict=False)]
                    except ValueError:
                        return None  # unknown
        return [n for n in nets if n.version in host_versions]

    def access_report(self, host: dict, aliases: dict, rules: list, networks: list) -> list:
        res = self._Resolver(aliases)
        ips = list(dict.fromkeys(ipaddress.ip_address(a) for i in host["interfaces"] for a in [i.get("ip4"), *(i.get("ip6_all") or [i.get("ip6")])] if a))
        versions = {ip.version for ip in ips}
        out = []
        all_ips = ips
        for s in host["services"]:
            # a service bound to some addresses only needs to be reachable there
            ips = [ipaddress.ip_address(a) for a in s.get("addresses") or []] if s.get("bind") else all_ips
            versions = {ip.version for ip in ips}
            for token in s.get("allow_from") or []:
                row = {"service": s["name"], "port": f"{s['port'] or 'any'}/{s['proto']}", "from": token}
                src = self._source_nets(token, res, networks, versions)
                if not ips:
                    row.update(status="host has no address", _tone="warn")
                elif src is None:
                    row.update(status="unknown source (not a zone, network, alias or CIDR)", _tone="warn")
                elif not src:
                    row.update(status="source has no addresses in the host's address family", _tone="")
                else:
                    per_family = {}
                    for fam in sorted({n.version for n in src}):
                        fam_src = [n for n in src if n.version == fam]
                        fam_ips = [ip for ip in ips if ip.version == fam]
                        per_family[fam] = next((r for r in rules if self._allowed(r, res, fam_src, fam_ips, s["port"], s["proto"])), None)
                    hits = [r for r in per_family.values() if r]
                    names = list(dict.fromkeys(r.get("description") or r.get("uuid", "") for r in hits))
                    if hits and len(hits) == len(per_family):
                        row.update(status="allowed", rule="; ".join(names), _tone="ok")
                    elif hits:
                        ok = ", ".join(f"IPv{f}" for f, r in per_family.items() if r)
                        no = ", ".join(f"IPv{f}" for f, r in per_family.items() if not r)
                        row.update(status=f"{ok} allowed, {no}: no pass rule", rule="; ".join(names), _tone="warn")
                    else:
                        row.update(status="no pass rule found", _tone="err")
                out.append(row)
        return out

    def run_check_access(self, params):
        aliases, rules, networks = self._existing(), self._rules(), self.ctx.inventory.networks()
        missing = []
        for h in self.ctx.hosts():
            for row in self.access_report(h, aliases, rules, networks):
                if row["_tone"] == "err" or (row["_tone"] == "warn" and "allowed" in row["status"]):
                    missing.append(f"{h['name']} {row['service']} ({row['port']}) from {row['from']}: {row['status']}")
        for m in missing:
            self.log(f"missing: {m}")
        managed = [z["zone"] for z in self.zone_report() if z["_tone"] == "ok"]
        if managed:
            self.log("zones managed by labdex (every inbound pass rule from labdex, no access gaps): " + ", ".join(managed))
        return {"missing": len(missing), "zones_managed": managed,
                "message": f"{len(missing)} declared access path(s) without a pass rule" if missing else "Every declared access has a pass rule"}

    def host_view(self, host: dict) -> dict:
        try:
            aliases, rules = self._existing(), self._rules()
        except PluginError as exc:
            return {"error": str(exc)}
        res = self._Resolver(aliases)
        ips = list(dict.fromkeys(ipaddress.ip_address(a) for i in host["interfaces"] for a in [i.get("ip4"), *(i.get("ip6_all") or [i.get("ip6")])] if a))
        member_of = sorted(n for n in aliases if any(self._covers(res.nets(n), ip) for ip in ips)
                           and not any(x in (ANY4, ANY6) for x in res.nets(n)))
        rows = []
        for r in rules:
            rs, rd, src, dst = self._rule_sides(r, res)
            to_host = any(self._covers([n for n in rd if n not in (ANY4, ANY6)], ip) for ip in ips)
            from_host = any(self._covers([n for n in rs if n not in (ANY4, ANY6)], ip) for ip in ips)
            if not (to_host or from_host):
                continue
            enabled = str(r.get("enabled", "1")) in ("1", "true", "True")
            action = str(r.get("action", "pass")).lower()
            out_rule = not self._inbound(r)
            rows.append({
                "labdex": "✓" if self._is_managed(r) else "",
                "dir": "out" if out_rule else "in",
                "direction": "to host" if to_host and not from_host else "from host" if from_host and not to_host else "both",
                "action": action + ("" if enabled else " (disabled)"), "interface": self._f(r, "interface"),
                "source": ("! " if str(r.get("source_not")) == "1" else "") + ", ".join(src),
                "destination": ("! " if str(r.get("destination_not")) == "1" else "") + ", ".join(dst),
                "port": self._f(r, "destination_port") or "any", "proto": self._f(r, "protocol") or "any",
                "description": self._f(r, "description", "descr"),
                "_tone": "" if not enabled or out_rule else ("ok" if action == "pass" else "err"),
            })
        access = self.access_report(host, aliases, rules, self.ctx.inventory.networks())
        missing = sum(1 for a in access if a["_tone"] == "err" or (a["_tone"] == "warn" and "allowed" in a["status"]))
        sections = [
            {"title": "Access check", "type": "table",
             "columns": [{"key": "service", "label": "Service"}, {"key": "port", "label": "Port"}, {"key": "from", "label": "Allow from"},
                         {"key": "status", "label": "Result"}, {"key": "rule", "label": "Rule"}],
             "rows": access, "empty": "No service on this host declares 'allow from'. Add it on the host's services to check the firewall."},
            {"title": "Rules that mention this host", "type": "table",
             "columns": [{"key": "direction", "label": ""}, {"key": "dir", "label": "Dir"}, {"key": "action", "label": "Action"}, {"key": "interface", "label": "Interface"},
                         {"key": "source", "label": "Source"}, {"key": "destination", "label": "Destination"},
                         {"key": "port", "label": "Port"}, {"key": "proto", "label": "Proto"}, {"key": "description", "label": "Description"},
                         {"key": "labdex", "label": "labdex"}],
             "rows": rows, "empty": "No rule names this host, its aliases or a network narrower than 'any'."},
            {"title": "Aliases on the firewall that contain this host", "type": "list", "items": member_of},
        ]
        return {
            "summary": [{"label": "missing access", "value": missing, "tone": "err" if missing else "ok"},
                        {"label": "rules", "value": len(rows), "tone": ""},
                        {"label": "aliases", "value": len(member_of), "tone": ""}],
            "sections": sections,
            "note": "Rules are matched by address, not evaluated in order: a block rule above a pass rule and the interface aren't considered. "
                    "Only inbound rules count for access; outbound ones (like 'let out anything from firewall host itself') are listed but never grant it.",
        }

    # ------------------------------------------------------------- Kea DHCP
    def _search(self, path):
        """Grid searches read rowCount/current from the JSON body (POST); GET is the fallback for older builds."""
        body = {"rowCount": -1, "current": 1}
        try:
            r = self.api.post(path, json=body).json()
        except PluginError:
            r = self.api.get(path, params=body).json()
        rows = r.get("rows") if isinstance(r, dict) else None
        if not isinstance(rows, list):
            raise PluginError(f"unexpected answer from {path}")
        return rows

    # ------------------------------------------------------------ policy rules
    def _interface_map(self) -> dict[str, str]:
        """inventory network → OPNsense interface (lan, opt1, …), by subnet or VLAN tag."""
        from labdex.models import Network, db
        rows = self._search("interfaces/overview/interfaces_info")
        by_net, by_vlan = {}, {}
        for r in rows:
            ident = r.get("identifier")
            if not ident:
                continue
            for fam in ("ipv4", "ipv6"):
                for e in r.get(fam) or []:
                    try:
                        by_net[ipaddress.ip_interface(e.get("ipaddr", "")).network] = ident
                    except ValueError:
                        pass
            if r.get("vlan_tag") not in (None, ""):
                by_vlan[int(r["vlan_tag"])] = ident
        out = {}
        for n in db.session.scalars(db.select(Network)):
            hit = None
            for p in n.prefixes:
                try:
                    hit = by_net.get(ipaddress.ip_network(p.prefix, strict=False)) if p.prefix else None
                except ValueError:
                    hit = None
                if hit:
                    break
            hit = hit or (by_vlan.get(n.vlan) if n.vlan is not None else None)
            if hit:
                out[n.name] = hit
        return out

    def desired_rules(self) -> dict[str, dict]:
        """key → rule: one per zone-matrix entry, one per service 'allow from' the matrix doesn't already cover."""
        from labdex import naming, policy
        from labdex.generators import aliases as galiases
        from labdex.models import AliasGroup, Host, Network, db
        fw = {a.name: a.fw_id for a in galiases.all_aliases()}
        ifmap = self._interface_map()
        nets = list(db.session.scalars(db.select(Network)))
        zone_ifs = {}
        for n in nets:
            if n.name in ifmap:
                zone_ifs.setdefault(n.zone, set()).add(ifmap[n.name])
        all_ifs = sorted(set(ifmap.values()))
        port_aliases = {g.name for g in db.session.scalars(db.select(AliasGroup).where(AliasGroup.type == "port"))}
        out: dict[str, dict] = {}

        def rule(key, human, ifs, src, dst, proto="any", port=""):
            out[key] = {"enabled": "1", "action": "pass", "quick": "1", "direction": "in", "ipprotocol": "inet46",
                        "interface": ",".join(sorted(ifs)), "protocol": proto, "source_net": src, "destination_net": dst,
                        "destination_port": port, "description": f"{human} [{key}]"}

        for c in policy.cells():
            ifs = zone_ifs.get(c.src)
            if not ifs:
                self.log(f"zone {c.src}: no interface on this firewall, skipped {c.src} → {c.dst}")
                continue
            src, dst = fw.get(naming.zone_group(c.src), naming.zone_group(c.src)), fw.get(naming.zone_group(c.dst), naming.zone_group(c.dst))
            why = f" ({c.description})" if c.description else ""
            for p in c.ports:
                m = policy.PORT_RE.match(p)
                if p == "any":
                    rule(f"zone:{c.src}>{c.dst}", f"{c.src} → {c.dst}{why}", ifs, src, dst)
                elif m:
                    port = m.group(2) + (f":{m.group(4)}" if m.group(4) else "")
                    rule(f"zone:{c.src}>{c.dst}:{p}", f"{c.src} → {c.dst} {p}{why}", ifs, src, dst, m.group(1).upper(), port)
                elif p in port_aliases:
                    rule(f"zone:{c.src}>{c.dst}:{p}", f"{c.src} → {c.dst} {p}{why}", ifs, src, dst, "TCP/UDP", fw.get(p, p))

        areas = {z.split("_")[0] for z in naming.all_zones()}

        def peer(t):
            """A zone, area, network, alias, CIDR or any → (its name on the firewall, the interfaces it comes in on)."""
            src_zones = [z for z in naming.all_zones() if z == t.upper() or z.split("_")[0] == t.upper()] if t.upper() in set(naming.all_zones()) | areas else []
            net = next((n for n in nets if n.name == t), None)
            if src_zones:
                ref = naming.zone_group(t.upper()) if t.upper() in set(naming.all_zones()) else naming.area_group(t.upper())
                return src_zones, fw.get(ref, ref), set().union(*(zone_ifs.get(z, set()) for z in src_zones))
            if net is not None:
                return [], fw.get(naming.network_alias(net), naming.network_alias(net)), ({ifmap[net.name]} if net.name in ifmap else set())
            if t.lower() == "any":
                return [], "any", set(all_ifs)
            return [], fw.get(t, t), set(all_ifs)  # an alias or a CIDR: wherever it may come from

        def port_args(p):
            m = policy.PORT_RE.match(p)
            if p == "any":
                return "any", ""
            if m:
                return m.group(1).upper(), m.group(2) + (f":{m.group(4)}" if m.group(4) else "")
            return "TCP/UDP", fw.get(p, p)

        for h in db.session.scalars(db.select(Host).order_by(Host.name)):
            dst = fw.get(naming.host_alias(h), naming.host_alias(h))
            for s in h.services:
                if not s.port or not s.allow_from:
                    continue
                proto = (s.proto or "tcp").upper()
                for t in s.allow_from:
                    src_zones, src, ifs = peer(t)
                    if any(policy.allows(z, h.zone, s.port, proto.lower()) for z in src_zones):
                        continue  # the matrix already lets it through
                    if not ifs:
                        self.log(f"{h.name} {s.name}: no interface for '{t}', skipped")
                        continue
                    rule(f"svc:{h.name}/{s.name}:{t}", f"{t} → {h.name} {s.name}", ifs, src, dst, proto, str(s.port))
            # the host's own rules: anything from / to a peer, on ports
            own_ifs = {ifmap[i.network.name] for i in h.interfaces if i.network is not None and i.network.name in ifmap}
            for r in h.rules or []:
                t, why = r.get("peer", ""), f" ({r['description']})" if r.get("description") else ""
                _, other, ifs = peer(t)
                for p in r.get("ports") or ["any"]:
                    proto, port = port_args(p)
                    if r.get("direction") == "out":
                        if not own_ifs:
                            self.log(f"{h.name}: no interface on this firewall for its own networks, skipped {h.name} → {t}")
                            continue
                        rule(f"host:{h.name}>{t}:{p}", f"{h.name} → {t} {p}{why}", own_ifs, dst, other, proto, port)
                    else:
                        if not ifs:
                            self.log(f"{h.name}: no interface for '{t}', skipped {t} → {h.name}")
                            continue
                        rule(f"host:{t}>{h.name}:{p}", f"{t} → {h.name} {p}{why}", ifs, other, dst, proto, port)
        return out

    KEY_RE = re.compile(r"\[((?:zone|svc|host):[^\]]+)\]\s*$")
    RULE_FIELDS = ("enabled", "action", "quick", "direction", "ipprotocol", "interface", "protocol", "source_net",
                   "destination_net", "destination_port", "description")

    def _managed_rules(self) -> dict[str, dict]:
        out = {}
        for r in self._rules():
            if not self._is_managed(r):
                continue
            m = self.KEY_RE.search(r.get("description") or "")
            out[m.group(1) if m else f"orphan:{r.get('uuid')}"] = r
        return out

    @staticmethod
    def _norm_rule(r: dict) -> dict:
        out = {}
        for k in Plugin.RULE_FIELDS:
            v = r.get(k, "")
            if isinstance(v, dict):  # get_rule style {option: {value, selected}}
                v = ",".join(sorted(o for o, x in v.items() if isinstance(x, dict) and x.get("selected")))
            v = str(v if v is not None else "")
            if k == "interface":
                v = ",".join(sorted(x for x in v.split(",") if x))
            if k == "protocol" and v.lower() == "any":
                v = "any"
            out[k] = v
        return out

    def plan_sync_rules(self, params):
        want = self.desired_rules()
        have = self._managed_rules()
        changes = []
        for key, w in sorted(want.items()):
            cur = have.get(key)
            if cur is None:
                changes.append(Change("create", "rule", w["description"], f"{w['interface']}: {w['source_net']} → {w['destination_net']} {w['protocol']} {w['destination_port']}".strip(),
                                      after=w, data={"key": key}))
                continue
            a, b = self._norm_rule(cur), self._norm_rule(w)
            diff = [k for k in self.RULE_FIELDS if a.get(k) != b.get(k)]
            if diff:
                changes.append(Change("update", "rule", w["description"], "changes " + ", ".join(diff), before={k: a[k] for k in diff},
                                      after={k: b[k] for k in diff}, data={"key": key, "uuid": cur.get("uuid")}))
        for key, cur in sorted(have.items()):
            if key not in want:
                changes.append(Change("delete", "rule", cur.get("description") or key, "no policy asks for it any more",
                                      data={"key": key, "uuid": cur.get("uuid")}))
        return changes

    def apply_sync_rules(self, changes, params):
        want = self.desired_rules()
        cat = self._category_uuid(create=True)
        done = 0
        for c in changes:
            key = c.data["key"]
            if c.op == "delete":
                r = self.api.post(f"firewall/filter/del_rule/{c.data['uuid']}").json()
                if r.get("result") not in ("deleted", "saved"):
                    raise PluginError(f"delete {c.name}: {r}")
            else:
                payload = {**want[key], "categories": cat}
                path = "firewall/filter/add_rule" if c.op == "create" else f"firewall/filter/set_rule/{c.data['uuid']}"
                self._check(self.api.post(path, json={"rule": payload}).json(), c)
            self.log(f"{c.op} {c.name}")
            done += 1
        r = self.api.post("firewall/filter/apply").json()
        self.log(f"apply: {r.get('status', r)}")
        return {"applied": done}

    # --------------------------------------------------------- port forwards
    def desired_nat(self) -> dict[str, dict]:
        """key → port forward, for every service marked public."""
        from labdex import store
        from labdex.models import Host, db
        out = {}
        wan = self.settings.get("wan_interface") or "wan"
        dest = self.settings.get("nat_destination") or "wanip"
        for h in db.session.scalars(db.select(Host).where(Host.status == "active").order_by(Host.name)):
            for s in h.services:
                if not s.public or not s.port:
                    continue
                v4 = next((a for a in store.service_addresses(h, s) if ":" not in a), None)
                if v4 is None:
                    self.log(f"{h.name} {s.name}: no IPv4 address to forward to, skipped (IPv6 needs no NAT: allow it with a rule)")
                    continue
                key = f"nat:{h.name}/{s.name}"
                ext = str(s.public_port or s.port)
                out[key] = {"interface": wan, "ipprotocol": "inet", "protocol": (s.proto or "tcp").upper(),
                            "source": {"network": "any"}, "destination": {"network": dest, "port": ext},
                            "target": v4, "local-port": str(s.port), "pass": "pass",
                            "descr": f"{s.public_name or h.name} {s.name} → {h.name}:{s.port} [{key}]"}
        return out

    @staticmethod
    def _nat_flat(r: dict) -> dict:
        def g(*keys):
            for k in keys:
                cur = r
                for part in k.split("."):
                    cur = cur.get(part) if isinstance(cur, dict) else None
                if cur not in (None, ""):
                    return str(cur)
                if k in r and r[k] not in (None, ""):
                    return str(r[k])
            return ""
        return {"interface": g("interface"), "protocol": g("protocol").upper(), "destination": g("destination.network", "destination"),
                "port": g("destination.port", "destination_port"), "target": g("target"), "local_port": g("local-port", "local_port"),
                "descr": g("descr", "description")}

    def plan_sync_nat(self, params):
        want = self.desired_nat()
        have = {}
        for r in self._search("firewall/d_nat/search_rule"):
            m = re.search(r"\[(nat:[^\]]+)\]\s*$", r.get("descr") or r.get("description") or "")
            if m:
                have[m.group(1)] = r
        changes = []
        for key, w in sorted(want.items()):
            cur = have.get(key)
            if cur is None:
                changes.append(Change("create", "port forward", w["descr"], f"{w['interface']} {w['protocol']} {w['destination']['port']} → {w['target']}:{w['local-port']}",
                                      after=w, data={"key": key}))
                continue
            a, b = self._nat_flat(cur), self._nat_flat(w)
            diff = [k for k in b if a.get(k) != b.get(k)]
            if diff:
                changes.append(Change("update", "port forward", w["descr"], "changes " + ", ".join(diff), before={k: a[k] for k in diff},
                                      after={k: b[k] for k in diff}, data={"key": key, "uuid": cur.get("uuid")}))
        for key, cur in sorted(have.items()):
            if key not in want:
                changes.append(Change("delete", "port forward", cur.get("descr") or key, "the service isn't public any more",
                                      data={"key": key, "uuid": cur.get("uuid")}))
        return changes

    def apply_sync_nat(self, changes, params):
        want = self.desired_nat()
        self._category_uuid(create=True)
        done = 0
        for c in changes:
            if c.op == "delete":
                r = self.api.post(f"firewall/d_nat/del_rule/{c.data['uuid']}").json()
                if r.get("result") not in ("deleted", "saved"):
                    raise PluginError(f"delete {c.name}: {r}")
            else:
                payload = {**want[c.data["key"]], "category": CATEGORY}
                path = "firewall/d_nat/add_rule" if c.op == "create" else f"firewall/d_nat/set_rule/{c.data['uuid']}"
                self._check(self.api.post(path, json={"rule": payload}).json(), c)
            self.log(f"{c.op} {c.name}")
            done += 1
        r = self.api.post("firewall/d_nat/apply").json()
        self.log(f"apply: {r.get('status', r)}")
        return {"applied": done}

    def policy_drift(self) -> list[dict]:
        """Pass rules not made by labdex whose zones the matrix doesn't allow (or can't place)."""
        from labdex import policy
        from labdex.models import Network, db
        res = self._Resolver(self._existing())
        zone_nets = []
        for n in db.session.scalars(db.select(Network)):
            for p in n.prefixes:
                try:
                    zone_nets.append((ipaddress.ip_network(p.prefix, strict=False), n.zone)) if p.prefix else None
                except ValueError:
                    pass

        def zones_of(nets):
            if any(n.prefixlen == 0 for n in nets):
                return {"*"}
            return {z for n in nets for zn, z in zone_nets if zn.version == n.version and (n.subnet_of(zn) or zn.subnet_of(n))}

        cells = {(c.src, c.dst) for c in policy.cells()}
        out = []
        for r in self._rules():
            if self._is_managed(r) or str(r.get("action", "pass")).lower() != "pass" or str(r.get("enabled", "1")) == "0" or not self._inbound(r):
                continue
            src_nets, dst_nets, src_t, dst_t = self._rule_sides(r, res)
            sz, dz = zones_of(src_nets), zones_of(dst_nets)
            if not sz or not dz:
                continue  # not between inventory networks (e.g. to the firewall itself, or outside)
            pairs = {(a, b) for a in sz for b in dz}
            if "*" in sz or "*" in dz:
                why = "any → " + ", ".join(sorted(dz)) if "*" in sz else ", ".join(sorted(sz)) + " → any"
            else:
                missing = sorted(f"{a} → {b}" for a, b in pairs if (a, b) not in cells)
                if not missing:
                    continue
                why = "the matrix has no " + ", ".join(missing[:4])
            out.append({"rule": r.get("description") or r.get("uuid", ""), "interface": r.get("interface", ""),
                        "from": " ".join(src_t), "to": " ".join(dst_t), "why": why})
        return out

    def zone_report(self) -> list[dict]:
        """Per zone: is every inbound pass rule on its interfaces made by labdex, and does every
        declared access to its hosts have a pass rule? Both → the zone is managed by labdex."""
        from labdex.models import Network, db
        ifmap = self._interface_map()
        zone_ifs: dict[str, set] = {}
        for n in db.session.scalars(db.select(Network)):
            if n.name in ifmap:
                zone_ifs.setdefault(n.zone, set()).add(ifmap[n.name])
        aliases, rules, networks = self._existing(), self._rules(), self.ctx.inventory.networks()
        gaps: dict[str, int] = {}
        for h in self.ctx.hosts():
            for row in self.access_report(h, aliases, rules, networks):
                if row["_tone"] == "err" or (row["_tone"] == "warn" and "allowed" in row["status"]):
                    gaps[h["zone"]] = gaps.get(h["zone"], 0) + 1
        out = []
        for zone in sorted(set(zone_ifs) | set(gaps)):
            ifs = zone_ifs.get(zone, set())
            mine = other = 0
            for r in rules:
                if str(r.get("enabled", "1")) == "0" or str(r.get("action", "pass")).lower() != "pass" or not self._inbound(r):
                    continue
                if not ifs & set(_split(r.get("interface") or "")):
                    continue
                if self._is_managed(r):
                    mine += 1
                else:
                    other += 1
            ok = bool(ifs) and not other and not gaps.get(zone)
            state = "managed by labdex" if ok else ("no interface on this firewall" if not ifs else "not yet")
            out.append({"zone": zone, "interfaces": ", ".join(sorted(ifs)), "labdex": mine, "other": other,
                        "gaps": gaps.get(zone, 0), "state": state, "_tone": "ok" if ok else ("" if not ifs else "warn")})
        return out

    def page_policy(self, args):
        try:
            plan = self.plan_sync_rules({})
            drift = self.policy_drift()
            zones = self.zone_report()
        except PluginError as exc:
            return {"summary": [], "sections": [], "note": f"Couldn't read the firewall: {exc}"}
        managed = sum(1 for z in zones if z["_tone"] == "ok")
        return {"summary": [{"label": "rule changes pending", "value": len(plan), "tone": "warn" if plan else "ok"},
                            {"label": "rules no policy explains", "value": len(drift), "tone": "warn" if drift else "ok"},
                            {"label": "zones managed by labdex", "value": f"{managed} of {sum(1 for z in zones if z['interfaces'])}",
                             "tone": "ok" if managed else ""}],
                "sections": [
                    {"title": "Zones", "type": "table",
                     "columns": [{"key": "zone", "label": "Zone"}, {"key": "interfaces", "label": "Interfaces"},
                                 {"key": "labdex", "label": "labdex rules"}, {"key": "other", "label": "Other pass rules"},
                                 {"key": "gaps", "label": "Access gaps"}, {"key": "state", "label": "State"}],
                     "rows": zones, "empty": "No zone has a network on this firewall's interfaces."},
                    {"title": "What “Sync policy rules” would change", "type": "table",
                     "columns": [{"key": "op", "label": "Op"}, {"key": "name", "label": "Rule"}, {"key": "summary", "label": "Change"}],
                     "rows": [c.as_dict() for c in plan], "empty": "The firewall's labdex rules match the policy."},
                    {"title": "Rules no policy explains", "type": "table",
                     "columns": [{"key": "rule", "label": "Rule"}, {"key": "interface", "label": "Interface"}, {"key": "from", "label": "From"},
                                 {"key": "to", "label": "To"}, {"key": "why", "label": "Why"}],
                     "rows": [d | {"_tone": "warn"} for d in drift], "empty": "Every pass rule between zones is covered by the matrix."}],
                "note": "labdex only writes rules in the category automation:labdex; your own rules are listed here, never changed."}

    # ------------------------------------------------------ prefix delegation
    def received_prefixes(self) -> dict[str, str]:
        """{interface identifier (wan, opt1, …) and its description: the IPv6 prefix it received}
        from interfaces/overview/interfaces_info: "ifctl.prefix" is a list (Autoconf::all, from /tmp/<dev>_prefixv6)."""
        out = {}
        for row in self._search("interfaces/overview/interfaces_info"):
            pd = row.get("ifctl.prefix")
            if isinstance(pd, list):
                pd = next((x for x in pd if x), "")
            pd = str(pd or "").strip()
            if not pd:
                continue
            for key in (row.get("identifier"), row.get("description"), row.get("device")):
                if key:
                    out.setdefault(str(key).lower(), pd)
        return out

    def run_sync_prefixes(self, params):
        received = self.received_prefixes()
        if not received:
            self.log("no interface reports a delegated prefix (DHCPv6-PD on the WAN?)")
        for k, v in received.items():
            self.log(f"{k}: received {v}")
        res = self.ctx.inventory.apply_delegated_prefixes(received, f"from {self.ctx.name}")
        for c in res["changed"]:
            self.log(f"{c['network']}: {c['from'] or 'unknown'} → {c['to']}")
        for p in res["problems"]:
            self.log(f"skipped {p}")
        return {"changed": len(res["changed"]), "unchanged": res["unchanged"], "problems": len(res["problems"])}

    def run_import_leases(self, params):
        """Kea leases: DHCPv4 always, DHCPv6 when it runs (address leases only, not delegated prefixes)."""
        try:
            rows = self._search("kea/leases4/search")
        except PluginError as exc:
            raise PluginError(f"{exc} (is Kea DHCPv4 enabled on the firewall?)") from exc
        entries = [{"ip": r.get("address"), "mac": r.get("hwaddr") or r.get("hw_address") or "",
                    "hostname": (r.get("hostname") or "").rstrip("."), "vendor": r.get("mac_info") or ""} for r in rows if r.get("address")]
        try:
            rows6 = self._search("kea/leases6/search")
        except PluginError as exc:
            rows6 = []
            self.log(f"no DHCPv6 leases ({exc})")
        v6 = [{"ip": r.get("address"), "mac": r.get("hwaddr") or "", "hostname": (r.get("hostname") or "").rstrip("."),
               "vendor": r.get("mac_info") or ""}
              for r in rows6 if r.get("address") and str(r.get("type", "IA_NA")).upper() != "IA_PD" and int(r.get("prefix_len") or 128) == 128]
        n = self.ctx.discovery.record_neighbours(f"kea:{self.ctx.name}", entries + v6)
        self.log(f"{len(entries)} DHCPv4 and {len(v6)} DHCPv6 leases imported")
        return {"leases": n} if not v6 else {"leases": n, "leases6": len(v6)}

    def plan_sync_reservations(self, params):
        if not self.settings.get("kea_reservations"):
            self.log("managing Kea reservations is switched off in the settings")
            return []
        subnets = {}
        for r in self._search("kea/dhcpv4/search_subnet"):
            try:
                subnets[ipaddress.ip_network(r.get("subnet", ""), strict=False)] = r["uuid"]
            except (ValueError, KeyError):
                pass
        selected = {h["name"] for h in self.ctx.hosts()}
        want = {}
        for r in self.ctx.inventory.dhcp_reservations():
            if r["hostname"] not in selected:
                continue
            ip = ipaddress.ip_address(r["ip"])
            subnet = next((u for n, u in subnets.items() if ip.version == n.version and ip in n), None)
            if subnet is None:
                continue
            want[r["mac"].lower()] = {"subnet": subnet, "ip_address": r["ip"], "hw_address": r["mac"].lower(),
                                      "hostname": r["hostname"], "description": f"{r['description'] or r['hostname']} {MARKER}".strip()}
        have = {}
        for r in self._search("kea/dhcpv4/search_reservation"):
            have[(r.get("hw_address") or "").lower()] = r
        changes = []
        for mac, w in want.items():
            cur = have.get(mac)
            if cur is not None and MARKER not in (cur.get("description") or ""):
                self.log(f"skip {w['hostname']}: {mac} already has a hand-made reservation ({cur.get('ip_address')})")
                continue
            clash = next((r for r in have.values() if r.get("ip_address") == w["ip_address"] and (r.get("hw_address") or "").lower() != mac), None)
            if clash is not None and MARKER not in (clash.get("description") or ""):
                self.log(f"skip {w['hostname']}: {w['ip_address']} is reserved by hand for {clash.get('hw_address')}")
                continue
            if cur is None:
                changes.append(Change("create", "reservation", w["hostname"], f"{w['ip_address']} ← {mac}", None, w, {"r": w}))
            else:
                diff = [k for k in ("ip_address", "hostname") if (cur.get(k) or "") != w[k]]
                if diff:
                    changes.append(Change("update", "reservation", w["hostname"], f"update {', '.join(diff)}",
                                          {k: cur.get(k) for k in ("ip_address", "hw_address", "hostname")}, w, {"r": w, "uuid": cur["uuid"]}))
        if self.settings.get("allow_delete", True):
            for mac, cur in have.items():
                if mac not in want and MARKER in (cur.get("description") or ""):
                    changes.append(Change("delete", "reservation", cur.get("hostname") or mac, f"{cur.get('ip_address')} ← {mac}",
                                          {k: cur.get(k) for k in ("ip_address", "hw_address", "hostname")}, None, {"uuid": cur["uuid"]}))
        return changes

    def apply_sync_reservations(self, changes, params):
        api, errors, done = self.api, [], 0
        for c in changes:
            try:
                if c.op == "create":
                    self._check(api.post("kea/dhcpv4/add_reservation", json={"reservation": c.data["r"]}).json(), c)
                elif c.op == "update":
                    self._check(api.post(f"kea/dhcpv4/set_reservation/{c.data['uuid']}", json={"reservation": c.data["r"]}).json(), c)
                else:
                    r = api.post(f"kea/dhcpv4/del_reservation/{c.data['uuid']}").json()
                    if r.get("result") not in ("deleted", "saved"):
                        raise PluginError(str(r))
                done += 1
                self.log(f"{c.op} {c.name}: ok")
            except PluginError as exc:
                errors.append(f"{c.op} {c.name}: {exc}")
        r = api.post("kea/service/reconfigure").json()
        self.log(f"reconfigure: {r.get('status', r)}")
        if errors:
            raise PluginError(f"{len(errors)} of {len(changes)} change(s) failed: " + "; ".join(errors[:5]))
        return {"applied": done}

    # ------------------------------------------------------------------ pages
    def page_access(self, args):
        aliases, rules, networks = self._existing(), self._rules(), self.ctx.inventory.networks()
        rows = []
        for h in self.ctx.hosts():
            for row in self.access_report(h, aliases, rules, networks):
                rows.append({"host": h["name"], **row})
        bad = [r for r in rows if r["_tone"] in ("err", "warn")]
        return {"summary": [{"label": "declared paths", "value": len(rows), "tone": ""},
                            {"label": "allowed", "value": sum(1 for r in rows if r["_tone"] == "ok"), "tone": "ok"},
                            {"label": "missing or partial", "value": len(bad), "tone": "err" if bad else "ok"}],
                "sections": [{"title": "Declared access (services' 'allow from')", "type": "table",
                              "columns": [{"key": "host", "label": "Host", "link": "host"}, {"key": "service", "label": "Service"},
                                          {"key": "port", "label": "Port"}, {"key": "from", "label": "From"},
                                          {"key": "status", "label": "Result"}, {"key": "rule", "label": "Rule"}],
                              "rows": sorted(rows, key=lambda r: ({"err": 0, "warn": 1}.get(r["_tone"], 2), r["host"])),
                              "empty": "No service declares 'allow from' yet."}],
                "note": "Matched by address; rule order, interface and direction aren't evaluated."}

    # -------------------------------------------------------- alias import
    BUILTIN_ALIASES = {"bogons", "bogonsv6", "sshlockout", "virusprot", "crowdsec_blacklists", "crowdsec6_blacklists"}
    IMPORT_TYPES = {"host": "host", "network": "network", "port": "port", "mac": "mac", "url": "url", "urltable": "url",
                    "networkgroup": "network"}

    def run_import_aliases(self, params):
        """Copy the firewall's own aliases into labdex as custom aliases, under their names on the
        firewall (so nothing is renamed there). Members that name other aliases become alias
        references; everything else is kept as it is. labdex's own aliases and OPNsense's built-in
        ones are skipped, and so is an alias labdex already has."""
        from fnmatch import fnmatchcase
        from labdex import audit, store
        from labdex.models import AliasGroup, db
        only = [p.strip() for p in str(params.get("only") or "").replace(",", " ").split() if p.strip()]
        existing = self._existing()
        have = {g.name for g in db.session.scalars(db.select(AliasGroup))} | {g.fw_id for g in db.session.scalars(db.select(AliasGroup)) if g.fw_id}
        generated = {a["fw_id"] for a in self.ctx.inventory.aliases()}
        made, skipped = [], []
        for name, cur in sorted(existing.items()):
            if self._is_managed(cur) or name.startswith("__") or name in self.BUILTIN_ALIASES:
                continue
            if only and not any(fnmatchcase(name, p) for p in only):
                continue
            if name in have or name in generated:
                skipped.append(f"{name} (already in labdex)")
                continue
            t = self.IMPORT_TYPES.get(str(cur.get("type") or "").lower())
            if t is None:
                skipped.append(f"{name} (type {cur.get('type')})")
                continue
            members = []
            for m in _norm(cur.get("content") or ""):
                members.append(f"alias:{m}" if m in existing and m != name else m)
            try:
                store.save_alias({"name": name, "fw_id": name, "type": t, "members": members,
                                  "description": str(cur.get("description") or "")[:200]})
                db.session.flush()
                made.append(name)
            except store.ValidationError as exc:
                skipped.append(f"{name} ({exc.errors[0]['field']}: {exc.errors[0]['message']})")
        for n in made:
            self.log(f"imported {n}")
        for n in skipped:
            self.log(f"skipped {n}")
        if made:
            audit.record("import", "alias", self.ctx.name, None, {"aliases": made},
                         summary=f"imported {len(made)} alias(es) from {self.ctx.name}", actor=(f"integration {self.ctx.name}", "system"))
            db.session.commit()
            from labdex.plugins import jobs
            jobs.emit("alias.created")
            if not self.settings.get("adopt_existing"):
                self.log("labdex now knows them but leaves them alone on the firewall; turn on 'take over' to let it manage them")
        return {"imported": len(made), "skipped": len(skipped),
                "message": f"{len(made)} alias(es) imported, {len(skipped)} skipped"}

    # ------------------------------------------------------------- discovery
    def run_import_arp(self, params):
        r = self.api.get("diagnostics/interface/getArp").json()
        rows = r.get("rows", r) if isinstance(r, dict) else r
        if not isinstance(rows, list):
            raise PluginError("unexpected answer from diagnostics/interface/getArp")
        entries = [{"ip": e.get("ip"), "mac": e.get("mac"), "hostname": e.get("hostname", ""),
                    "vendor": e.get("manufacturer", "")} for e in rows if isinstance(e, dict)]
        try:  # IPv6 neighbours (diagnostics/interface/getNdp: ip, mac, intf, manufacturer)
            r6 = self.api.get("diagnostics/interface/getNdp").json()
            rows6 = r6.get("rows", r6) if isinstance(r6, dict) else r6
        except PluginError as exc:
            rows6 = []
            self.log(f"no NDP table ({exc})")
        ndp = [{"ip": e.get("ip", "").split("%")[0], "mac": e.get("mac"), "hostname": "", "vendor": e.get("manufacturer", "")}
               for e in rows6 if isinstance(e, dict)]
        n = self.ctx.discovery.record_neighbours(f"opnsense:{self.ctx.name}", entries + ndp)
        self.log(f"{len(entries)} ARP and {len(ndp)} NDP entries imported (link-local addresses are skipped)")
        return {"entries": n}
