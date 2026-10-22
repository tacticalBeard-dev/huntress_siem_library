"""Lint the query library. Usage: python .github/scripts/lint.py [repo_root]

Checks every <folder>/<query>.yaml against the template and the known Huntress ES|QL traps,
scans queries and docs for data that looks like it came from a real environment, and checks
the README links every query. Prints one line per problem and exits 1 if there are any.
"""
import glob, ipaddress, os, re, sys
from urllib.parse import unquote

import yaml

ORDER = ["title", "id", "status", "description", "author", "date", "modified", "references",
         "tags", "logsource", "picker", "placeholders", "query", "expected_result", "outcomes",
         "known_limits", "analyst_notes"]
TEXT_FIELDS = ["title", "description", "author", "picker", "query", "expected_result",
               "known_limits", "analyst_notes"]
# Queries whose events depend on a logging setting; outcomes.empty must name it.
PREREQ = {
    "Sonicwall/admin-vpn-login.yaml": "Authentication Access",
    "Sonicwall/admin-wan-login.yaml": "Authentication Access",
    "Sonicwall/admin-logout.yaml": "Authentication Access",
    "Sonicwall/failed-logins.yaml": "Authentication Access",
    "Sonicwall/successful-sslvpn-user-login.yaml": "Authentication Access",
    "Sonicwall/user-vpn-login.yaml": "Authentication Access",
    "Sonicwall/user-wan-login.yaml": "Authentication Access",
    "Sonicwall/user-logout.yaml": "Authentication Access",
    "Meraki/all-security-alerts.yaml": "Security events",
    "Windows Event/registry-key-modification.yaml": "SACL",
    "Windows Event/scheduled-task-creation.yaml": "Other Object Access",
    "Windows Event/kerberoasting-rc4-service-ticket-request.yaml": "Kerberos",
    "Windows Event/overpass-the-hash-rc4-tgt-request.yaml": "Kerberos",
    "Windows Event/local-user-account-created.yaml": "User Account Management",
    "Windows Event/privileged-group-membership-change.yaml": "Security Group Management",
    "Windows Event/sonicwall-vpn-ioc-driver-installed-by-attacker.yaml": "Security System Extension",
    "Windows Event/sonicwall-vpn-ioc-ransomware-executables.yaml": "Process Creation",
    "Windows Event/key-storage-provider.yaml": "Other System Events",
    "Windows Event/pass-the-hash-ntlm-network-logon-zero-key.yaml": "Audit Logon",
}
# The template's example GUID and well-known Microsoft first-party app IDs.
ALLOWED_GUIDS = {"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                 "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "797f4846-ba00-4fd7-ba43-dac1f8f63013"}
README_SECTIONS = ["Read this first", "Field reference", "Find a query", "Huntress documentation"]
CONTRIB_SECTIONS = ["Template", "Testing a query", "Pull request checklist"]

UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                              "100.64.0.0/10", "2001:db8::/32")]
# One-line, name-shaped tokens like <ip> or <user@client.com>; not "a <= 5 ... b >".
PLACEHOLDER = re.compile(r"<[A-Za-z][\w@.\- ]{0,40}>")

problems = []


def report(code, rel, msg):
    problems.append(f"{code} {rel}: {msg}")


def public_ip(token):
    """True for an address that could point at a real network: not private, reserved,
    documentation, shared address space or a netmask."""
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return False
    if ip.version == 4 and (token.startswith("255.") or token.endswith(".0.0.0")):
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or \
            ip.is_multicast or ip.is_unspecified:
        return False
    return not any(ip in n for n in DOC_NETS)


def identifying(rel, text, ioc):
    """Flag emails, public IPs and GUIDs. Emails are checked everywhere, including inside
    <...>, and only the placeholder domains are allowed; IPs and GUIDs inside a placeholder
    are skipped."""
    for e in EMAIL.findall(text):
        if not re.search(r"@(example\.(com|net|org)|client\.com)$", e.rstrip(".")):
            report("I1", rel, f"email {e}")
    if ioc:
        return
    text = PLACEHOLDER.sub("", text)
    for ip in IPV4.findall(text) + IPV6.findall(text):
        if public_ip(ip):
            report("I2", rel, f"public IP {ip} (tag published IOC queries with ioc)")
    for g in GUID.findall(text):
        if g.lower() not in ALLOWED_GUIDS:
            report("I3", rel, f"GUID {g}")


def providers_in(query):
    found = re.findall(r'event\.provider\s*==\s*"([^"]+)"', query)
    for group in re.findall(r"event\.provider\s+IN\s*\(([^)]*)\)", query, re.I):
        found += re.findall(r'"([^"]+)"', group)
    return found


def check_query(repo, path, ids):
    rel = os.path.relpath(path, repo).replace(os.sep, "/")
    raw = open(path, encoding="utf-8").read()
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*\.yaml", os.path.basename(rel)):
        report("Q1", rel, "file name not lowercase kebab-case")
    if "—" in raw or "–" in raw:
        report("Q5", rel, "contains an em or en dash")
    try:
        d = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        report("Q9", rel, f"YAML parse error: {e}")
        return
    if not isinstance(d, dict):
        report("Q9", rel, "not a YAML mapping")
        return
    if list(d) != ORDER:
        report("Q2", rel, f"fields missing or out of order: {list(d)}")
    qid = str(d.get("id"))
    ids.setdefault(qid, []).append(rel)
    if not UUID4.match(qid):
        report("Q4", rel, f"id is not a lowercase UUIDv4: {qid}")
    for f in TEXT_FIELDS:
        if not isinstance(d.get(f), str) or not d[f].strip():
            report("Q9", rel, f"{f} empty or not a string")
    q = d.get("query") if isinstance(d.get("query"), str) else ""

    ls = d.get("logsource") if isinstance(d.get("logsource"), dict) else {}
    prov = ls.get("provider")
    provs = prov if isinstance(prov, list) else [prov]
    if not provs or not all(isinstance(p, str) and p.strip() for p in provs):
        report("Q3", rel, "logsource.provider must be a string, a list of strings, or any")
    elif prov != "any":
        for p in providers_in(q):
            if p not in provs:
                report("Q3", rel, f"query filters on provider {p!r}, not in logsource.provider")

    if re.search(r"\|\s*limit\b", q, re.I):
        report("Q6", rel, "limit in query (any limit reads only the last 4 hours)")
    if re.search(r'LIKE\s+"[^"]*%', q, re.I):
        report("Q6", rel, "% inside LIKE (the wildcard is *)")
    if re.search(r"(?<![.\w])message\)?\s*(==|like\b)", q, re.I):
        report("Q6", rel, "searches message (use CONTAINS(event.original, ...))")
    if re.search(r"\bfrom\s+logs[*-]", q, re.I):
        report("Q6", rel, "source must be from logs")

    ph = d.get("placeholders")
    if not isinstance(ph, list):
        report("Q9", rel, "placeholders must be a list ([] when there are none)")
        ph = []
    listed = set()
    for item in ph:
        m = re.match(r"\s*(<[^<>]+>)\s*:", str(item))
        if m:
            listed.add(m.group(1))
        else:
            report("Q7", rel, f"placeholder entry not '<name>: ...': {item!r}")
    used = set(PLACEHOLDER.findall(q))
    if used != listed:
        report("Q7", rel, f"placeholders in query {sorted(used)} != listed {sorted(listed)}")

    oc = d.get("outcomes")
    if not isinstance(oc, dict) or set(oc) != {"rows", "empty", "error"} or \
            not all(isinstance(x, str) and x.strip() for x in oc.values()):
        report("Q9", rel, "outcomes needs non-empty rows, empty and error")
    elif rel in PREREQ and PREREQ[rel].lower() not in oc["empty"].lower():
        report("Q8", rel, f"outcomes.empty should name the {PREREQ[rel]!r} setting")

    tags = d.get("tags") if isinstance(d.get("tags"), list) else []
    identifying(rel, raw.replace(qid, ""), ioc="ioc" in tags)


def check_docs(repo, queries):
    docs = {}
    for name in ("README.md", "CONTRIBUTING.md"):
        p = os.path.join(repo, name)
        if not os.path.exists(p):
            report("D0", name, "missing")
            docs[name] = ""
            continue
        text = docs[name] = open(p, encoding="utf-8").read()
        for link in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            if not re.match(r"[a-z]+:", link) and not os.path.exists(os.path.join(repo, unquote(link))):
                report("D1", name, f"broken relative link {link}")
        if "—" in text or "–" in text:
            report("D2", name, "contains an em or en dash")
        identifying(name, text, ioc=False)
    linked = {unquote(l) for l in re.findall(r"\]\(([^)#\s]+\.yaml)\)", docs["README.md"])}
    for rel in queries:
        if rel not in linked:
            report("D4", "README.md", f"query not linked: {rel}")
    for name, sections, code in (("README.md", README_SECTIONS, "D5"),
                                 ("CONTRIBUTING.md", CONTRIB_SECTIONS, "D6")):
        for s in sections:
            if docs[name] and not re.search(rf"^#+\s+{re.escape(s)}", docs[name], re.M | re.I):
                report(code, name, f"missing section {s}")


def main():
    repo = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    paths = sorted(glob.glob(os.path.join(repo, "*", "*.yaml")))
    ids = {}
    for path in paths:
        check_query(repo, path, ids)
    for qid, rels in ids.items():
        if len(rels) > 1:
            report("Q4", rels[0], f"duplicate id {qid}, also in {rels[1:]}")
    check_docs(repo, [os.path.relpath(p, repo).replace(os.sep, "/") for p in paths])
    for line in problems:
        print(line)
    print(f"{len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
