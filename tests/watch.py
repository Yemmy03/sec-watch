#!/usr/bin/env python3
"""
security-watch: twice-daily security digest for a fixed software inventory.

It never touches your code. It reads inventory.yml and public sources only:
  OSV.dev ........ per-package, per-version advisories (npm, PyPI)
  CISA KEV ....... vulnerabilities exploited in the wild
  NVD ............ severity data and CVEs for tools (Docker, Node.js, ...)
  EPSS (FIRST) ... exploit-likelihood score
  cve.now ........ JSON Feed of freshly published CVEs (early warning)
  News RSS ....... optional extra feeds (off by default; see news_feeds in inventory.yml)
  npm registry ... resolves version ranges, detects deprecated packages
  endoflife.date . upcoming / past end-of-life dates

Every vulnerability is reported once, in the fixed 8-field format:
  CVE / Severity / Affected technology / Affected team/s / Potential impact /
  Relevance / Exploitation status / Recommended action / Source

Environment variables:
  SLACK_WEBHOOK_URL   Slack incoming webhook (required unless --dry-run)
  NVD_API_KEY         optional, makes NVD calls much faster
  STATE_PATH          optional, default state/state.json

Usage:
  python watch.py --dry-run                      # print the report, send nothing, save nothing
  python watch.py                                # normal run (posts to Slack, saves state)
  python watch.py --baseline                     # force a silent baseline run
  python watch.py --mode news                    # cve.now digest: CVSS 9.5+ only, max 20 items
  python watch.py --monthly-summary [--dry-run]  # monthly executive overview (read-only on state)
  python watch.py --monthly-summary --month 2026-09
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote
from zoneinfo import ZoneInfo

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
UA = "security-watch/1.0 (personal security digest)"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NPM_REG = "https://registry.npmjs.org/"
EOL_URL = "https://endoflife.date/api/{}.json"
CVENOW_URL = "https://cve.now/feed?format=json"          # JSON Feed 1.1
DEFAULT_NEWS = [{"name": "Cybersecuritynews", "url": "https://cybersecuritynews.com/feed/"}]

# Fixed report wording
SEP = "=" * 24                      # break-out line after each CVE
MATCH_CONFIRMED = "Confirmed match in the inventory."
MATCH_UNVERIFIED = "Unverified match in the inventory."
EXPLOIT_CONFIRMED = "Actively exploited in the wild"
EXPLOIT_UNCONFIRMED = "Cannot confirm actively exploited in the wild status"
TEAMS_UNMAPPED = "Unmapped: no owning team is recorded for this technology in the inventory."
FOOTER_NOTE = ("Findings are evaluated against the technology inventory and public vulnerability intelligence. "
               "An inventory match does not confirm a deployed or vulnerable version: this system has no access "
               "to application source code or deployed runtime versions. Team ownership comes from the inventory mappings.")

# News mode: a tightly controlled vulnerability channel
NEWS_MIN_CVSS = 9.5                 # hard floor; settings can raise it but never lower it
NEWS_MAX_ITEMS = 20
NEWS_QUEUE_MAX_AGE_DAYS = 3
LEGACY_NEWS_THRESHOLD = 8.5         # threshold used before 9.5; only used to read old state entries

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}
SEV_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", None: "Unrated"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Package names too generic to match against free text (cve.now / news) by name alone.
# They can still be matched by explicit identity (e.g. "npm package next", pkg:npm/next).
GENERIC_NAMES = {
    "next", "copy", "color", "chai", "bull", "nock", "lit", "joi", "pug", "he", "ms", "qs", "pg",
    "fs", "sdk", "request", "redirect", "compression", "concurrently", "moment", "husky",
    "react", "redux", "sass", "zod", "jest", "uuid", "ulid", "btoa", "dayjs", "mixpanel",
    "classnames", "csv-parser", "base-64", "utf8", "numeral", "opossum", "restana", "pusher",
}

# Ecosystem / product context used to reject look-alikes (e.g. a WordPress plugin called "... Express ...")
FOREIGN_ECO_NPM = re.compile(
    r"\b(wordpress|drupal|joomla|magento|prestashop|woocommerce|typo3|php|python|pypi|java|maven|golang|"
    r"rust|crate|ruby|rubygems|nuget|android|\.net)\b", re.I)
FOREIGN_ECO_PYPI = re.compile(
    r"\b(wordpress|drupal|joomla|magento|woocommerce|php|npm|node\.?js|javascript|java|maven|golang|"
    r"rust|ruby|rubygems|nuget|\.net)\b", re.I)
FOREIGN_PRODUCT = re.compile(r"\b(plugin|theme|extension|add-?on|firmware)\b", re.I)
ECO_HINTS = {"npm": ["npm", "node.js", "nodejs", "javascript", "typescript", "yarn", "pnpm"],
             "pypi": ["pypi", "python", "pip"]}
OSV_ECO = {"npm": "npm", "pypi": "PyPI"}
_NEVER = re.compile(r"(?!x)x")

NOW = datetime.now(timezone.utc)
NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    retry = Retry(total=3, backoff_factor=1.5, status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET", "POST"]))
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=16))
    return s


SESSION = make_session()


def get_json(url, params=None, headers=None, timeout=30):
    r = SESSION.get(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


def post_json(url, payload, timeout=60):
    r = SESSION.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


_last_nvd = 0.0


def nvd_get(params):
    """NVD allows 5 requests / 30 s without a key and 50 / 30 s with one."""
    global _last_nvd
    gap = 0.7 if NVD_KEY else 6.3
    wait = gap - (time.time() - _last_nvd)
    if wait > 0:
        time.sleep(wait)
    _last_nvd = time.time()
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    return get_json(NVD_URL, params=params, headers=headers, timeout=60)


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #
def esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def short_text(t, n=240):
    t = re.sub(r"```.*?```", " ", t or "", flags=re.S)
    t = re.sub(r"`([^`]*)`", r"\1", t)
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"^#+\s*", "", t, flags=re.M)
    t = " ".join(t.split())
    if len(t) <= n:
        return t
    cut = t[:n]
    k = max(cut.rfind(". "), cut.rfind("; "))
    return cut[:k + 1] if k > 80 else cut.rstrip() + "…"


def strip_html(t):
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<!\[CDATA\[|\]\]>", "", t or "")).split())


def parse_dt(s):
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except ValueError:
        try:
            d = parsedate_to_datetime(s)
        except Exception:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def sev_from_score(score):
    if score is None:
        return None
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else None


# --------------------------------------------------------------------------- #
# Inventory normalisation (supports legacy lists AND {versions, teams} mappings)
# --------------------------------------------------------------------------- #
def entry_versions_teams(v):
    """Return (versions, teams) for a legacy list entry or a {versions: [...], teams: [...]} mapping."""
    if isinstance(v, dict):
        vers, teams = v.get("versions") or [], v.get("teams") or []
    elif isinstance(v, (list, tuple)):
        vers, teams = v, []
    elif v is None:
        vers, teams = [], []
    else:
        vers, teams = [v], []
    if isinstance(vers, (str, int, float)):
        vers = [vers]
    if isinstance(teams, str):
        teams = [teams]
    return [str(x) for x in vers], [str(t) for t in teams]


def normalize_inventory(inv):
    """Return a copy of the inventory where npm/pypi are always {name: [versions]} (the shape the scanner
    uses), news_keywords/unversioned are plain strings, and ownership is held in inv['_owners'].
    Idempotent: normalising an already-normalised inventory returns it unchanged."""
    inv = inv or {}
    if inv.get("_normalized"):
        return inv
    out = dict(inv)
    owners = {"npm": {}, "pypi": {}, "unversioned": {}, "keywords": {}, "tools": {}, "services": {}}
    for eco in ("npm", "pypi"):
        norm = {}
        for name, v in (inv.get(eco) or {}).items():
            vers, teams = entry_versions_teams(v)
            norm[str(name)] = vers
            owners[eco][str(name)] = teams
        out[eco] = norm
    kws = []
    for k in inv.get("news_keywords") or []:
        if isinstance(k, dict):
            word, teams = str(k.get("keyword") or k.get("name") or "").strip(), entry_versions_teams(k)[1]
        else:
            word, teams = str(k).strip(), []
        if word:
            kws.append(word)
            owners["keywords"][word] = teams
    out["news_keywords"] = kws
    unv = []
    for u in inv.get("unversioned") or []:
        if isinstance(u, dict):
            name, teams = str(u.get("name") or "").strip(), entry_versions_teams(u)[1]
        else:
            name, teams = str(u).strip(), []
        if name:
            unv.append(name)
            owners["unversioned"][name] = teams
    out["unversioned"] = unv
    for tool in inv.get("tools") or []:
        if isinstance(tool, dict) and tool.get("name"):
            owners["tools"][tool["name"]] = entry_versions_teams({"teams": tool.get("teams")})[1]
    reg = inv.get("teams")
    out["teams"] = {str(k): v for k, v in reg.items()} if isinstance(reg, dict) else {}
    out["_owners"] = owners
    out["_normalized"] = True
    return out


def owners_of(inv, eco_key, name):
    """Team keys that own a package, looked up case-insensitively. Empty list = unmapped (never invented)."""
    owners = (inv.get("_owners") or {}).get(eco_key, {})
    if name in owners:
        return list(owners[name])
    low = str(name).lower()
    for k, v in owners.items():
        if k.lower() == low:
            return list(v)
    return []


def team_label(inv, key):
    reg = (inv.get("teams") or {}).get(key)
    if isinstance(reg, dict):
        name = str(reg.get("name") or key)
        slack = str(reg.get("slack") or "").strip()
        return f"{name} ({slack})" if slack else name
    return str(key)


def resolve_teams(inv, keys):
    """Team keys -> display labels, de-duplicated, order preserved. Unknown keys are shown as written."""
    out, seen = [], set()
    for k in keys or []:
        if k in seen:
            continue
        seen.add(k)
        out.append(team_label(inv, k))
    return out


# --------------------------------------------------------------------------- #
# State (the "what have I already told you" memory)
# --------------------------------------------------------------------------- #
def load_state(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(path, state):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def seen_dict(state, key):
    v = state.get(key, {})
    if isinstance(v, list):                       # tolerate old list format
        v = {i: NOW.date().isoformat() for i in v}
    return dict(v)


def prune(d, days):
    cutoff = (NOW - timedelta(days=days)).date().isoformat()
    return {k: v for k, v in d.items() if v >= cutoff}


# --------------------------------------------------------------------------- #
# npm version resolution (no code access: versions come from your inventory)
# --------------------------------------------------------------------------- #
def parse_exact(v):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?", v.strip())
    if not m:
        return None
    return (int(m[1]), int(m[2]), int(m[3])), m[4]


def parse_partial(s):
    m = re.fullmatch(r"v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.\-]+))?", s)
    if not m:
        return None
    parts = []
    for g in (m[1], m[2], m[3]):
        if g is None or g in ("x", "X", "*"):
            break
        parts.append(int(g))
    return parts, m[4]


def bump(parts, idx):
    out = list(parts) + [0] * (3 - len(parts))
    out[idx] += 1
    for i in range(idx + 1, 3):
        out[i] = 0
    return tuple(out)


def resolve_spec(spec, reg):
    """Return (assumed_version, floor_version) or None if the spec is too exotic.
    assumed = newest stable release that satisfies the range (what a fresh install gets)."""
    s = str(spec).strip()
    stable = {}
    latest = None
    if reg:
        latest = reg.get("latest")
        for v in reg["versions"]:
            p = parse_exact(v)
            if p and not p[1]:
                stable[p[0]] = v
    if s in ("", "*", "x", "latest"):
        return (latest, latest) if latest else None
    if "||" in s or " " in s or "<" in s or s.startswith("=") or (">" in s and not s.startswith(">=")):
        return None
    if s[0] in "^~":
        op, body = s[0], s[1:]
    elif s.startswith(">="):
        op, body = ">=", s[2:]
    else:
        op, body = "=", s
    p = parse_partial(body.strip())
    if not p:
        return None
    parts, pre = p
    if pre:                                       # pre-release spec: use as written
        return body.strip(), body.strip()
    if not parts:
        return (latest, latest) if latest else None
    lower = tuple((parts + [0, 0, 0])[:3])
    floor = ".".join(map(str, lower))
    if op == "=":
        if len(parts) == 3:
            return body.strip(), body.strip()
        upper = bump(parts, len(parts) - 1)
    elif op == "^":
        nz = [i for i, x in enumerate(parts) if x != 0]
        upper = bump(parts, nz[0] if nz else len(parts) - 1)
    elif op == "~":
        upper = bump(parts, 0 if len(parts) == 1 else 1)
    else:                                         # ">="
        upper = None
    cands = [t for t in stable if t >= lower and (upper is None or t < upper)]
    assumed = stable[max(cands)] if cands else floor
    return assumed, floor


def fetch_registry(name):
    d = get_json(NPM_REG + quote(name, safe="@"), headers={"Accept": "application/vnd.npm.install-v1+json"}, timeout=45)
    versions = d.get("versions", {})
    return {
        "latest": (d.get("dist-tags") or {}).get("latest"),
        "versions": list(versions),
        "deprecated": {v: m.get("deprecated") for v, m in versions.items() if m.get("deprecated")},
    }


# --------------------------------------------------------------------------- #
# OSV
# --------------------------------------------------------------------------- #
def osv_query(targets):
    """targets: dicts with key, eco, name, versions. Returns (ids_by_key, hits, failed_keys)."""
    jobs = [(t["key"], t["name"], t["eco"], v) for t in targets for v in t["versions"]]
    ids_by_key, hits, failed = {}, {}, set()
    for chunk in chunks(jobs, 300):
        try:
            resp = post_json(OSV_BATCH, {"queries": [
                {"package": {"name": n, "ecosystem": e}, "version": v} for _, n, e, v in chunk]})
            results = resp.get("results", [])
            if len(results) != len(chunk):
                raise ValueError("unexpected OSV result count")
        except Exception as ex:
            log(f"OSV batch failed: {ex}")
            failed.update(k for k, *_ in chunk)
            continue
        for (key, n, e, v), r in zip(chunk, results):
            ids = {x["id"] for x in (r.get("vulns") or [])}
            token, guard = r.get("next_page_token"), 0
            while token and guard < 20:
                try:
                    more = post_json(OSV_BATCH, {"queries": [
                        {"package": {"name": n, "ecosystem": e}, "version": v, "page_token": token}]})["results"][0]
                except Exception as ex:
                    log(f"OSV page failed: {ex}")
                    failed.add(key)
                    break
                ids |= {x["id"] for x in (more.get("vulns") or [])}
                token, guard = more.get("next_page_token"), guard + 1
            ids_by_key.setdefault(key, set()).update(ids)
            for i in ids:
                hits.setdefault(i, []).append((key, n, e, v))
    for k in failed:
        ids_by_key.pop(k, None)
    return ids_by_key, hits, failed


def osv_detail(vid):
    return get_json(OSV_VULN + quote(vid, safe=""), timeout=30)


_osv_cache = {}


def osv_record(vid):
    """OSV record for an id (cached per run). None when OSV does not know it yet (normal for fresh CVEs)."""
    vid = vid.upper()
    if vid not in _osv_cache:
        try:
            _osv_cache[vid] = osv_detail(vid)
        except Exception as e:
            log(f"OSV has no record for {vid} yet ({e.__class__.__name__})")
            _osv_cache[vid] = None
    return _osv_cache[vid]


def osv_severity(v):
    s = str((v.get("database_specific") or {}).get("severity", "")).upper()
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(s)


def pick_cve(v):
    if v.get("id", "").upper().startswith("CVE-"):
        return v["id"].upper()
    for a in v.get("aliases", []) or []:
        if a.upper().startswith("CVE-"):
            return a.upper()
    return None


def vt(s):
    p = parse_exact(s)
    return p[0] if p else None


def fixed_versions(vuln, name, eco, ver):
    out = []
    for a in vuln.get("affected", []) or []:
        p = a.get("package", {}) or {}
        if p.get("name", "").lower() != name.lower() or p.get("ecosystem") != eco:
            continue
        for r in a.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if "fixed" in ev:
                    out.append(ev["fixed"])
    cur = vt(ver)
    out = [f for f in out if not (cur and vt(f) and vt(f) <= cur)]      # only fixes newer than yours
    same = [f for f in out if f.split(".")[0] == ver.split(".")[0]]
    res = same or out

    def k(s):
        return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", s)]
    return sorted(set(res), key=k)[:3]


def advisory_url(vuln):
    vid = vuln["id"]
    if vid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vid}"
    for r in vuln.get("references", []) or []:
        if r.get("type") == "ADVISORY" and r.get("url"):
            return r["url"]
    cve = pick_cve(vuln)
    return f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else f"https://osv.dev/vulnerability/{vid}"


def osv_affects(vuln, name, eco, ver):
    """Does this OSV record's affected data cover `ver` of package `name`?
    True / False when the data can decide it, None when it cannot (unparsable versions, no ranges)."""
    cur = vt(ver)
    decided_false = False
    for a in vuln.get("affected", []) or []:
        p = a.get("package") or {}
        if str(p.get("name", "")).lower() != name.lower() or p.get("ecosystem") != eco:
            continue
        if ver in (a.get("versions") or []):
            return True
        for r in a.get("ranges") or []:
            if r.get("type") not in ("SEMVER", "ECOSYSTEM") or cur is None:
                continue
            evs, bad = [], False
            for e in r.get("events") or []:
                raw = e.get("introduced") if "introduced" in e else e.get("fixed") if "fixed" in e else e.get("last_affected")
                key = (0, 0, 0) if raw == "0" else vt(str(raw)) if raw is not None else None
                if key is None:
                    bad = True
                    break
                evs.append((key, e))
            if bad:
                continue
            inside = False
            for key, e in sorted(evs, key=lambda x: x[0]):
                if "introduced" in e and cur >= key:
                    inside = True
                if "fixed" in e and cur >= key:
                    inside = False
                if "last_affected" in e and cur > key:
                    inside = False
            if inside:
                return True
            decided_false = True
    return False if decided_false else None


# --------------------------------------------------------------------------- #
# KEV / EPSS / NVD
# --------------------------------------------------------------------------- #
def load_kev():
    d = get_json(KEV_URL, timeout=60)
    return {v["cveID"].upper(): v for v in d.get("vulnerabilities", [])}


def epss_scores(cves):
    out = {}
    for chunk in chunks(sorted(cves), 80):
        try:
            d = get_json(EPSS_URL, params={"cve": ",".join(chunk)})
            for row in d.get("data", []):
                out[row["cve"].upper()] = float(row["epss"])
        except Exception as ex:
            log(f"EPSS failed: {ex}")
    return out


def nvd_cpes(cve):
    """Affected-product data (vendor/product/version bounds) from an NVD record's configurations."""
    out = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = str(m.get("criteria", "")).split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue
                out.append({"vendor": parts[3].lower(), "product": parts[4].lower(), "version": parts[5],
                            "vulnerable": m.get("vulnerable", True),
                            "vsi": m.get("versionStartIncluding"), "vse": m.get("versionStartExcluding"),
                            "vei": m.get("versionEndIncluding"), "vee": m.get("versionEndExcluding")})
    return out


def nvd_parse(cve):
    metrics = cve.get("metrics", {}) or {}
    sev = score = None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(k)
        if arr:
            d = arr[0].get("cvssData", {}) or {}
            sev = (d.get("baseSeverity") or arr[0].get("baseSeverity") or "").upper() or None
            score = d.get("baseScore")
            if sev:
                break
    desc = next((x["value"] for x in cve.get("descriptions", []) if x.get("lang") == "en"), "")
    return {"id": cve.get("id", "").upper(), "severity": sev, "score": score,
            "published": cve.get("published"), "summary": desc, "status": cve.get("vulnStatus", ""),
            "cpes": nvd_cpes(cve)}


_nvd_cache = {}
_nvd_budget = [25]          # cap on single-CVE lookups per run


def nvd_cve(cve_id):
    cve_id = cve_id.upper()
    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]
    if _nvd_budget[0] <= 0:
        return None
    _nvd_budget[0] -= 1
    try:
        vulns = nvd_get({"cveId": cve_id}).get("vulnerabilities", [])
        res = nvd_parse(vulns[0]["cve"]) if vulns else None
    except Exception as ex:
        log(f"NVD lookup {cve_id} failed: {ex}")
        res = None
    _nvd_cache[cve_id] = res
    return res


def nvd_tool_cves(tool, start, end):
    out = []
    for vp in tool.get("cpe", []) or []:
        params = {"virtualMatchString": f"cpe:2.3:a:{vp}" + ":*" * 8,
                  "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                  "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                  "resultsPerPage": 200}
        for v in nvd_get(params).get("vulnerabilities", []):
            out.append(nvd_parse(v["cve"]))
    return out


# --------------------------------------------------------------------------- #
# End-of-life
# --------------------------------------------------------------------------- #
def check_eol(entries, warn_days):
    items = []
    for e in entries or []:
        try:
            data = get_json(EOL_URL.format(e["product"]), timeout=20)
        except Exception as ex:
            log(f"endoflife.date {e['product']} skipped: {ex}")
            continue
        wanted = {str(c) for c in e.get("cycles", [])}
        for row in data:
            cyc = str(row.get("cycle"))
            if cyc not in wanted:
                continue
            eol = row.get("eol")
            label = e.get("label", e["product"])
            if eol is True:
                items.append((f"{e['product']}:{cyc}:eol", f"{label} {cyc}: end-of-life, no more security fixes."))
            elif isinstance(eol, str):
                d = parse_dt(eol)
                if not d:
                    continue
                days = (d - NOW).days
                if days < 0:
                    items.append((f"{e['product']}:{cyc}:{eol}", f"{label} {cyc}: end-of-life since {eol}, no more security fixes."))
                elif days <= warn_days:
                    items.append((f"{e['product']}:{cyc}:{eol}", f"{label} {cyc}: reaches end-of-life on {eol} (in {days} days)."))
    return items


# --------------------------------------------------------------------------- #
# cve.now JSON Feed (early warning)
# --------------------------------------------------------------------------- #
def fetch_cvenow(url):
    """Follows JSON Feed pagination (next_url) if the feed offers it."""
    items, pages = [], 0
    while url and pages < 5:
        d = get_json(url, timeout=45)
        items += d.get("items", [])
        url, pages = d.get("next_url"), pages + 1
    return items


def parse_cvenow_item(it):
    raw = it.get("id", "")
    cve = raw.split("#")[0].upper()
    if not CVE_RE.fullmatch(cve):
        return None
    title = (it.get("title") or "").strip()
    if title.upper().startswith(cve + ":"):
        title = title[len(cve) + 1:].strip()
    title = re.sub(r"\s*\(Update:[^)]*\)\s*$", "", title)
    text = (it.get("content_text") or "").strip()
    num = r"\d+(?:\.\d+)?"
    m = re.search(rf"CVSS score (?:changed from {num} to )?({num})", text)
    score = float(m.group(1)) if m else None
    body = re.sub(rf"^Update: CVSS score (?:changed from {num} to )?{num}(?: published)?\.\s*", "", text)
    return {"cve": cve, "title": title, "text": body, "score": score,
            "url": it.get("url") or f"https://cve.now/{cve}", "modified": parse_dt(it.get("date_modified"))}


def dedupe_cvenow(raw):
    """One parsed entry per CVE (the most recently modified wins). A bad item never breaks the rest."""
    parsed = {}
    for it in raw:
        try:
            p = parse_cvenow_item(it)
        except Exception as e:
            log(f"cve.now item skipped: {e}")
            continue
        if p and (p["cve"] not in parsed or (p["modified"] and parsed[p["cve"]]["modified"]
                                             and p["modified"] > parsed[p["cve"]]["modified"])):
            parsed[p["cve"]] = p
    return parsed


# --------------------------------------------------------------------------- #
# News digest: CVSS >= 9.5 CVEs from cve.now that are NOT in your inventory
# --------------------------------------------------------------------------- #
def news_threshold(st):
    """Effective news CVSS floor. Settings may raise it; nothing (settings, state) can lower it below 9.5."""
    try:
        configured = float((st or {}).get("news_min_cvss", NEWS_MIN_CVSS))
    except (TypeError, ValueError):
        configured = NEWS_MIN_CVSS
    return max(configured, NEWS_MIN_CVSS)


def parse_cvss_from_page(text):
    """Read 'CVSS 9.8 Critical' from a cve.now item page. The score only counts as verified when the
    severity label next to it agrees with the number; anything else returns None."""
    for m in re.finditer(r"CVSS\s*(\d{1,2}(?:\.\d)?)\s*(Critical|High|Medium|Low)\b", text or "", re.I):
        v = float(m.group(1))
        if 0 < v <= 10 and sev_from_score(v) == m.group(2).upper():
            return v
    return None


def cvenow_page_score(cid):
    """cve.now shows a CVSS score on every item page ("CVSS 8.8 High"). Read it from there.
    Returns a float, or None if the page or a verifiable score can't be read."""
    r = SESSION.get(f"https://cve.now/{cid}", timeout=20)
    if r.status_code != 200:
        return None
    return parse_cvss_from_page(strip_html(r.text))


def _done_parts(prev):
    """news_done values look like 'date|score' (legacy), 'date|score|q' (queued) or 'date|score|n' (not queued)."""
    parts = str(prev).split("|") if prev else []
    try:
        score = float(parts[1]) if len(parts) > 1 else None
    except ValueError:
        score = None
    flag = parts[2] if len(parts) > 2 else None
    return score, flag


def _was_queued(prev):
    score, flag = _done_parts(prev)
    if flag == "q":
        return True
    if flag == "n":
        return False
    return score is not None and score >= LEGACY_NEWS_THRESHOLD     # legacy entry: queued under the old 8.5 rule


def cve_sort_key(cid):
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", str(cid).upper())
    return (int(m[1]), int(m[2]), "") if m else (9999, 0, str(cid))


def news_item_valid(it, min_score):
    """A queued item may only be reported if it is a real CVE with a numeric, verified CVSS >= min_score."""
    if not isinstance(it, dict):
        return False
    if not CVE_RE.fullmatch(str(it.get("cve", ""))):
        return False
    sc = it.get("score")
    if isinstance(sc, bool) or not isinstance(sc, (int, float)) or sc != sc:
        return False
    if not (0 < sc <= 10) or sc < max(min_score, NEWS_MIN_CVSS):
        return False
    return bool(it.get("title") or it.get("text"))


def sanitize_queue(queue, today, min_score=NEWS_MIN_CVSS, max_age_days=NEWS_QUEUE_MAX_AGE_DAYS):
    """Keep only valid, qualifying, unexpired queue entries (drops legacy 8.5+ leftovers and junk)."""
    if not isinstance(queue, dict):
        return {}
    cutoff = (datetime.strptime(today, "%Y-%m-%d") - timedelta(days=max_age_days)).strftime("%Y-%m-%d")
    out = {}
    for k, it in queue.items():
        if news_item_valid(it, min_score) and str(it.get("queued") or today) >= cutoff:
            out[str(it["cve"]).upper()] = it
    return out


def select_news(queue, today, min_score=NEWS_MIN_CVSS, max_items=NEWS_MAX_ITEMS):
    """Return (selected, overflow): highest CVSS first, ties broken by CVE number, at most max_items selected."""
    ok = sorted(sanitize_queue(queue, today, min_score).values(),
                key=lambda i: (-float(i["score"]), cve_sort_key(i["cve"])))
    return ok[:max_items], ok[max_items:]


def collect_news(parsed, matchers, ns, today, min_score, announced, skip=(), score_lookup=None, budget=0):
    """Queue cve.now items whose verified CVSS is >= min_score (never below 9.5) and that do NOT match the
    inventory. Score comes from the feed text when present, otherwise from the item's own cve.now page.
    An item is re-checked only if its score later rises across the threshold, and never re-queued if it was
    already queued before."""
    min_score = max(float(min_score), NEWS_MIN_CVSS)
    queue, done, tries = ns["queue"], ns["done"], ns.setdefault("tries", {})
    stats = ns.setdefault("stats", {"looked": 0, "found": 0})
    added = 0
    for cid, p in parsed.items():
        if not p["text"] or cid in queue or cid in announced or cid in skip:
            continue
        prev = done.get(cid)
        score = p["score"]
        if score is None:
            if prev is not None:                       # already resolved on an earlier run
                continue
            if match_text(matchers, p["title"], p["text"]):
                done[cid] = f"{today}|inventory"       # touches your stack: normal runs handle it
                continue
            if not score_lookup or budget <= 0 or tries.get(cid, 0) >= 2:
                continue
            tries[cid] = tries.get(cid, 0) + 1
            budget -= 1
            stats["looked"] += 1
            try:
                score = score_lookup(cid)
            except Exception as e:
                log(f"cve.now page {cid}: {e}")
                score = None
            time.sleep(0.4)                            # be polite to the site
            if score is None:
                continue                               # retried on the next run (max 2 tries)
            stats["found"] += 1
        prev_score, was_q = _done_parts(prev)[0], _was_queued(prev)
        tries.pop(cid, None)
        crossing = prev is None or (not was_q and prev_score is not None and prev_score < min_score <= score)
        will_queue = crossing and score >= min_score and not match_text(matchers, p["title"], p["text"])
        done[cid] = f"{today}|{score}|{'q' if (will_queue or was_q) else 'n'}"
        if will_queue:
            queue[cid] = {"cve": cid, "title": p["title"], "text": short_text(p["text"], 300),
                          "score": score, "url": p["url"], "queued": today}
            added += 1
    return added


def render_news(it, n=None):
    score = it["score"]
    emoji, label = ("🔴", "Critical") if score >= 9 else ("🟠", "High")
    head = it["title"].split(":")[0].strip()
    tech = head if ":" in it["title"] and len(head) <= 70 else it["title"][:80]
    return "\n".join([
        f"*{n}.* CVE: {it['cve']}" if n else f"• CVE: {it['cve']}",
        f"• Severity: {emoji} {label} (CVSS {score})",
        f"• Affected technology: {esc(tech)}",
        f"• Potential impact: {esc(short_text(it['title'] + '. ' + it['text'], 280))}",
        "• Relevance: 📰🚫 News → Not in your inventory (no match found, for awareness only)",
        "• Recommended action: No action needed for your stack. Keep an eye on it if you adopt or use this software.",
        f"• Source: <{it['url']}> · <https://nvd.nist.gov/vuln/detail/{it['cve']}>",
        SEP,
    ])


def run_news(args, inv, st, tz, state, webhook):
    """7 PM run: ONLY the cve.now vulnerability digest (CVSS 9.5+, max 20 per output)."""
    inv = normalize_inventory(inv)
    min_score = news_threshold(st)
    max_detail = int(st.get("max_detailed_items", 40))
    today = NOW.date().isoformat()
    ns = {"queue": sanitize_queue(state.get("news_queue"), today, min_score),
          "done": dict(state.get("news_done") or {}), "tries": dict(state.get("news_tries") or {})}
    announced = seen_dict(state, "announced_cves")
    health = {}
    try:
        parsed = dedupe_cvenow(fetch_cvenow(st.get("cvenow_url", CVENOW_URL)))
        health["cve.now"] = "✓"
        lookups = int(st.get("news_page_lookups_per_run", 150)) if st.get("news_page_scores", True) else 0
        collect_news(parsed, build_matchers(inv, {}), ns, today, min_score, announced,
                     score_lookup=cvenow_page_score, budget=lookups)
        stt = ns.get("stats", {})
        if stt.get("looked"):
            health["cve.now pages"] = (f"✓ {stt['found']}/{stt['looked']} scored" if stt["found"]
                                       else f"⚠️ 0/{stt['looked']} scored (page layout may have changed)")
    except Exception as e:
        log(f"cve.now failed: {e}")
        health["cve.now"] = "⚠️ unavailable (anything queued earlier is still included)"
    items, overflow = select_news(ns["queue"], today, min_score)
    stamp = NOW.astimezone(tz).strftime("%a %d %b %Y · %I:%M %p") + " Lagos"
    if items:
        head = (f"📰🚫 *NEWS → Not in your inventory* · {stamp}\n"
                f"{len(items)} CVE(s) rated {min_score:g}+ on cve.now. For awareness only: none matched your stack.")
        if overflow:
            head += (f"\nShowing the top {len(items)} of {len(items) + len(overflow)} by CVSS; "
                     f"{len(overflow)} more are queued for the next run.")
        blocks = [head]
        for n, it in enumerate(items, 1):
            blocks.append(render_news(it, n) if n <= max_detail else
                          f"*{n}.* {it['cve']} · CVSS {it['score']} · {esc(it['title'][:80])} · <{it['url']}>")
    else:
        blocks = [f"📰🚫 *NEWS → Not in your inventory* · {stamp}\n✅ No new CVEs rated {min_score:g}+ outside your inventory."]
    blocks.append("_Source: cve.now only · " + " · ".join(f"{k} {v}" for k, v in health.items()) +
                  " · Scores come from the feed text or the item's own cve.now page; items with no verifiable score are not included._")
    messages = split_blocks(blocks)
    if args.dry_run:
        print(("\n" + "=" * 60 + "\n").join(messages))
        log("Dry run: nothing sent, state not saved.")
        return 0
    post_slack(webhook, messages)
    # Only what was actually posted leaves the queue; qualifying overflow is kept for the next run.
    state.update({"news_queue": {i["cve"]: i for i in overflow}, "news_done": prune(ns["done"], 30),
                  "news_tries": ns.get("tries", {}), "last_news_run": NOW.isoformat()})
    save_state(args.state, state)
    log(f"News run done: {len(items)} item(s) posted, {len(overflow)} kept for the next run.")
    return 0


# --------------------------------------------------------------------------- #
# Inventory matching
# --------------------------------------------------------------------------- #
def _identity_re(names, kind):
    """Explicit package identity: 'npm package X', 'X npm package', 'X (npm)', 'X@1.2', pkg:npm/X, registry URL."""
    alts = "|".join(re.escape(n) for n in sorted(set(names), key=len, reverse=True))
    if kind == "npm":
        pat = (rf"pkg:npm/(?:{alts})\b|npmjs\.com/package/(?:{alts})(?![\w-])"
               rf"|\bnpm (?:package|module)s? [`'\"]?(?:{alts})(?![\w/-])"
               rf"|(?<![\w/-])(?:{alts})[`'\"]? npm (?:package|module)"
               rf"|(?<![\w/-])(?:{alts}) \(npm\)|(?<![\w/-])(?:{alts})@\d")
    else:
        pat = (rf"pkg:pypi/(?:{alts})\b|pypi\.org/project/(?:{alts})(?![\w-])"
               rf"|\b(?:pypi|python) (?:package|module)s? [`'\"]?(?:{alts})(?![\w/-])"
               rf"|(?<![\w/-])(?:{alts})[`'\"]? (?:pypi|python) (?:package|module)"
               rf"|(?<![\w/-])(?:{alts}) \(pypi\)")
    return re.compile(pat, re.I)


def build_matchers(inv, versions_by_pkg):
    """Terms that connect free text to your inventory. Returns list of dicts.
    Each matcher carries the owning teams from the inventory and, for packages, an explicit-identity pattern."""
    inv = normalize_inventory(inv)
    owners = inv["_owners"]
    aliases = inv.get("aliases", {}) or {}
    ms = []

    def add(term, label, kind, versions=None, teams=None, identity=None, regex=None):
        ms.append({"re": regex or re.compile(r"(?<![\w/-])" + re.escape(term) + r"(?![\w/-])", re.I),
                   "term": term, "label": label, "kind": kind, "versions": versions or [],
                   "teams": list(teams or []), "identity": identity,
                   "plain": not re.search(r"[-./@\s]", term)})

    for name in (inv.get("npm") or {}):
        if name.startswith("@types/"):
            continue                                  # type stubs are never named in advisories
        vs = sorted(versions_by_pkg.get(name, []))
        teams = owners["npm"].get(name, [])
        ident = _identity_re({name, *[a for a in (aliases.get(name) or [])]}, "npm")
        if len(name) >= 4 and name.lower() not in GENERIC_NAMES:
            add(name.lower(), name, "npm", vs, teams, ident)   # scoped names are matched in full only
        else:
            add(name.lower(), name, "npm", vs, teams, ident, regex=_NEVER)   # generic: explicit identity only
        for a in aliases.get(name, []) or []:
            add(a, name, "npm", vs, teams, ident)
    for name in (inv.get("pypi") or {}):
        vs = [str(x) for x in inv["pypi"][name]]
        add(name.lower(), name, "pypi", vs, owners["pypi"].get(name, []),
            _identity_re({name, *(aliases.get(name) or [])}, "pypi"))
    for tool in inv.get("tools", []) or []:
        for t in set((tool.get("kev_keywords") or []) + (tool.get("news_keywords") or [])):
            add(t, tool["name"], "tool", [str(tool["version"])] if tool.get("version") else [],
                owners["tools"].get(tool["name"], []))
    return ms


def _hint_present(kind, text, term):
    hints = [h for h in ECO_HINTS.get(kind, []) if h != term.lower()]
    return bool(hints) and re.search(r"(?<![\w-])(?:" + "|".join(re.escape(h) for h in hints) + r")(?![\w-])", text, re.I)


def _evidence(m, title, body):
    """Why (if at all) this advisory text refers to the inventory item. Returns 'identity', 'title' or None.
    A word that merely appears in the description (or in a differently-named product) is never enough."""
    kind, full = m["kind"], f"{title} {body}"
    if kind == "tool":
        if not m["re"].search(title) or FOREIGN_ECO_NPM.search(title):
            return None
        if re.search(re.escape(m["term"]) + r"\s+(?:package|packages|module|library)\b", title, re.I):
            return None                               # "npm package foo" is not the npm CLI
        return "title"
    if m.get("identity") and m["identity"].search(full):
        return "identity"
    if not m["re"].search(title):
        return None                                   # body-only mentions are never a match
    foreign = FOREIGN_ECO_PYPI if kind == "pypi" else FOREIGN_ECO_NPM
    if m["plain"]:                                    # ordinary words (express, numpy, ...) need ecosystem context
        if foreign.search(full) or FOREIGN_PRODUCT.search(title):
            return None
        return "title" if _hint_present(kind, full, m["term"]) else None
    return None if foreign.search(title) else "title"


def match_text(matchers, title, body):
    """Matchers whose product is demonstrably the subject of the advisory text (see _evidence).
    Returned dicts are copies carrying an 'evidence' key."""
    hits, seen = [], set()
    for m in matchers:
        if m["label"] in seen:
            continue
        ev = _evidence(m, title, body)
        if ev:
            seen.add(m["label"])
            hits.append(dict(m, evidence=ev))
    hits.sort(key=lambda m: (not m["re"].search(title), -len(m["term"])))
    return hits


def _product_names(label):
    n = label.lower()
    names = {n, n.replace("-", "_"), n.replace("_", "-")}
    if n.startswith("@") and "/" in n:
        tail = n.split("/", 1)[1]
        names |= {tail, tail.replace("-", "_")}
    return names


def _cpe_verdict(c, cur):
    v = c["version"]
    if v not in ("*", "-"):
        pv = vt(v)
        return None if (pv is None or cur is None) else pv == cur
    bounds = {k: c.get(k) for k in ("vsi", "vse", "vei", "vee") if c.get(k)}
    if not bounds:
        return True if v == "*" else None
    if cur is None or any(vt(b) is None for b in bounds.values()):
        return None
    ok = True
    if "vsi" in bounds and not cur >= vt(bounds["vsi"]):
        ok = False
    if "vse" in bounds and not cur > vt(bounds["vse"]):
        ok = False
    if "vei" in bounds and not cur <= vt(bounds["vei"]):
        ok = False
    if "vee" in bounds and not cur < vt(bounds["vee"]):
        ok = False
    return ok


def _level(verdicts):
    if any(v is True for v in verdicts):
        return "confirmed"
    if not verdicts or any(v is None for v in verdicts):
        return "unverified"
    return None                                       # every inventory version is outside the affected range


def assess_match(m, osv_rec=None, nvd_rec=None):
    """Combine a text candidate with structured vulnerability data.
      'confirmed'  : structured data names the package AND an inventory version falls in the affected range
      'unverified' : text-only evidence, or the package matches but the version cannot be established
      None         : structured data shows the advisory is about a different product/version -> reject
    Tools are always 'unverified' (installed version is not known)."""
    if m.get("kind") not in OSV_ECO:
        return "unverified"
    eco, label, versions = OSV_ECO[m["kind"]], m["label"], m.get("versions") or []
    pkg_entries = [a for a in ((osv_rec or {}).get("affected") or []) if a.get("package")]
    if pkg_entries:
        mine = [a for a in pkg_entries if (a["package"].get("ecosystem") == eco
                                            and str(a["package"].get("name", "")).lower() == label.lower())]
        if not mine:
            return None
        return _level([osv_affects(osv_rec, label, eco, v) for v in versions])
    if nvd_rec and nvd_rec.get("cpes"):
        names = _product_names(label)
        mine = [c for c in nvd_rec["cpes"] if c["product"] in names and c.get("vulnerable", True)]
        if not mine:
            return None
        verdicts = []
        for v in versions:
            r = [_cpe_verdict(c, vt(v)) for c in mine]
            verdicts.append(True if any(x is True for x in r) else None if any(x is None for x in r) else False)
        return _level(verdicts)
    return "unverified"


# --------------------------------------------------------------------------- #
# News RSS / Atom
# --------------------------------------------------------------------------- #
def parse_feed(content):
    root = ET.fromstring(content)
    out = []
    for it in root.iter("item"):
        out.append({
            "title": (it.findtext("title") or "").strip(),
            "link": (it.findtext("link") or "").strip(),
            "date": parse_dt(it.findtext("pubDate")),
            "text": strip_html((it.findtext("description") or "") + " " +
                               (it.findtext("{http://purl.org/rss/1.0/modules/content/}encoded") or "")),
        })
    ns = "{http://www.w3.org/2005/Atom}"
    for it in root.iter(ns + "entry"):
        link = it.find(ns + "link")
        out.append({
            "title": (it.findtext(ns + "title") or "").strip(),
            "link": (link.get("href") if link is not None else "") or "",
            "date": parse_dt(it.findtext(ns + "published") or it.findtext(ns + "updated")),
            "text": strip_html((it.findtext(ns + "summary") or "") + " " + (it.findtext(ns + "content") or "")),
        })
    return out


# --------------------------------------------------------------------------- #
# Finding construction + rendering (the 8-field format)
# --------------------------------------------------------------------------- #
def finding(**kw):
    base = {"kind": "pkg", "id": None, "cve": None, "sev": None, "score": None, "kev": False, "mal": False,
            "epss": None, "impact": "", "tech": "", "fixed": [], "sources": "", "deprecated": False,
            "teams": [], "match": "unverified"}
    base.update(kw)
    return base


def sev_text(f):
    """Severity only. Exploitation evidence (CISA KEV) lives in its own field."""
    s = SEV_LABEL["CRITICAL"] if f["mal"] else SEV_LABEL[f["sev"]]
    if f["score"] is not None:
        s += f" (CVSS {f['score']})"
    if f["mal"]:
        s += " · malicious package"
    if f["epss"] is not None:
        s += f" · EPSS {f['epss']:.2f}"
    return s


def tech_text(f):
    t = f["tech"].rstrip(". ")
    if f["deprecated"]:
        t += " · package is deprecated, no fix expected, replace it"
    return f"{t}. {MATCH_CONFIRMED if f.get('match') == 'confirmed' else MATCH_UNVERIFIED}"


def teams_text(f):
    teams = f.get("teams") or []
    return ", ".join(teams) if teams else TEAMS_UNMAPPED


def relevance_text(f):
    teams = f.get("teams") or []
    checks = ("(1) whether the affected technology is actually deployed or used, (2) whether the deployed version "
              "falls within the affected range, (3) whether the vulnerable functionality or configuration is "
              "present, and (4) whether mitigation or remediation is required.")
    if teams:
        who = ", ".join(teams)
        return (f"This technology is in the inventory under {who}, so a vulnerability here may matter to them. "
                f"An inventory match does not confirm deployment or an exploitable condition. {who} should verify {checks}")
    return ("This technology is in the inventory but no owning team is mapped, so the owner must be identified first. "
            "An inventory match does not confirm deployment or an exploitable condition. The owning team should "
            f"verify {checks}")


def exploit_text(f):
    return EXPLOIT_CONFIRMED if f.get("kev") else EXPLOIT_UNCONFIRMED


def action_text(f):
    teams = f.get("teams") or []
    owner = ", ".join(teams) if teams else "The owning team (not mapped in the inventory)"
    steps = [f"{owner}: verify the technology is deployed and which version is running, and check whether the "
             "vulnerable component or functionality is enabled."]
    if f.get("deprecated"):
        steps.append("The package is deprecated: plan a replacement.")
    if f.get("fixed"):
        steps.append(f"Upgrade to a fixed version named in the advisory ({', '.join(f['fixed'])}) once you have "
                     "confirmed it applies to the deployed version.")
    else:
        steps.append("No fixed version is stated in the available data: follow the vendor's advisory for a fix.")
    steps.append("If patching cannot happen immediately, apply the vendor's recommended mitigations.")
    if f.get("kev"):
        steps.append("CISA lists this as exploited in the wild: treat it as urgent and follow the required action in the CISA KEV entry.")
    else:
        steps.append("Prioritise remediation using severity, exploitation evidence and business impact.")
    return " ".join(steps)


def render_finding(f, n=None):
    cve_text = f["cve"] or f"No CVE assigned ({f['id']})"
    return "\n".join([
        f"*{n}.* CVE: {esc(cve_text)}" if n else f"• CVE: {esc(cve_text)}",
        f"• Severity: {esc(sev_text(f))}",
        f"• Affected technology: {esc(tech_text(f))}",
        f"• Affected team/s: {esc(teams_text(f))}",
        f"• Potential impact: {esc(f['impact'] or 'Not described in the advisory.')}",
        f"• Relevance: {esc(relevance_text(f))}",
        f"• Exploitation status: {exploit_text(f)}",
        f"• Recommended action: {esc(action_text(f))}",
        f"• Source: {f['sources']}",
        SEP,
    ])


def priority(f):
    rank = 0 if f["mal"] else 1 if f["kev"] else 2 + SEV_ORDER[f["sev"]]
    return (rank, -(f["epss"] or 0.0), f["cve"] or f["id"] or "")


def bucket(f):
    if f["mal"] or f["kev"] or f["sev"] in ("CRITICAL", "HIGH"):
        return "high"
    return {"MEDIUM": "medium", "LOW": "low"}.get(f["sev"], "unrated")


def compact_line(f, n=None):
    teams = f.get("teams") or []
    return (f"{('*%d.* ' % n) if n else '• '}{esc(f['cve'] or f['id'])} · {esc(f['tech'][:80])} · "
            f"{SEV_LABEL[f['sev']]} · {esc(', '.join(teams) if teams else 'teams unmapped')} · {f['sources']}")


def footer_text(health_line, baseline):
    if baseline:
        return "_" + health_line + "_"
    return "_" + health_line + " · " + FOOTER_NOTE + "_"


# --------------------------------------------------------------------------- #
# Alert history + monthly executive overview
# --------------------------------------------------------------------------- #
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def alert_history(state):
    h = state.get("alert_history")
    return h if isinstance(h, dict) else {}


def record_alerts(state, items, date_str):
    """Record each unique vulnerability (CVE id, or OSV id when no CVE exists) the first time it is reported.
    Called only after a real, non-baseline report was delivered. Returns the number of new records."""
    hist = state.get("alert_history")
    if not isinstance(hist, dict):
        hist = state["alert_history"] = {}
    added = 0
    for f in items:
        key = str(f.get("cve") or f.get("id") or "").upper()
        if not key or key in hist:
            continue
        hist[key] = {"first_seen": date_str, "kind": f.get("kind"),
                     "severity": "CRITICAL" if f.get("mal") else f.get("sev"), "score": f.get("score")}
        added += 1
    return added


def _entry_date(e):
    d = str(e.get("first_seen") or "") if isinstance(e, dict) else ""
    return d if DATE_RE.fullmatch(d) else None


def monthly_summary(state, year, month):
    """Counts of unique recorded alerts first identified in the given month. Read-only; never fabricates history."""
    prefix = f"{year:04d}-{month:02d}"
    hist = alert_history(state)
    new = high = 0
    for e in hist.values():
        d = _entry_date(e)
        if d and d.startswith(prefix):
            new += 1
            if str(e.get("severity") or "").upper() in ("HIGH", "CRITICAL"):
                high += 1
    started = str(state.get("alert_history_started") or "")
    if not DATE_RE.fullmatch(started):
        dates = sorted(d for d in map(_entry_date, hist.values()) if d)
        started = dates[0] if dates else None
    ny, nm = (year + 1, 1) if month == 12 else (year, month + 1)
    start, end = f"{prefix}-01", f"{ny:04d}-{nm:02d}-01"
    note = None
    if started is None:
        note = ("No alert history has been recorded yet; tracking starts with the next inventory scan, "
                "so these counts do not cover this month fully.")
    elif started >= end:
        note = f"Alert tracking began on {started}; nothing was recorded for this period and earlier months are not estimated."
    elif started > start:
        note = f"Alert tracking began on {started}; alerts identified earlier in this month were not recorded and are not included."
    return {"label": datetime(year, month, 1).strftime("%B %Y"), "new": new, "high": high, "note": note}


def render_monthly_summary(s):
    text = ("🛡️ SECURITY WATCH — MONTHLY EXECUTIVE OVERVIEW\n\n"
            f"Reporting period: {s['label']}\n\n"
            f"• New vulnerability alerts identified: {s['new']}\n\n"
            f"• High/Critical vulnerabilities identified: {s['high']}")
    if s.get("note"):
        text += f"\n\n_Note: {s['note']}_"
    return text


def parse_month(s):
    m = re.fullmatch(r"(\d{4})-(\d{2})", s or "")
    if not m or not 1 <= int(m[2]) <= 12:
        raise ValueError(f"--month must look like 2026-10, got {s!r}")
    return int(m[1]), int(m[2])


def run_monthly(args, tz, state, webhook):
    if args.month:
        year, month = parse_month(args.month)
    else:
        local = NOW.astimezone(tz)
        year, month = local.year, local.month
    text = render_monthly_summary(monthly_summary(state, year, month))
    if args.dry_run:
        print(text)
        return 0
    post_slack(webhook, [text])
    print(text)
    return 0                                           # state is never written in this mode


# --------------------------------------------------------------------------- #
# Slack
# --------------------------------------------------------------------------- #
def split_blocks(blocks, limit=3800):
    msgs, cur = [], ""
    for b in blocks:
        if cur and len(cur) + len(b) + 2 > limit:
            msgs.append(cur)
            cur = ""
        cur = (cur + "\n\n" + b) if cur else b
    if cur:
        msgs.append(cur)
    return msgs


def post_slack(webhook, messages):
    for m in messages:
        r = SESSION.post(webhook, json={"text": m, "mrkdwn": True, "unfurl_links": False,
                                        "unfurl_media": False}, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"Slack returned {r.status_code}: {r.text[:200]}")
        time.sleep(1.1)       # Slack asks for ~1 message per second per webhook


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", default="inventory.yml")
    ap.add_argument("--state", default=os.environ.get("STATE_PATH", "state/state.json"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--mode", choices=["full", "news"], default="full",
                    help="full = inventory scan (9 AM, 2 PM); news = cve.now CVSS 9.5+ digest (7 PM)")
    ap.add_argument("--monthly-summary", action="store_true",
                    help="print/post the monthly executive overview from stored alert history (never modifies state)")
    ap.add_argument("--month", help="reporting month for --monthly-summary, e.g. 2026-10 (default: current month)")
    args = ap.parse_args(argv)

    with open(args.inventory, "r", encoding="utf-8") as f:
        inv = normalize_inventory(yaml.safe_load(f))
    st = inv.get("settings", {}) or {}
    tz = ZoneInfo(st.get("timezone", "Africa/Lagos"))
    strategy = st.get("version_strategy", "newest")
    max_detail = int(st.get("max_detailed_items", 40))
    news_hours = int(st.get("news_max_age_hours", 24))
    news_cve_days = int(st.get("news_cve_max_age_days", 45))
    tool_cve_days = int(st.get("tool_cve_max_age_days", 45))
    eol_warn = int(st.get("eol_warn_days", 90))
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook and not args.dry_run:
        log("SLACK_WEBHOOK_URL is not set (use --dry-run to test without Slack).")
        return 2

    state = load_state(args.state)
    if args.monthly_summary:
        try:
            return run_monthly(args, tz, state, webhook)
        except ValueError as e:
            log(str(e))
            return 2
    if args.mode == "news":
        return run_news(args, inv, st, tz, state, webhook)
    baseline = args.baseline or not state.get("initialized")
    last_run = parse_dt(state.get("last_run")) or (NOW - timedelta(hours=news_hours))
    today = NOW.date().isoformat()
    local_today = NOW.astimezone(tz).date().isoformat()
    min_news = news_threshold(st)
    health = {}
    log(f"Run at {NOW.isoformat()} · baseline={baseline}")

    # ---- 1. npm registry: resolve ranges + detect deprecations ------------------
    registry, reg_fail = {}, 0
    names = list((inv.get("npm") or {}).keys())
    with cf.ThreadPoolExecutor(8) as ex:
        futs = {ex.submit(fetch_registry, n): n for n in names}
        for fut in cf.as_completed(futs):
            n = futs[fut]
            try:
                registry[n] = fut.result()
            except Exception as e:
                registry[n] = None
                reg_fail += 1
                log(f"registry {n}: {e}")
    health["npm registry"] = "✓" if not reg_fail else f"⚠️ {reg_fail} unreachable"

    targets, unresolved, versions_by_pkg, deprecated = [], [], {}, {}
    for name, specs in (inv.get("npm") or {}).items():
        reg = registry.get(name)
        for spec in specs:
            res = resolve_spec(spec, reg)
            if res is None or res[0] is None:
                unresolved.append(f"{name}@{spec}")
                continue
            assumed, floor = res
            vers = {"newest": [assumed], "floor": [floor], "both": [assumed, floor]}.get(strategy, [assumed])
            vers = list(dict.fromkeys(v for v in vers if v))
            targets.append({"key": f"npm:{name}@{spec}", "eco": "npm", "name": name, "spec": str(spec), "versions": vers})
            versions_by_pkg.setdefault(name, set()).update(vers)
            if reg:
                msg = reg["deprecated"].get(reg.get("latest")) or next(
                    (reg["deprecated"][v] for v in vers if v in reg["deprecated"]), None)
                if msg:
                    deprecated[name] = short_text(str(msg), 140)
    for name, specs in (inv.get("pypi") or {}).items():
        for spec in specs:
            targets.append({"key": f"pypi:{name}@{spec}", "eco": "PyPI", "name": name.lower(),
                            "spec": str(spec), "versions": [str(spec)]})
            versions_by_pkg.setdefault(name, set()).add(str(spec))

    # ---- 2. OSV -------------------------------------------------------------
    ids_by_key, hits, failed = osv_query(targets)
    health["OSV"] = "✓" if not failed else f"⚠️ {len(failed)} lookups failed"
    pkg_state = {k: set(v) for k, v in (state.get("pkg_vulns") or {}).items()}
    new_ids, baselined = {}, 0                      # vuln id -> [(key,name,eco,ver)]
    for key, ids in ids_by_key.items():
        prev = pkg_state.get(key)
        if prev is None or baseline:
            baselined += len(ids)
            pkg_state[key] = set(ids) | (prev or set())
            continue
        for vid in ids - prev:
            for h in hits.get(vid, []):
                if h[0] == key:
                    new_ids.setdefault(vid, []).append(h)
        pkg_state[key] = prev | ids
    spec_of = {t["key"]: t["spec"] for t in targets}

    def pkg_owner_keys(hit_list):
        out = []
        for _key, name, eco, _ver in hit_list:
            out += owners_of(inv, "pypi" if eco == "PyPI" else "npm", name)
        return out

    # ---- 3. KEV -------------------------------------------------------------
    kev, kev_seen = {}, seen_dict(state, "kev_seen")
    try:
        kev = load_kev()
        health["CISA KEV"] = "✓"
    except Exception as e:
        log(f"KEV failed: {e}")
        health["CISA KEV"] = "⚠️ unavailable"
    kev_new = {} if (baseline or not kev) else {c: e for c, e in kev.items() if c not in kev_seen}
    for c in kev:
        kev_seen.setdefault(c, today)

    announced = seen_dict(state, "announced_cves")
    findings, run_cves = [], set()

    # ---- 4. package findings (new OSV ids) -------------------------------------
    details = {}
    if new_ids and not baseline:
        with cf.ThreadPoolExecutor(8) as ex:
            futs = {ex.submit(osv_detail, vid): vid for vid in new_ids}
            for fut in cf.as_completed(futs):
                try:
                    details[futs[fut]] = fut.result()
                except Exception as e:
                    log(f"OSV detail {futs[fut]}: {e}")
    for vid, tlist in new_ids.items():
        v = details.get(vid) or {"id": vid}
        if v.get("withdrawn"):
            continue
        cve = pick_cve(v)
        if cve and (cve in announced or cve in run_cves):
            continue
        mal = vid.startswith("MAL-")
        sev, score = osv_severity(v), None
        if mal:
            sev = "CRITICAL"
        if sev is None and cve:
            n = nvd_cve(cve)
            if n:
                sev, score = n["severity"] if n["severity"] in SEV_ORDER else None, n["score"]
        grouped, fixed = {}, []
        for key, name, eco, ver in sorted(set(tlist)):
            grouped.setdefault((name, ver), []).append(spec_of.get(key, "?"))
            fixed += fixed_versions(v, name, eco, ver)
        techs = [f"{n} {ver} (inventory {', '.join(sorted(set(sp)))})" for (n, ver), sp in sorted(grouped.items())]
        shown = ", ".join(techs[:3]) + (f" +{len(techs) - 3} more" if len(techs) > 3 else "")
        if any(sp != ver for (_n, ver), specs_ in grouped.items() for sp in specs_):
            shown += ". Matched against the newest release in the declared range; the deployed version is not verified"
        findings.append(finding(
            kind="pkg", id=vid, cve=cve, sev=sev, score=score, mal=mal,
            kev=bool(cve and cve in kev), impact=short_text(v.get("details") or v.get("summary") or ""),
            tech=shown, match="confirmed", teams=resolve_teams(inv, pkg_owner_keys(tlist)),
            fixed=list(dict.fromkeys(fixed))[:3], sources=f"<{advisory_url(v)}>",
            deprecated=any(h[1] in deprecated for h in tlist)))
        if cve:
            run_cves.add(cve)

    # newly KEV-listed CVEs that match an already-known advisory for your packages
    all_hit_ids = {i for k, ids in ids_by_key.items() for i in ids}
    for cve_id, entry in kev_new.items():
        if cve_id in run_cves:
            continue
        try:
            rec = osv_detail(cve_id)
        except Exception:
            continue
        rec_ids = {rec.get("id")} | set(rec.get("aliases", []) or [])
        match = rec_ids & all_hit_ids
        if not match:
            continue
        hit_list = [h for i in match for h in hits.get(i, [])]
        who = sorted({f"{h[1]} {h[3]}" for h in hit_list})[:3]
        findings.append(finding(
            kind="pkg", id=cve_id, cve=cve_id, sev="CRITICAL", kev=True,
            impact="Newly added to CISA's exploited list. " + short_text(entry.get("shortDescription", "")),
            tech=", ".join(who), match="confirmed", teams=resolve_teams(inv, pkg_owner_keys(hit_list)),
            sources=f"<https://nvd.nist.gov/vuln/detail/{cve_id}>"))
        run_cves.add(cve_id)

    # ---- 5. tools: KEV keywords + NVD ------------------------------------------
    tool_findings = {}
    tools = inv.get("tools", []) or []
    for cve_id, entry in kev_new.items():
        text = f"{entry.get('vendorProject', '')} {entry.get('product', '')}".lower()
        for tool in tools:
            if any(re.search(r"(?<![\w-])" + re.escape(k.lower()) + r"(?![\w-])", text)
                   for k in tool.get("kev_keywords", []) or []):
                f = tool_findings.setdefault(cve_id, finding(
                    kind="tool", id=cve_id, cve=cve_id, kev=True,
                    impact="Newly added to CISA's exploited list. " + short_text(entry.get("shortDescription", "")),
                    sources=f"<https://nvd.nist.gov/vuln/detail/{cve_id}>"))
                f["_tools"] = f.get("_tools", []) + [tool]
    tool_seen = seen_dict(state, "tool_cves_seen")
    nvd_ok = True
    since = NOW - timedelta(days=tool_cve_days) if baseline else max(last_run - timedelta(hours=2), NOW - timedelta(days=14))
    for tool in tools:
        if not tool.get("cpe"):
            continue
        try:
            for c in nvd_tool_cves(tool, since, NOW):
                cid = c["id"]
                if not cid or c["status"].lower().startswith("reject") or c["severity"] == "NONE":
                    continue
                pub = parse_dt(c["published"])
                if pub and pub < NOW - timedelta(days=tool_cve_days):
                    continue
                is_new = cid not in tool_seen
                tool_seen.setdefault(cid, today)
                if baseline or not is_new or cid in announced:
                    continue
                f = tool_findings.setdefault(cid, finding(
                    kind="tool", id=cid, cve=cid, kev=cid in kev,
                    sources=f"<https://nvd.nist.gov/vuln/detail/{cid}>"))
                f["sev"] = c["severity"] if c["severity"] in SEV_ORDER else f["sev"]
                f["score"] = c["score"]
                f["impact"] = f["impact"] or short_text(c["summary"])
                f["_tools"] = f.get("_tools", []) + [tool]
        except Exception as e:
            nvd_ok = False
            log(f"NVD tool query {tool['name']} failed: {e}")
    health["NVD"] = "✓" if nvd_ok else "⚠️ some tool lookups failed"
    for cid, f in list(tool_findings.items()):
        if cid in run_cves or (cid in announced and not f["kev"]):
            tool_findings.pop(cid)
            continue
        tl = f.pop("_tools", [])
        names = list(dict.fromkeys(t["name"] for t in tl))
        vers = [f"{t['name']} {t['version']}" for t in tools if t["name"] in names and t.get("version")]
        f["tech"] = ", ".join(names) + (f" (your version: {', '.join(vers)})" if vers else " (version unknown, check your installed version)")
        f["teams"] = resolve_teams(inv, [k for t in tl for k in (t.get("teams") or [])])
        f["match"] = "unverified"                    # matched by product name only; installed version unknown
        findings.append(f)
        run_cves.add(cid)

    # ---- 6. cve.now early warning ----------------------------------------------
    early = []
    ns = {"queue": sanitize_queue(state.get("news_queue"), today, min_news),
          "done": dict(state.get("news_done") or {}), "tries": dict(state.get("news_tries") or {})}
    cn_seen = seen_dict(state, "cvenow_seen")
    cn_url = st.get("cvenow_url", CVENOW_URL)
    try:
        raw = fetch_cvenow(cn_url)
        parsed = dedupe_cvenow(raw)
        mods = [p["modified"] for p in parsed.values() if p["modified"]]
        oldest = min(mods) if mods else None
        health["cve.now"] = "✓"
        if not baseline and oldest and oldest > last_run:
            health["cve.now"] = (f"⚠️ feed window ({oldest.astimezone(tz).strftime('%H:%M')} → now) is shorter than "
                                 f"the gap since last run; OSV/NVD/KEV still cover the rest")
        matchers = build_matchers(inv, versions_by_pkg)
        for cid, p in parsed.items():
            is_new = cid not in cn_seen
            cn_seen.setdefault(cid, today)
            if baseline or not is_new or cid in announced or cid in run_cves or not p["text"]:
                continue
            ms = match_text(matchers, p["title"], p["text"])
            if not ms:
                continue
            n = nvd_cve(cid)
            rec = osv_record(cid)
            kept = []
            for m in ms:
                lvl = assess_match(m, rec, n)
                if lvl:
                    kept.append((m, lvl))
                else:
                    log(f"early warning {cid}: structured data does not support a match on {m['label']}; dropped")
            if not kept:
                continue
            score, sev = p["score"], sev_from_score(p["score"])
            if n:
                pub = parse_dt(n["published"])
                if pub and pub < NOW - timedelta(days=int(st.get("early_max_age_days", 14))):
                    continue                              # old CVE, feed entry is just an update
                if score is None:
                    score, sev = n["score"], (n["severity"] if n["severity"] in SEV_ORDER else None)
            techs = []
            for m, _lvl in kept[:2]:
                if m["kind"] == "tool":
                    techs.append(f"{m['label']} (version unknown, check your installed version)")
                else:
                    vs = ", ".join(m["versions"][:6]) or "version unknown"
                    techs.append(f"{m['label']} (inventory {vs})")
            level = "confirmed" if all(l == "confirmed" for _m, l in kept) else "unverified"
            tech = "; ".join(techs)
            if level != "confirmed":
                tech += ". The available advisory data does not establish that the inventory version is affected"
            early.append(finding(
                kind="early", id=cid, cve=cid, sev=sev, score=score, kev=cid in kev,
                impact=short_text(f"{p['title']}. {p['text']}", 280), tech=tech, match=level,
                teams=resolve_teams(inv, [k for m, _l in kept for k in m["teams"]]),
                sources=f"<{p['url']}> · <https://nvd.nist.gov/vuln/detail/{cid}>"))
            run_cves.add(cid)
        # silently queue CVSS 9.5+ items outside your inventory for the 7 PM news digest
        lookups = int(st.get("news_page_lookups_per_run", 150)) if st.get("news_page_scores", True) else 0
        collect_news(parsed, matchers, ns, today, min_news, announced, run_cves,
                     score_lookup=cvenow_page_score, budget=lookups)
    except Exception as e:
        log(f"cve.now failed: {e}")
        health["cve.now"] = "⚠️ unavailable"

    # ---- 7. EPSS for everything we are about to show -----------------------------
    all_f = findings + early
    scores = epss_scores({f["cve"] for f in all_f if f["cve"]}) if all_f else {}
    for f in all_f:
        f["epss"] = scores.get(f["cve"])
    health["EPSS"] = "✓" if (scores or not all_f) else "⚠️ unavailable"

    # ---- 8. informational: deprecations + end-of-life -----------------------------
    dep_announced = seen_dict(state, "deprecated_announced")
    dep_new = {n: m for n, m in deprecated.items() if n not in dep_announced}
    eol_announced = seen_dict(state, "eol_announced")
    eol_new = [(k, t) for k, t in check_eol(inv.get("eol"), eol_warn) if k not in eol_announced]
    eol_teams = {e.get("product"): entry_versions_teams({"teams": e.get("teams")})[1] for e in (inv.get("eol") or [])}

    def team_suffix(keys):
        labels = resolve_teams(inv, keys)
        return f" (Teams: {', '.join(labels)})" if labels else ""

    # ---- 9. news ----------------------------------------------------------------------
    news_out, news_seen = [], seen_dict(state, "news_seen")
    news_since = max(last_run, NOW - timedelta(hours=news_hours))
    nm = build_matchers(inv, versions_by_pkg)
    terms = [re.compile(r"(?<![\w-])" + re.escape(t) + r"(?![\w-])", re.I)
             for t in (inv.get("news_keywords") or [])]
    news_fail, news_bad = 0, []
    feeds = inv.get("news_feeds")
    if feeds is None:
        feeds = DEFAULT_NEWS                       # key missing entirely: use the built-in default
    for feed in feeds:                             # news_feeds: [] means no extra news sources
        try:
            r = SESSION.get(feed["url"], timeout=30, headers={
                "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5"})
            r.raise_for_status()
            head = r.content.lstrip()[:200]
            if not head.startswith((b"<?xml", b"<rss", b"<feed", b"<rdf")):
                ctype = getattr(r, "headers", {}).get("Content-Type", "?")
                raise ValueError(f"address returned a web page, not a feed "
                                 f"(Content-Type: {ctype}; starts with: {head[:80]!r})")
            entries = parse_feed(r.content)
        except Exception as e:
            news_fail += 1
            news_bad.append(feed["name"])
            log(f"news {feed['name']}: {e}")
            continue
        for a in entries:
            if not a["link"] or a["link"] in news_seen:
                continue
            news_seen[a["link"]] = today
            if baseline or not a["date"] or a["date"] < news_since or a["date"] < NOW - timedelta(hours=news_hours):
                continue
            hay = f"{a['title']} {a['text']}"
            cves = sorted({c.upper() for c in CVE_RE.findall(hay)})[:4]
            relevant = any(t.search(hay) for t in terms) or any(c in run_cves for c in cves) \
                or bool(match_text(nm, a["title"], ""))
            if not relevant:
                continue
            status, old = [], 0
            for c in cves:
                n = nvd_cve(c)
                if n is None:
                    status.append(f"{c} (not yet in NVD, unconfirmed)")
                    continue
                pub = parse_dt(n["published"])
                if pub and pub < NOW - timedelta(days=news_cve_days):
                    old += 1
                    continue
                status.append(f"{c} (verified in NVD" + (f", {SEV_LABEL[n['severity']]}" if n["severity"] in SEV_ORDER else "") + ")")
            if cves and old == len(cves):
                continue                                  # recycled story about old CVEs
            if cves and all(c in run_cves or c in announced for c in cves):
                continue                                  # already reported from another source
            news_out.append(f"• <{a['link']}|{esc(a['title'][:110])}> · {feed['name']}" +
                            (f" · {esc('; '.join(status))}" if status else " · no CVE named yet"))
    if feeds:
        health["News"] = "✓" if not news_fail else f"⚠️ {', '.join(news_bad)}: not a readable feed (see log)"

    # ---- 10. build the message(s) -----------------------------------------------------
    stamp = NOW.astimezone(tz).strftime("%a %d %b %Y · %I:%M %p") + " Lagos"
    health_line = "Sources: " + " · ".join(f"{k} {v}" for k, v in health.items())
    blocks = []
    n_pkgs = len({t["name"] for t in targets})

    if baseline:
        blocks.append(f"✅ *Security Watch: baseline complete* · {stamp}\n"
                      f"Recorded {baselined} existing advisories across {n_pkgs} packages, {len(kev)} KEV entries and "
                      f"{len(cn_seen)} recent cve.now items. From now on you only see NEW findings, once each.")
        if deprecated:
            blocks.append("ℹ️ *Deprecated packages in your inventory (one-time notice)*\n" +
                          "\n".join(f"• `{n}`: {esc(m)}{esc(team_suffix(owners_of(inv, 'npm', n)))}"
                                    for n, m in sorted(deprecated.items())))
        if eol_new:
            blocks.append("ℹ️ *End-of-life (one-time notice)*\n" +
                          "\n".join(f"• {esc(t)}{esc(team_suffix(eol_teams.get(k.split(':')[0], [])))}" for k, t in eol_new))
        notes = []
        if inv.get("unversioned"):
            notes.append("No version given, not scanned: " + ", ".join(inv["unversioned"]))
        if unresolved:
            notes.append("Version spec too complex to resolve: " + ", ".join(unresolved[:15]))
        if notes:
            blocks.append("\n".join(notes))
    else:
        main_f = sorted([f for f in findings if f["kind"] == "pkg"], key=priority)
        tools_f = sorted([f for f in findings if f["kind"] == "tool"], key=priority)
        early_f = sorted(early, key=priority)
        counts = {k: sum(1 for f in main_f if bucket(f) == k) for k in ("high", "medium", "low", "unrated")}
        total = len(main_f) + len(tools_f) + len(early_f)
        anything = total or dep_new or eol_new or news_out
        head = f"🛡️ *Security Watch* · {stamp}\n"
        if not anything:
            head += "✅ No new findings."
        else:
            head += (f"{len(main_f)} package finding(s) ({counts['high']} high/critical), {len(early_f)} early warning(s), "
                     f"{len(tools_f)} tool item(s), {len(dep_new) + len(eol_new)} informational, {len(news_out)} news.")
        blocks.append(head)
        detailed = 0
        num = 0

        def section(title, items):
            nonlocal detailed, num
            if not items:
                return
            blocks.append(title)
            for f in items:
                num += 1
                if detailed < max_detail:
                    blocks.append(render_finding(f, num))
                    detailed += 1
                else:
                    blocks.append(compact_line(f, num))

        section("🔴 *CRITICAL / HIGH*", [f for f in main_f if bucket(f) == "high"])
        section("🟠 *MEDIUM*", [f for f in main_f if bucket(f) == "medium"])
        section("⚪ *LOW*", [f for f in main_f if bucket(f) == "low"])
        section("❔ *UNRATED* (severity not published yet)", [f for f in main_f if bucket(f) == "unrated"])
        section("🆕 *EARLY WARNING* (cve.now feed, unconfirmed until OSV/NVD catch up)", early_f)
        section("🟡 *MAY AFFECT YOU: tools* (check your installed version)", tools_f)
        if dep_new or eol_new:
            lines = [f"• `{n}` deprecated: {esc(m)}{esc(team_suffix(owners_of(inv, 'npm', n)))}"
                     for n, m in sorted(dep_new.items())]
            lines += [f"• {esc(t)}{esc(team_suffix(eol_teams.get(k.split(':')[0], [])))}" for k, t in eol_new]
            blocks.append("ℹ️ *INFORMATIONAL*\n" + "\n".join(lines))
        if news_out:
            blocks.append("📰 *NEWS* (new since last run; CVEs checked against NVD)\n" + "\n".join(news_out))
    blocks.append(footer_text(health_line, baseline))
    messages = split_blocks(blocks)

    # ---- 11. deliver, then (only then) remember ------------------------------------------
    if args.dry_run:
        print(("\n" + "=" * 60 + "\n").join(messages))
        log("Dry run: nothing sent, state not saved.")
        return 0
    post_slack(webhook, messages)

    for f in findings + early:
        if f["cve"]:
            announced.setdefault(f["cve"], today)
    dep_announced.update({n: today for n in deprecated if n not in dep_announced})
    eol_announced.update({k: today for k, _ in eol_new})
    if not baseline:                                  # baseline results are never counted as new alerts
        record_alerts(state, findings + early, local_today)
    state.setdefault("alert_history_started", local_today)
    state.update({
        "initialized": True,
        "last_run": NOW.isoformat(),
        "pkg_vulns": {k: sorted(v) for k, v in pkg_state.items()},
        "kev_seen": kev_seen,
        "tool_cves_seen": prune(tool_seen, 120),
        "cvenow_seen": prune(cn_seen, 30),
        "announced_cves": prune(announced, 365),
        "deprecated_announced": dep_announced,
        "eol_announced": eol_announced,
        "news_seen": prune(news_seen, 30),
        "news_queue": ns["queue"],
        "news_done": prune(ns["done"], 30),
        "news_tries": ns.get("tries", {}),
    })
    save_state(args.state, state)
    log("Done: posted to Slack and saved state.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
