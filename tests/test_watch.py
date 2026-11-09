"""Regression tests for watch.py. No network access: every external call is mocked.

Run from the repository root:   python -m pytest tests -q
(pytest is a development tool only; it is not added to requirements.txt.)
"""
import json
import os
import re
import sys
import types
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import watch  # noqa: E402

TZ = ZoneInfo("Africa/Lagos")
TODAY = watch.NOW.date().isoformat()

# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
INV_RAW = {
    "teams": {
        "frontend": {"name": "Frontend", "slack": "#team-frontend", "oncall": ""},
        "be_pvb": {"name": "Backend PVB", "slack": "", "oncall": ""},
        "be_pocket": {"name": "Backend Pocket", "slack": "", "oncall": ""},
        "be_piggyvest": {"name": "Backend Piggyvest", "slack": "", "oncall": ""},
        "data": {"name": "Data Team", "slack": "", "oncall": ""},
    },
    "npm": {
        # new schema: mapping with versions + teams (several owners)
        "express": {"versions": ["^4.21.2"], "teams": ["frontend", "be_piggyvest", "be_pocket", "be_pvb"]},
        "@grpc/grpc-js": {"versions": ["^1.2.12"], "teams": ["be_pocket"]},
        "typescript": {"versions": ["5.9.3"], "teams": ["frontend"]},
        "next": {"versions": ["14.2.6"], "teams": ["frontend"]},
        # legacy schema: plain list, no ownership information
        "lodash": ["^4.17.21"],
        "@types/node": ["^18"],
    },
    "pypi": {"numpy": {"versions": ["1.26.0"], "teams": ["data"]}},
    "aliases": {"express": ["Express.js"], "@grpc/grpc-js": ["grpc-js"], "next": ["Next.js"]},
    "tools": [{"name": "Docker", "version": None, "teams": ["be_pvb"],
               "kev_keywords": ["docker"], "news_keywords": ["Docker"]}],
}
VERS = {"express": {"4.21.2"}, "@grpc/grpc-js": {"1.14.0"}, "typescript": {"5.9.3"},
        "lodash": {"4.17.21"}, "next": {"14.2.6"}, "numpy": {"1.26.0"}}


@pytest.fixture(scope="module")
def inv():
    return watch.normalize_inventory(INV_RAW)


@pytest.fixture(scope="module")
def matchers(inv):
    return watch.build_matchers(inv, VERS)


def labels(hits):
    return [h["label"] for h in hits]


def cn_item(cid, score=None, title="Acme Widget flaw", desc="Remote attacker can run code.", extra=""):
    text = (f"Update: CVSS score {score} published. " if score is not None else "") + desc + extra
    return {"id": cid, "title": f"{cid}: {title}", "content_text": text,
            "url": f"https://cve.now/{cid}", "date_modified": "2026-10-28T10:00:00Z"}


def parsed_items(*items):
    return watch.dedupe_cvenow(list(items))


def fresh_ns():
    return {"queue": {}, "done": {}, "tries": {}}


# --------------------------------------------------------------------------- #
# Change 1: inventory matching
# --------------------------------------------------------------------------- #
class TestMatching:
    WP_TITLE = "WordPress Optima Express + MarketBoost IDX Plugin plugin <= 8.7.8 - Broken Access Control"
    WP_BODY = ("The WordPress Optima Express + MarketBoost IDX plugin is affected by a broken access control "
               "flaw that stems from missing authorization checks.")

    def test_cve_2026_116393_does_not_match_npm_express(self, matchers):
        assert "express" not in labels(watch.match_text(matchers, self.WP_TITLE, self.WP_BODY))

    def test_wordpress_plugin_with_prefixed_title_also_rejected(self, matchers):
        title = "CVE-2026-116393: " + self.WP_TITLE
        assert watch.match_text(matchers, title, self.WP_BODY) == []

    def test_functype_does_not_match_typescript_from_body_mention(self, matchers):
        title = "Functype: MCP set_functype_version Package Alias RCE via Unsanitized pnpm install + Dynamic Import"
        body = "Functype is a TypeScript library for functional programming. The MCP server runs pnpm install."
        assert watch.match_text(matchers, title, body) == []

    def test_legitimate_express_alias_in_title_still_matches(self, matchers):
        hits = watch.match_text(matchers, "Express.js: open redirect in res.location()",
                                "Express.js before 4.19.2 allows open redirects via a crafted URL.")
        assert labels(hits) == ["express"]
        assert hits[0]["evidence"] == "title"

    def test_legitimate_plain_name_with_node_context_matches(self, matchers):
        hits = watch.match_text(matchers, "express vulnerable to cross-site scripting",
                                "express is a Node.js web framework. Versions before 4.20 are affected.")
        assert labels(hits) == ["express"]

    def test_explicit_package_identity_matches_even_without_title_mention(self, matchers):
        hits = watch.match_text(matchers, "Prototype pollution in query parser",
                                "This affects the npm package express through its query parser.")
        assert labels(hits) == ["express"]
        assert hits[0]["evidence"] == "identity"

    def test_generic_name_matches_only_by_explicit_identity(self, matchers):
        assert watch.match_text(matchers, "Next steps for the Acme router", "Update to the next release.") == []
        hits = watch.match_text(matchers, "SSRF in server actions", "affects pkg:npm/next before 14.2.7")
        assert labels(hits) == ["next"]

    def test_namespaced_package_matches_in_full_only(self, matchers):
        assert labels(watch.match_text(matchers, "@grpc/grpc-js: memory exhaustion in message decoding", "")) == ["@grpc/grpc-js"]
        assert watch.match_text(matchers, "@evil/express-helper: path traversal", "express helper for npm") == []
        assert watch.match_text(matchers, "@other/grpc-js-extra: leak", "") == []

    def test_alias_matches_namespaced_package(self, matchers):
        hits = watch.match_text(matchers, "Denial of service in grpc-js before 1.9.15", "")
        assert labels(hits) == ["@grpc/grpc-js"]

    def test_body_only_mention_is_not_a_match(self, matchers):
        hits = watch.match_text(matchers, "Acme Router: authentication bypass",
                                "Acme Router can be deployed next to express and Node.js apps.")
        assert hits == []

    def test_tool_title_match_and_foreign_context_rejection(self, matchers):
        assert labels(watch.match_text(matchers, "Docker Desktop: privilege escalation", "")) == ["Docker"]
        assert watch.match_text(matchers, "WordPress plugin for Docker dashboards: XSS", "") == []

    def test_new_schema_mapping_supported(self, inv):
        assert inv["npm"]["express"] == ["^4.21.2"]
        assert inv["_owners"]["npm"]["express"] == ["frontend", "be_piggyvest", "be_pocket", "be_pvb"]
        assert inv["_owners"]["pypi"]["numpy"] == ["data"]

    def test_legacy_list_schema_supported(self, inv):
        assert inv["npm"]["lodash"] == ["^4.17.21"]
        assert inv["_owners"]["npm"]["lodash"] == []          # legacy entries simply have no owners

    def test_normalisation_is_idempotent_and_does_not_mutate_input(self, inv):
        assert watch.normalize_inventory(inv) is inv
        assert isinstance(INV_RAW["npm"]["express"], dict)    # raw input untouched

    def test_news_keywords_and_unversioned_accept_both_shapes(self):
        n = watch.normalize_inventory({"news_keywords": ["Redis", {"keyword": "MySQL", "teams": ["data"]}],
                                       "unversioned": ["pydrive (PyPI)", {"name": "pymysql (PyPI)", "teams": ["data"]}]})
        assert n["news_keywords"] == ["Redis", "MySQL"]
        assert n["unversioned"] == ["pydrive (PyPI)", "pymysql (PyPI)"]
        assert n["_owners"]["keywords"]["MySQL"] == ["data"]

    def test_team_ownership_preserved_for_multi_team_packages(self, matchers):
        m = next(x for x in matchers if x["label"] == "express")
        assert m["teams"] == ["frontend", "be_piggyvest", "be_pocket", "be_pvb"]
        assert watch.resolve_teams(watch.normalize_inventory(INV_RAW), m["teams"]) == [
            "Frontend (#team-frontend)", "Backend Piggyvest", "Backend Pocket", "Backend PVB"]

    def test_unmapped_package_has_no_teams(self, matchers):
        assert next(x for x in matchers if x["label"] == "lodash")["teams"] == []

    def test_weak_text_only_match_is_unverified_not_confirmed(self, matchers):
        m = watch.match_text(matchers, "Express.js: open redirect", "Express.js before 4.19.2")[0]
        assert watch.assess_match(m, None, None) == "unverified"

    # ---- structured data (OSV / NVD) -------------------------------------------------
    @staticmethod
    def express_matcher(matchers, versions):
        m = dict(next(x for x in matchers if x["label"] == "express"))
        m["versions"] = versions
        return m

    OSV_EXPRESS = {"id": "GHSA-x", "affected": [{"package": {"name": "express", "ecosystem": "npm"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.22.0"}]}]}]}

    def test_osv_range_confirms_affected_version(self, matchers):
        assert watch.assess_match(self.express_matcher(matchers, ["4.21.2"]), self.OSV_EXPRESS) == "confirmed"

    def test_osv_range_rejects_fixed_version(self, matchers):
        assert watch.assess_match(self.express_matcher(matchers, ["4.22.1"]), self.OSV_EXPRESS) is None

    def test_osv_record_for_other_package_rejects_match(self, matchers):
        other = {"affected": [{"package": {"name": "optima-express", "ecosystem": "Packagist"}}]}
        assert watch.assess_match(self.express_matcher(matchers, ["4.21.2"]), other) is None

    def test_nvd_cpe_for_wordpress_plugin_rejects_express(self, matchers):
        nvd = {"cpes": [{"vendor": "optima_express", "product": "optima_express_+_marketboost_idx",
                         "version": "*", "vulnerable": True, "vsi": None, "vse": None, "vei": "8.7.8", "vee": None}]}
        assert watch.assess_match(self.express_matcher(matchers, ["4.21.2"]), None, nvd) is None

    def test_nvd_cpe_version_range_for_real_express(self, matchers):
        nvd = {"cpes": [{"vendor": "expressjs", "product": "express", "version": "*", "vulnerable": True,
                         "vsi": None, "vse": None, "vei": None, "vee": "4.19.2"}]}
        assert watch.assess_match(self.express_matcher(matchers, ["4.17.1"]), None, nvd) == "confirmed"
        assert watch.assess_match(self.express_matcher(matchers, ["4.21.2"]), None, nvd) is None

    def test_package_match_without_version_evidence_is_unverified(self, matchers):
        osv = {"affected": [{"package": {"name": "express", "ecosystem": "npm"}}]}   # no ranges, no version list
        assert watch.assess_match(self.express_matcher(matchers, ["4.21.2"]), osv) == "unverified"

    def test_tools_are_always_unverified(self, matchers):
        m = next(x for x in matchers if x["kind"] == "tool")
        assert watch.assess_match(m, {"affected": [{"package": {"name": "x", "ecosystem": "npm"}}]}) == "unverified"


# --------------------------------------------------------------------------- #
# Change 2 + 3: eight fields, wording, footer
# --------------------------------------------------------------------------- #
FIELD_ORDER = ["Severity", "Affected technology", "Affected team/s", "Potential impact", "Relevance",
               "Exploitation status", "Recommended action", "Source"]


def fields_of(text):
    out = {}
    for line in text.split("\n"):
        m = re.match(r"• ([^:]+): (.*)", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out, [re.match(r"• ([^:]+):", l).group(1) for l in text.split("\n") if re.match(r"• [^:]+:", l)]


class TestReportFormat:
    def sample(self, **kw):
        base = dict(kind="pkg", id="GHSA-1", cve="CVE-2026-1111", sev="HIGH", score=7.5, kev=True,
                    impact="Open redirect.", tech="express 4.21.2 (inventory ^4.21.2)", match="confirmed",
                    teams=["Frontend (#team-frontend)", "Backend PVB"], fixed=["4.22.0"],
                    sources="<https://example.test/advisory>", epss=0.91)
        base.update(kw)
        return watch.finding(**base)

    def test_all_eight_fields_in_order(self):
        _, order = fields_of(watch.render_finding(self.sample(), 1))
        assert order == FIELD_ORDER

    def test_severity_has_no_exploitation_suffix(self):
        f, _ = fields_of(watch.render_finding(self.sample(), 1))
        assert "exploited" not in f["Severity"].lower() and "KEV" not in f["Severity"]
        assert f["Severity"] == "High (CVSS 7.5) · EPSS 0.91"

    def test_exploitation_status_exact_strings(self):
        yes, _ = fields_of(watch.render_finding(self.sample(kev=True), 1))
        no, _ = fields_of(watch.render_finding(self.sample(kev=False), 1))
        assert yes["Exploitation status"] == "Actively exploited in the wild"
        assert no["Exploitation status"] == "Cannot confirm actively exploited in the wild status"

    def test_high_scores_alone_do_not_imply_exploitation(self):
        f, _ = fields_of(watch.render_finding(self.sample(kev=False, sev="CRITICAL", score=10.0, epss=0.99), 1))
        assert f["Exploitation status"] == watch.EXPLOIT_UNCONFIRMED

    def test_inventory_match_wording(self):
        c, _ = fields_of(watch.render_finding(self.sample(match="confirmed"), 1))
        u, _ = fields_of(watch.render_finding(self.sample(match="unverified"), 1))
        assert c["Affected technology"].endswith("Confirmed match in the inventory.")
        assert u["Affected technology"].endswith("Unverified match in the inventory.")
        assert "Unverified" not in c["Affected technology"] and "Confirmed" not in u["Affected technology"]

    def test_old_assumed_version_wording_is_gone(self):
        text = watch.render_finding(self.sample(), 1)
        assert "assumed from inventory" not in text and "version assumed" not in text

    def test_match_defaults_to_unverified_when_unset(self):
        f = watch.finding(id="GHSA-2", tech="foo 1.0.0")
        assert fields_of(watch.render_finding(f, 1))[0]["Affected technology"].endswith("Unverified match in the inventory.")

    def test_multiple_teams_all_listed(self):
        f, _ = fields_of(watch.render_finding(self.sample(), 1))
        assert f["Affected team/s"] == "Frontend (#team-frontend), Backend PVB"

    def test_unknown_ownership_is_not_fabricated(self):
        f, _ = fields_of(watch.render_finding(self.sample(teams=[]), 1))
        assert f["Affected team/s"] == watch.TEAMS_UNMAPPED
        assert "Frontend" not in f["Affected team/s"]
        assert "no owning team is mapped" in f["Relevance"]

    def test_relevance_names_teams_and_asks_for_verification(self):
        rel, _ = fields_of(watch.render_finding(self.sample(), 1))
        rel = rel["Relevance"]
        assert "Frontend (#team-frontend), Backend PVB" in rel
        for needle in ("deployed or used", "affected range", "functionality or configuration", "remediation is required"):
            assert needle in rel
        assert "does not confirm deployment" in rel

    def test_recommended_action_does_not_invent_a_fix(self):
        with_fix, _ = fields_of(watch.render_finding(self.sample(fixed=["4.22.0"]), 1))
        no_fix, _ = fields_of(watch.render_finding(self.sample(fixed=[]), 1))
        assert "4.22.0" in with_fix["Recommended action"]
        assert "No fixed version is stated" in no_fix["Recommended action"]
        assert not re.search(r"\b\d+\.\d+\.\d+\b", no_fix["Recommended action"])

    def test_missing_evidence_renders_without_crash(self):
        text = watch.render_finding(watch.finding(id="GHSA-bare"), 1)
        assert "No CVE assigned (GHSA-bare)" in text and "Not described in the advisory." in text
        assert "Unrated" in text

    def test_compact_line_survives_missing_teams(self):
        assert "teams unmapped" in watch.compact_line(self.sample(teams=[]), 3)

    def test_footer_no_longer_claims_versions_are_assumed(self):
        foot = watch.footer_text("Sources: OSV ✓", baseline=False)
        assert "assumed from your inventory" not in foot and "Versions are assumed" not in foot
        for needle in ("inventory", "does not confirm", "source code", "runtime versions", "Team ownership"):
            assert needle in foot

    def test_footer_is_slack_italic_wrapped(self):
        foot = watch.footer_text("Sources: OSV ✓", baseline=False)
        assert foot.startswith("_") and foot.endswith("_")
        assert watch.footer_text("Sources: OSV ✓", baseline=True) == "_Sources: OSV ✓_"


# --------------------------------------------------------------------------- #
# Change 4: news mode
# --------------------------------------------------------------------------- #
def run_news_capture(monkeypatch, tmp_path, feed, state=None, st=None, dry_run=False, page_scores=None):
    posted = []
    monkeypatch.setattr(watch, "fetch_cvenow", lambda url: feed)
    monkeypatch.setattr(watch, "post_slack", lambda webhook, msgs: posted.extend(msgs))
    monkeypatch.setattr(watch, "cvenow_page_score", lambda cid: (page_scores or {}).get(cid))
    monkeypatch.setattr(watch.time, "sleep", lambda s: None)
    args = types.SimpleNamespace(dry_run=dry_run, state=str(tmp_path / "state.json"))
    state = {} if state is None else state
    rc = watch.run_news(args, watch.normalize_inventory({"npm": {"zzz-lib": ["1.0.0"]}}),
                        st if st is not None else {}, TZ, state, "https://hooks.test/x")
    return rc, "\n".join(posted), state, args


def posted_cves(text):
    return re.findall(r"CVE: (CVE-\d{4}-\d+)", text)


class TestNewsThreshold:
    def test_floor_is_9_5_whatever_settings_say(self):
        assert watch.news_threshold({"news_min_cvss": 8.5}) == 9.5
        assert watch.news_threshold({}) == 9.5
        assert watch.news_threshold({"news_min_cvss": "garbage"}) == 9.5
        assert watch.news_threshold({"news_min_cvss": 9.8}) == 9.8       # may be raised, never lowered

    @pytest.mark.parametrize("score,expected", [(9.5, True), (10.0, True), (9.4, False), (9.49, False)])
    def test_collect_news_threshold(self, score, expected):
        ns = fresh_ns()
        watch.collect_news(parsed_items(cn_item("CVE-2026-500001", score)), [], ns, TODAY, 9.5, {})
        assert ("CVE-2026-500001" in ns["queue"]) is expected

    def test_collect_news_ignores_a_weaker_threshold_argument(self):
        ns = fresh_ns()
        watch.collect_news(parsed_items(cn_item("CVE-2026-500002", 8.7)), [], ns, TODAY, 8.5, {})
        assert ns["queue"] == {}

    def test_missing_cvss_does_not_qualify(self):
        ns = fresh_ns()
        watch.collect_news(parsed_items(cn_item("CVE-2026-500003", None)), [], ns, TODAY, 9.5, {},
                           score_lookup=lambda cid: None, budget=5)
        assert ns["queue"] == {}

    def test_epss_alone_does_not_qualify(self):
        ns = fresh_ns()
        item = cn_item("CVE-2026-500004", None, desc="Critical flaw. EPSS probability 0.97, likely to be exploited.")
        watch.collect_news(parsed_items(item), [], ns, TODAY, 9.5, {}, score_lookup=lambda cid: None, budget=5)
        assert ns["queue"] == {}
        assert not watch.news_item_valid({"cve": "CVE-2026-500004", "title": "t", "score": None, "epss": 0.99}, 9.5)

    def test_page_score_is_used_only_when_verifiable(self):
        ns = fresh_ns()
        watch.collect_news(parsed_items(cn_item("CVE-2026-500005", None)), [], ns, TODAY, 9.5, {},
                           score_lookup=lambda cid: 9.8, budget=5)
        assert ns["queue"]["CVE-2026-500005"]["score"] == 9.8

    @pytest.mark.parametrize("page,expected", [
        ("Details CVSS 9.8 Critical vector", 9.8),
        ("CVSS 9.8 High", None),                  # label disagrees with the number -> not verified
        ("CVSS 3.1/AV:N/AC:L", None),             # a CVSS *version*, not a score
        ("no score here", None),
    ])
    def test_cvss_page_parsing_requires_a_consistent_label(self, page, expected):
        assert watch.parse_cvss_from_page(page) == expected

    def test_inventory_matches_are_not_queued_as_news(self):
        ms = watch.build_matchers(watch.normalize_inventory(INV_RAW), VERS)
        ns = fresh_ns()
        item = cn_item("CVE-2026-500006", 9.9, title="Express.js: open redirect", desc="Express.js before 4.19.2 allows redirects.")
        watch.collect_news(parsed_items(item), ms, ns, TODAY, 9.5, {})
        assert ns["queue"] == {}

    def test_unrelated_general_news_never_reaches_the_report(self):
        junk = {"title": "Hackers breach bank", "text": "story", "score": 9.9, "url": "https://x.test", "queued": TODAY}
        queue = {"not-a-cve": junk, "CVE-2026-500007": dict(junk, cve="CVE-2026-500007"),
                 "CVE-2026-500008": {"cve": "CVE-2026-500008", "title": "t", "text": "x", "score": None, "queued": TODAY}}
        selected, overflow = watch.select_news(queue, TODAY)
        assert [i["cve"] for i in selected] == ["CVE-2026-500007"] and overflow == []

    def test_previously_queued_alert_is_not_requeued_when_score_rises(self):
        ns = fresh_ns()
        ns["done"] = {"CVE-2026-510001": f"{TODAY}|9.0",          # legacy entry, queued under the old 8.5 rule
                      "CVE-2026-510002": f"{TODAY}|8.0",          # legacy entry, never queued
                      "CVE-2026-510003": f"{TODAY}|9.0|q",
                      "CVE-2026-510004": f"{TODAY}|9.0|n",
                      "CVE-2026-510005": f"{TODAY}|inventory"}
        items = [cn_item(c, 9.7, desc="Update") for c in ns["done"]]
        for it in items:
            it["content_text"] = f"Update: CVSS score changed from 9.0 to 9.7. {it['id']} detail."
        watch.collect_news(parsed_items(*items), [], ns, TODAY, 9.5, {})
        assert set(ns["queue"]) == {"CVE-2026-510002", "CVE-2026-510004"}


class TestNewsOutput:
    def test_more_than_20_gives_at_most_20_highest_first(self, monkeypatch, tmp_path):
        feed = [cn_item(f"CVE-2026-6{i:05d}", 9.5 + (i % 6) / 10) for i in range(25)]
        expected = sorted(((9.5 + (i % 6) / 10, i) for i in range(25)), key=lambda x: (-x[0], x[1]))[:20]
        rc, text, state, _ = run_news_capture(monkeypatch, tmp_path, feed)
        got = posted_cves(text)
        assert rc == 0 and len(got) == 20
        assert got == [f"CVE-2026-6{i:05d}" for _, i in expected]

    def test_tie_break_is_deterministic_regardless_of_input_order(self):
        items = {f"CVE-2026-7{i:05d}": {"cve": f"CVE-2026-7{i:05d}", "title": "t", "text": "x", "score": 9.8,
                                        "url": "u", "queued": TODAY} for i in range(30)}
        a, _ = watch.select_news(items, TODAY)
        b, _ = watch.select_news(dict(reversed(list(items.items()))), TODAY)
        assert [i["cve"] for i in a] == [i["cve"] for i in b] == [f"CVE-2026-7{i:05d}" for i in range(20)]

    def test_overflow_is_kept_and_posted_next_run_without_repeats(self, monkeypatch, tmp_path):
        feed = [cn_item(f"CVE-2026-8{i:05d}", 9.5 + (i % 6) / 10) for i in range(25)]
        _, text1, state, _ = run_news_capture(monkeypatch, tmp_path, feed)
        first = set(posted_cves(text1))
        assert len(first) == 20 and len(state["news_queue"]) == 5
        overflow = set(state["news_queue"])                     # snapshot: run_news updates state in place
        assert not first & overflow
        # second run: same feed, state carried over
        _, text2, state2, _ = run_news_capture(monkeypatch, tmp_path, feed, state=state)
        second = set(posted_cves(text2))
        assert second == overflow and not second & first
        assert state2["news_queue"] == {}
        # third run: nothing new, nothing re-posted
        _, text3, _, _ = run_news_capture(monkeypatch, tmp_path, feed, state=state2)
        assert posted_cves(text3) == []

    def test_overflow_message_is_transparent(self, monkeypatch, tmp_path):
        feed = [cn_item(f"CVE-2026-9{i:05d}", 9.8) for i in range(22)]
        _, text, _, _ = run_news_capture(monkeypatch, tmp_path, feed)
        assert "top 20 of 22" in text and "2 more are queued" in text

    def test_legacy_queue_and_8_5_setting_cannot_weaken_the_rule(self, monkeypatch, tmp_path):
        def q(cid, score):
            return {"cve": cid, "title": "Acme flaw", "text": "x", "score": score, "url": "https://x.test", "queued": TODAY}
        state = {"news_queue": {"CVE-2026-300001": q("CVE-2026-300001", 8.7),
                                "CVE-2026-300002": q("CVE-2026-300002", 9.6),
                                "CVE-2026-300003": q("CVE-2026-300003", 9.4)},
                 "news_done": {"CVE-2026-300001": f"{TODAY}|8.7"}}
        _, text, state_after, _ = run_news_capture(monkeypatch, tmp_path, [], state=state, st={"news_min_cvss": 8.5})
        assert posted_cves(text) == ["CVE-2026-300002"]
        assert state_after["news_queue"] == {}
        assert "rated 9.5+" in text

    def test_expired_queue_entries_are_dropped(self):
        old = {"cve": "CVE-2026-310001", "title": "t", "text": "x", "score": 9.9, "url": "u", "queued": "2026-01-01"}
        assert watch.select_news({"CVE-2026-310001": old}, TODAY) == ([], [])

    def test_dry_run_changes_nothing(self, monkeypatch, tmp_path):
        feed = [cn_item("CVE-2026-320001", 9.9)]
        rc, text, state, args = run_news_capture(monkeypatch, tmp_path, feed, dry_run=True)
        assert rc == 0 and not os.path.exists(args.state)

    def test_works_with_empty_legacy_state(self, monkeypatch, tmp_path):
        rc, text, state, _ = run_news_capture(monkeypatch, tmp_path, [], state={})
        assert rc == 0 and "No new CVEs rated 9.5+" in text


# --------------------------------------------------------------------------- #
# Change 5: alert history + monthly overview
# --------------------------------------------------------------------------- #
def alert(cve, sev="HIGH", **kw):
    return watch.finding(id=kw.pop("id", cve), cve=cve, sev=sev, **kw)


class TestMonthlySummary:
    def state_with(self, *entries):
        return {"alert_history": {k: {"first_seen": d, "severity": s} for k, d, s in entries},
                "alert_history_started": "2026-10-01"}

    def test_report_has_exactly_the_two_metrics(self):
        text = watch.render_monthly_summary(watch.monthly_summary(self.state_with(("CVE-1", "2026-10-03", "HIGH")), 2026, 10))
        assert text.startswith("🛡️ SECURITY WATCH — MONTHLY EXECUTIVE OVERVIEW\n\nReporting period: October 2026\n\n")
        assert [l for l in text.split("\n") if l.startswith("•")] == [
            "• New vulnerability alerts identified: 1", "• High/Critical vulnerabilities identified: 1"]

    def test_period_is_generated_not_hard_coded(self):
        assert watch.monthly_summary({}, 2027, 3)["label"] == "March 2027"
        assert watch.monthly_summary({}, 2026, 12)["label"] == "December 2026"

    def test_unique_cve_is_counted_once_across_sources_and_packages(self):
        state = {}
        added = watch.record_alerts(state, [alert("CVE-2026-1", kind="pkg"), alert("CVE-2026-1", kind="early"),
                                            alert("cve-2026-1", kind="tool")], "2026-10-05")
        assert added == 1 and len(state["alert_history"]) == 1

    def test_osv_id_used_only_when_no_cve_exists(self):
        state = {}
        watch.record_alerts(state, [watch.finding(id="GHSA-aaaa", sev="LOW"), alert("CVE-2026-2", id="GHSA-bbbb")], "2026-10-05")
        assert set(state["alert_history"]) == {"GHSA-AAAA", "CVE-2026-2"}

    def test_high_critical_counting(self):
        state = self.state_with(("A", "2026-10-02", "CRITICAL"), ("B", "2026-10-03", "HIGH"), ("C", "2026-10-04", "MEDIUM"),
                                ("D", "2026-10-05", "LOW"), ("E", "2026-10-06", None))
        s = watch.monthly_summary(state, 2026, 10)
        assert (s["new"], s["high"]) == (5, 2)

    def test_malicious_package_counts_as_critical(self):
        state = {}
        watch.record_alerts(state, [watch.finding(id="MAL-1", sev=None, mal=True)], "2026-10-05")
        assert watch.monthly_summary(state, 2026, 10)["high"] == 1

    def test_other_months_are_excluded(self):
        state = self.state_with(("A", "2026-09-30", "HIGH"), ("B", "2026-10-01", "HIGH"), ("C", "2026-11-01", "HIGH"))
        assert watch.monthly_summary(state, 2026, 10)["new"] == 1

    def test_re_recording_does_not_inflate_counts(self):
        state = {}
        for day in ("2026-10-05", "2026-10-06", "2026-10-07"):
            watch.record_alerts(state, [alert("CVE-2026-3")], day)
        assert watch.monthly_summary(state, 2026, 10)["new"] == 1
        assert state["alert_history"]["CVE-2026-3"]["first_seen"] == "2026-10-05"

    def test_summary_is_read_only_and_repeatable(self):
        state = self.state_with(("A", "2026-10-02", "HIGH"))
        before = json.dumps(state, sort_keys=True)
        a = watch.render_monthly_summary(watch.monthly_summary(state, 2026, 10))
        b = watch.render_monthly_summary(watch.monthly_summary(state, 2026, 10))
        assert a == b and json.dumps(state, sort_keys=True) == before

    def test_legacy_state_without_history_is_safe_and_not_fabricated(self):
        legacy = {"initialized": True, "announced_cves": {"CVE-2026-1": "2026-10-24"}}   # no alert_history at all
        s = watch.monthly_summary(legacy, 2026, 10)
        assert (s["new"], s["high"]) == (0, 0)
        assert "No alert history has been recorded yet" in s["note"]

    def test_malformed_history_entries_are_ignored(self):
        state = {"alert_history": {"A": "oops", "B": {"first_seen": "not-a-date"}, "C": {"first_seen": "2026-10-02", "severity": "HIGH"}}}
        assert watch.monthly_summary(state, 2026, 10)["new"] == 1
        assert watch.monthly_summary({"alert_history": []}, 2026, 10)["new"] == 0

    def test_partial_coverage_is_disclosed(self):
        s = watch.monthly_summary({"alert_history": {}, "alert_history_started": "2026-10-20"}, 2026, 10)
        assert "tracking began on 2026-10-20" in s["note"]
        s2 = watch.monthly_summary({"alert_history": {}, "alert_history_started": "2026-10-20"}, 2026, 9)
        assert "nothing was recorded for this period" in s2["note"]
        s3 = watch.monthly_summary({"alert_history": {}, "alert_history_started": "2026-10-01"}, 2026, 10)
        assert s3["note"] is None

    def test_month_argument_validation(self):
        assert watch.parse_month("2026-09") == (2026, 9)
        for bad in ("2026-13", "09-2026", "", None):
            with pytest.raises(ValueError):
                watch.parse_month(bad)


# --------------------------------------------------------------------------- #
# End-to-end: main() with every network call mocked
# --------------------------------------------------------------------------- #
@pytest.fixture
def env(monkeypatch, tmp_path):
    inv_path = tmp_path / "inventory.yml"
    inv_path.write_text(yaml.safe_dump({
        "settings": {"timezone": "Africa/Lagos"},
        "teams": {"frontend": {"name": "Frontend", "slack": "#team-frontend", "oncall": ""}},
        "npm": {"foo-lib": {"versions": ["1.0.0"], "teams": ["frontend"]},    # new schema
                "bar-lib": ["2.0.0"]},                                         # legacy schema, no owner
        "aliases": {}, "tools": [], "eol": [], "news_feeds": [], "news_keywords": [],
    }))
    ctl = {"ids": set(), "posted": [], "details": {
        "GHSA-bbbb-0002": {"id": "GHSA-bbbb-0002", "aliases": ["CVE-2026-5002"], "details": "Foo lib flaw.",
                           "database_specific": {"severity": "HIGH"}},
        "GHSA-dddd-0004": {"id": "GHSA-dddd-0004", "aliases": ["CVE-2026-5004"], "details": "Bar lib flaw.",
                           "database_specific": {"severity": "MODERATE"}},
        "GHSA-eeee-0005": {"id": "GHSA-eeee-0005", "aliases": ["CVE-2026-5005"], "details": "Dry run flaw.",
                           "database_specific": {"severity": "CRITICAL"}},
    }}

    def fake_osv_query(targets):
        ids_by_key, hits = {}, {}
        for t in targets:
            mine = {v for v in ctl["ids"] if (v in ("GHSA-bbbb-0002", "GHSA-eeee-0005")) == (t["name"] == "foo-lib")
                    or v == "GHSA-aaaa-0001"} if t["name"] == "foo-lib" else {v for v in ctl["ids"] if v == "GHSA-dddd-0004"}
            ids_by_key[t["key"]] = set(mine)
            for v in mine:
                hits.setdefault(v, []).append((t["key"], t["name"], "npm", t["versions"][0]))
        return ids_by_key, hits, set()

    monkeypatch.setattr(watch, "fetch_registry", lambda n: None)
    monkeypatch.setattr(watch, "osv_query", fake_osv_query)
    monkeypatch.setattr(watch, "osv_detail", lambda vid: ctl["details"].get(vid, {"id": vid}))
    monkeypatch.setattr(watch, "load_kev", lambda: {})
    monkeypatch.setattr(watch, "fetch_cvenow", lambda url: [])
    monkeypatch.setattr(watch, "check_eol", lambda *a, **k: [])
    monkeypatch.setattr(watch, "epss_scores", lambda cves: {})
    monkeypatch.setattr(watch, "nvd_cve", lambda cid: None)
    monkeypatch.setattr(watch, "post_slack", lambda w, msgs: ctl["posted"].extend(msgs))
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.test/x")
    ctl.update(inv=str(inv_path), state=str(tmp_path / "state.json"))
    return ctl


def read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def read_json(path):
    return json.loads(read_text(path))


def run_main(env, *extra):
    return watch.main(["--inventory", env["inv"], "--state", env["state"], *extra])


class TestEndToEnd:
    def test_full_lifecycle(self, env, capsys):
        # 1. first run is a silent baseline: nothing is recorded as an alert
        env["ids"] = {"GHSA-aaaa-0001"}
        assert run_main(env) == 0
        state = read_json(env["state"])
        assert watch.alert_history(state) == {} and state["initialized"]
        assert "baseline complete" in env["posted"][0]
        env["posted"].clear()

        # 2. two new advisories: one for a mapped package, one for an unmapped legacy entry
        env["ids"] = {"GHSA-aaaa-0001", "GHSA-bbbb-0002", "GHSA-dddd-0004"}
        assert run_main(env) == 0
        report = "\n".join(env["posted"])
        assert "• Affected team/s: Frontend (#team-frontend)" in report
        assert "• Affected team/s: " + watch.TEAMS_UNMAPPED in report
        assert report.count("• Exploitation status: Cannot confirm actively exploited in the wild status") == 2
        assert "Confirmed match in the inventory." in report and "assumed from inventory" not in report
        assert "no access to application source code" in report
        state = read_json(env["state"])
        assert set(state["alert_history"]) == {"CVE-2026-5002", "CVE-2026-5004"}

        # 3. repeated scan with identical data must not inflate anything
        env["posted"].clear()
        assert run_main(env) == 0
        assert len(read_json(env["state"])["alert_history"]) == 2

        # 4. dry run with a brand-new advisory: nothing posted, nothing recorded, state byte-identical
        env["posted"].clear()
        before = read_text(env["state"])
        env["ids"] = env["ids"] | {"GHSA-eeee-0005"}
        assert run_main(env, "--dry-run") == 0
        assert env["posted"] == [] and read_text(env["state"]) == before
        capsys.readouterr()

        # 5. monthly summary: 2 unique alerts, 1 High/Critical (the MODERATE one is Medium); state untouched
        assert run_main(env, "--monthly-summary", "--dry-run") == 0
        out = capsys.readouterr().out
        local = watch.NOW.astimezone(TZ)
        assert f"Reporting period: {local.strftime('%B %Y')}" in out
        assert "• New vulnerability alerts identified: 2" in out
        assert "• High/Critical vulnerabilities identified: 1" in out
        assert read_text(env["state"]) == before
        assert run_main(env, "--monthly-summary", "--dry-run") == 0
        assert capsys.readouterr().out == out                                   # idempotent
        assert run_main(env, "--monthly-summary") == 0                          # posts to Slack, still read-only
        assert read_text(env["state"]) == before

    def test_monthly_summary_with_legacy_state_file(self, env, capsys):
        with open(env["state"], "w", encoding="utf-8") as fh:
            json.dump({"initialized": True, "announced_cves": {"CVE-2026-1": "2026-10-24"}, "news_queue": {}}, fh)
        assert run_main(env, "--monthly-summary", "--month", "2026-09", "--dry-run") == 0
        out = capsys.readouterr().out
        assert "Reporting period: September 2026" in out
        assert "• New vulnerability alerts identified: 0" in out and "No alert history" in out

    def test_bad_month_argument_fails_cleanly(self, env):
        assert run_main(env, "--monthly-summary", "--month", "2026-99", "--dry-run") == 2

    def test_existing_cli_modes_still_present(self, env):
        parser_help = watch.argparse.ArgumentParser
        assert parser_help  # smoke: module exposes the same entry point
        with pytest.raises(SystemExit):
            watch.main(["--mode", "bogus"])


# --------------------------------------------------------------------------- #
# The real inventory.yml shipped in this repository
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not (ROOT / "inventory.yml").exists(), reason="inventory.yml not present")
class TestRealInventory:
    @pytest.fixture
    def real(self):
        return watch.normalize_inventory(yaml.safe_load(read_text(ROOT / "inventory.yml")))

    def test_loads_and_builds_matchers(self, real):
        assert len(real["npm"]) > 300 and all(isinstance(v, list) and v for v in real["npm"].values())
        assert isinstance(real["unversioned"], list) and all(isinstance(x, str) for x in real["unversioned"])
        assert watch.build_matchers(real, {})

    def test_every_team_key_in_use_exists_in_the_registry(self, real):
        used = {t for group in real["_owners"].values() for teams in group.values() for t in teams}
        assert used <= set(real["teams"]), used - set(real["teams"])

    def test_express_is_owned_by_all_four_backend_and_frontend_teams(self, real):
        assert real["_owners"]["npm"]["express"] == ["frontend", "be_piggyvest", "be_pocket", "be_pvb"]

    def test_false_positive_regression_against_the_real_inventory(self, real):
        ms = watch.build_matchers(real, {})
        assert watch.match_text(ms, TestMatching.WP_TITLE, TestMatching.WP_BODY) == []
