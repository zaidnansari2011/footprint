"""Offline tests for the logic that decides what Footprint says. No network needed."""

import pytest

from app import lookalike, net, scan, scoring, usernames


# ---------------------------------------------------------------- input parsing

@pytest.mark.parametrize("raw, target", [
    ("tesla.com", "tesla.com"),
    ("https://www.Tesla.com/models?x=1", "tesla.com"),
    ("shop.example.co.uk", "example.co.uk"),
    ("xavier.ac.in", "xavier.ac.in"),
])
def test_domains_are_reduced_to_the_registered_name(raw, target):
    t = scan.parse_target(raw)
    assert t["mode"] == "domain" and t["target"] == target


def test_a_bare_word_is_a_username():
    t = scan.parse_target("  Torvalds ")
    assert t == {"mode": "handle", "target": "torvalds", "brand": "torvalds"}


@pytest.mark.parametrize("raw", ["", "x", "localhost.invalidtld123", "...", "a..b"])
def test_rubbish_is_rejected(raw):
    assert scan.parse_target(raw) is None


# ---------------------------------------------------------------- SSRF guard

@pytest.mark.parametrize("ip, public", [
    ("8.8.8.8", True),
    ("127.0.0.1", False),
    ("10.1.2.3", False),
    ("192.168.0.1", False),
    ("169.254.169.254", False),  # cloud metadata endpoint
    ("::1", False),
    ("not-an-ip", False),
])
def test_only_public_addresses_are_fetchable(ip, public):
    assert net._is_public(ip) is public


@pytest.mark.asyncio
async def test_safe_fetch_refuses_localhost():
    async with net.make_client() as c:
        assert await net.safe_fetch(c, "http://localhost:8077/") is None
        assert await net.safe_fetch(c, "file:///etc/passwd") is None


# ---------------------------------------------------------------- lookalikes

def test_permutations_cover_every_trick():
    rows = lookalike.permutations("paypal", "com")
    names = {r["display"] for r in rows}
    kinds = {r["kind"] for r in rows}
    assert {"paypal.net", "paypal-login.com", "paypa1.com", "paypl.com", "papyal.com", "pay-pal.com"} <= names
    assert kinds == set(lookalike.KIND_LABEL)
    assert "paypal.com" not in names
    idn = next(r for r in rows if r["kind"] == "idn")
    assert idn["domain"].startswith("xn--") and idn["display"] != idn["domain"]


def _cand(**kw):
    base = dict(brand_owned=False, mx=False, age_days=None, clone_like=False, login_form=False, kind="omission", parked=False)
    base.update(kw)
    return base


def test_mail_records_alone_do_not_make_a_domain_suspicious():
    c = _cand(mx=True)
    lookalike.score_and_verdict(c)
    assert c["verdict"] == "Registered"


def test_new_domain_with_login_page_and_mail_is_phishing():
    c = _cand(mx=True, age_days=12, login_form=True, clone_like=True)
    lookalike.score_and_verdict(c)
    assert c["verdict"] == "Likely phishing" and c["score"] >= 60
    assert "Asks for a password" in c["reasons"]


def test_parked_domains_are_capped_and_labelled():
    c = _cand(mx=True, age_days=5, clone_like=True, parked=True)
    lookalike.score_and_verdict(c)
    assert c["verdict"] == "Parked" and c["score"] <= 30


def test_brand_owned_scores_zero():
    c = _cand(brand_owned=True, mx=True, login_form=True)
    lookalike.score_and_verdict(c)
    assert c == {**c, "score": 0, "verdict": "Brand-owned"}


# ---------------------------------------------------------------- usernames

def test_handle_variants_look_like_support_accounts():
    v = usernames.handle_variants("tesla")
    assert "teslasupport" in v and "tesla_support" in v and "teslaofficial" in v
    assert "tes1a" in v
    assert "tesla" not in v


def test_site_list_is_calibrated_and_clean():
    sites = usernames.load_sites()
    assert len(sites) > 150
    assert "GitHub" in sites and "1337x" not in sites
    # every site must put the handle somewhere: the profile URL, a probe URL, or a POST body
    assert all("{}" in s["url"] + s.get("urlProbe", "") + str(s.get("request_payload", "")) for s in sites.values())


# ---------------------------------------------------------------- scoring

def test_score_adds_up_and_bands():
    result = {
        "mode": "domain",
        "dns": {"A": ["1.1.1.1"], "MX": ["mx"], "TXT": [], "CAA": [], "SPF": None, "DMARC": None, "exists": True},
        "whois": None, "hosts": {}, "web": None, "history": None,
        "subdomains": {"interesting": [], "resolved": {}},
        "lookalikes": {"registered": []},
        "accounts": {"impersonators": []},
    }
    s = scoring.score(result)
    titles = [f["title"] for f in s["findings"]]
    assert titles[:2] == ["No SPF record", "No DMARC policy"]  # highs first
    assert s["score"] == 12 + 12 + 2 and s["band"] == "Moderate"
