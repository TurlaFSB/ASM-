import base64

import dns.resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.scanner import emailsec as es


class FakeResolver:
    lifetime = 5

    def __init__(self, txt=None, mx=None):
        self.txt, self.mx = txt or {}, mx

    def resolve(self, name, rtype):
        if rtype == "MX":
            if self.mx is None:
                raise dns.resolver.NoAnswer()
            return [type("M", (), {"exchange": e})() for e in self.mx]
        recs = self.txt.get(name)
        if recs is None:
            raise dns.resolver.NXDOMAIN()
        return [type("T", (), {"strings": [r.encode()]})() for r in recs]


def ids(findings):
    return {f["template_id"] for f in findings}


def test_domain_without_any_mail_dns_scores_missing_records_as_medium():
    out = es.run_email_security("a.com", FakeResolver(mx=["mail.a.com."]))
    f = {x["template_id"]: x for x in out["findings"]}
    assert f["email-spf-missing"]["severity"] == "medium" and f["email-dmarc-missing"]["severity"] == "medium"
    assert "email-mta-sts-missing" in f and all("email-security" in x["tags"] for x in out["findings"])


def test_domain_with_no_mx_is_low_and_null_mx_counts_as_no_mail():
    out = es.run_email_security("a.com", FakeResolver())
    assert {x["severity"] for x in out["findings"]} == {"low"} and "email-mta-sts-missing" not in ids(out["findings"])
    null = es.run_email_security("a.com", FakeResolver(mx=["."]))
    assert null["has_mx"] is False


def test_spf_qualifiers():
    def spf(rec):
        return ids(es.check_spf("a.com", True, FakeResolver(txt={"a.com": [rec]})))
    assert "email-spf-allow-all" not in spf("v=spf1 -all")
    assert "email-spf-allow-all" in spf("v=spf1 +all")
    assert "email-spf-allow-all" in spf("v=spf1 all")
    assert "email-spf-neutral" in spf("v=spf1 ip4:1.2.3.4 ?all")
    assert "email-spf-softfail" in spf("v=spf1 ip4:1.2.3.4 ~all")
    assert "email-spf-no-all" in spf("v=spf1 ip4:1.2.3.4")
    assert "email-spf-ptr" in spf("v=spf1 ptr -all")
    assert spf("v=spf1 ip4:1.2.3.4 -all") == set()
    assert "email-spf-no-all" not in spf("v=spf1 redirect=_spf.x.com")


def test_multiple_spf_records_flagged():
    r = FakeResolver(txt={"a.com": ["v=spf1 -all", "v=spf1 +all"]})
    assert "email-spf-multiple" in ids(es.check_spf("a.com", True, r))


def test_spf_lookup_limit_follows_includes():
    txt = {"a.com": ["v=spf1 " + " ".join(f"include:i{n}.x.com" for n in range(6)) + " -all"]}
    for n in range(6):
        txt[f"i{n}.x.com"] = ["v=spf1 include:deep%d.x.com mx -all" % n]
        txt[f"deep{n}.x.com"] = ["v=spf1 ip4:1.1.1.1 -all"]
    r = FakeResolver(txt=txt)
    # 6 top-level includes, and each of those has one include and one mx inside it
    assert es.spf_lookup_count(txt["a.com"][0], r) == 6 + 6 * 2
    assert "email-spf-too-many-lookups" in ids(es.check_spf("a.com", True, r))


def test_dmarc_policies():
    def dmarc(rec):
        return ids(es.check_dmarc("a.com", True, FakeResolver(txt={"_dmarc.a.com": [rec]})))
    assert dmarc("v=DMARC1; p=reject; rua=mailto:r@a.com") == set()
    assert "email-dmarc-monitor-only" in dmarc("v=DMARC1; p=none; rua=mailto:r@a.com")
    assert "email-dmarc-no-reports" in dmarc("v=DMARC1; p=reject")
    assert "email-dmarc-partial" in dmarc("v=DMARC1; p=quarantine; pct=25; rua=mailto:r@a.com")
    assert "email-dmarc-subdomain-none" in dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:r@a.com")
    assert "email-dmarc-invalid" in dmarc("v=DMARC1; rua=mailto:r@a.com")


def _p(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def test_dkim_key_strength():
    r = FakeResolver(txt={"google._domainkey.a.com": [f"v=DKIM1; k=rsa; p={_p(1024)}"],
                          "selector1._domainkey.a.com": ["v=DKIM1; k=rsa; p="]})
    out = es.check_dkim("a.com", r)
    assert out["selectors"] == ["google", "selector1"]
    assert ids(out["findings"]) == {"email-dkim-1024-key"}
    assert es.check_dkim("a.com", FakeResolver())["findings"] == []     # nothing found proves nothing


def test_lookup_error_does_not_invent_findings():
    class Broken(FakeResolver):
        def resolve(self, name, rtype):
            raise dns.resolver.NoNameservers()
    assert es.check_spf("a.com", True, Broken()) == []          # SERVFAIL is "unknown", never "no SPF record"
    assert es.check_dmarc("a.com", True, Broken()) == []
    out = es.run_email_security("a.com", Broken())
    assert out["module_status"].startswith("failed") and out["findings"] == []
