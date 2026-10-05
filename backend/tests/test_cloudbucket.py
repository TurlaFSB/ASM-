from backend.scanner import cloudbucket as cb

LISTING = "<?xml version='1.0'?><ListBucketResult><Name>acme</Name><Contents><Key>secret-plan.pdf</Key></Contents></ListBucketResult>"


def test_candidate_names():
    n = cb.candidate_names("acme.com")
    assert n[0] == "acme" and "acme-backup" in n and "acme-dev" in n
    assert cb.candidate_names("acme.co.uk")[0] == "acme"
    assert cb.candidate_names("localhost") == []
    assert all(3 <= len(x) <= 63 for x in n)


def test_public_s3_listing_is_reported_without_object_names():
    def get(url):
        return (200, {}, LISTING) if url == "https://acme.s3.amazonaws.com/" else (404, {}, "NoSuchBucket")
    f, state = cb.check_s3("acme", "acme.com", get)
    assert state == "public" and "ownership-unverified" in f["tags"]
    assert "secret-plan" not in str(f) and "cloud-storage" in f["tags"]


def test_severity_reflects_that_the_name_is_only_a_guess():
    def get(url):
        return (200, {}, LISTING)
    distinctive, _ = cb.check_s3("northwindtraders", "northwindtraders.com", get)
    assert distinctive["severity"] == "medium"                      # never high: ownership is unproven
    for domain in ("example.com", "acme.com", "shop.co.uk", "dataflow.io"):
        f, _ = cb.check_s3(cb.base_label(domain), domain, get)
        assert f["severity"] == ("info" if cb.is_generic_label(domain) else "medium")
    assert cb.is_generic_label("example.com") and cb.is_generic_label("abc.org") and not cb.is_generic_label("northwindtraders.com")


def test_private_and_missing_buckets_are_not_findings():
    assert cb.check_s3("acme", "acme.com", lambda u: (403, {}, "AccessDenied")) == (None, "private")
    assert cb.check_s3("acme", "acme.com", lambda u: (404, {}, "NoSuchBucket")) == (None, "absent")
    assert cb.check_s3("acme", "acme.com", lambda u: None) == (None, "unknown")
    assert cb.check_gcs("acme", "acme.com", lambda u: (403, {}, "")) == (None, "private")


def test_s3_regional_redirect_is_followed_once():
    seen = []

    def get(url):
        seen.append(url)
        if url == "https://acme.s3.amazonaws.com/":
            return 301, {"x-amz-bucket-region": "eu-west-1"}, "PermanentRedirect"
        return 200, {}, LISTING
    f, state = cb.check_s3("acme", "acme.com", get)
    assert state == "public" and seen[-1] == "https://acme.s3.eu-west-1.amazonaws.com/"


def test_hostile_region_header_is_not_used_to_build_a_url():
    seen = []

    def get(url):
        seen.append(url)
        return 301, {"x-amz-bucket-region": "evil.com/x"}, ""
    assert cb.check_s3("acme", "acme.com", get)[1] == "unknown" and len(seen) == 1


def test_gcs_public_listing():
    f, state = cb.check_gcs("acme", "acme.com", lambda u: (200, {}, LISTING))
    assert state == "public" and f["template_id"].startswith("cloud-storage-public-google")


def test_azure_needs_account_then_container_listing():
    assert cb.check_azure("acme-dev", "acme.com", lambda u: None, exists=lambda a: False) == (None, "absent")
    calls = []

    def get(url):
        calls.append(url)
        return (200, {}, "<EnumerationResults>") if "/backup?" in url else (404, {}, "")
    f, state = cb.check_azure("acme-dev", "acme.com", get, exists=lambda a: a == "acmedev")
    assert state == "public" and f["host"] == "acmedev/backup" and calls[0].startswith("https://acmedev.")
    assert cb.check_azure("acme", "acme.com", lambda u: (404, {}, ""), exists=lambda a: True) == (None, "private")


def test_run_aggregates_and_flags_blocked_egress():
    def get(url):
        return (200, {}, LISTING) if url == "https://acme-backup.s3.amazonaws.com/" else (404, {}, "")
    out = cb.run_cloud_bucket_check("acme.com", get=get, azure_exists=lambda a: False, pause=0)
    assert out["module_status"] == "ok" and [f["host"] for f in out["findings"]] == ["acme-backup"]
    blocked = cb.run_cloud_bucket_check("acme.com", get=lambda u: None, azure_exists=lambda a: False, pause=0)
    assert blocked["module_status"].startswith("partial") and blocked["findings"] == []
    assert cb.run_cloud_bucket_check("x", pause=0)["module_status"] == "no candidate names"
