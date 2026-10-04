from backend.scanner import sensitive_files as sf

GIT_HEAD = b"ref: refs/heads/main\n"
ENV = b"APP_NAME=shop\nDB_PASSWORD=hunter2\nDEBUG=false\n"
HTML = b"<html><head><title>Welcome</title></head><body>hello</body></html>"


def site(files):
    """A fake host: path -> (status, body); everything else is a 404."""
    def get(url):
        path = "/" + url.split("/", 3)[3]
        status, body = files.get(path, (404, b"not found"))
        return status, {}, body
    return get


def scan(files):
    return sf.check_host("https://a.com", site(files), delay=0)


def test_exposed_git_and_env_are_found_with_evidence_but_no_content():
    findings, failed = scan({"/.git/HEAD": (200, GIT_HEAD), "/.env": (200, ENV)})
    by = {f["template_id"]: f for f in findings}
    assert failed == 0 and set(by) == {"exposed-git", "exposed-env"}
    assert by["exposed-env"]["severity"] == "critical"            # secret-looking variable name present
    assert by["exposed-git"]["matched_at"] == "https://a.com/.git/HEAD" and by["exposed-git"]["host"] == "https://a.com"
    assert "hunter2" not in str(by) and "DB_PASSWORD" not in str(by)
    assert "exposed-file" in by["exposed-git"]["tags"]


def test_env_without_secret_names_is_high():
    f, _ = scan({"/.env": (200, b"APP_NAME=shop\nDEBUG=false\n")})
    assert f[0]["severity"] == "high"


def test_catch_all_soft_404_site_produces_no_findings():
    everything = {p.path: (200, HTML) for p in sf.PROBES}
    findings, _ = scan(everything)
    assert findings == []


def test_redirects_and_errors_are_not_exposure():
    findings, _ = scan({"/.git/HEAD": (302, GIT_HEAD), "/.env": (403, ENV), "/backup.zip": (500, b"PK\x03\x04")})
    assert findings == []


def test_archives_need_real_magic_bytes():
    f, _ = scan({"/backup.zip": (200, b"PK\x03\x04rest"), "/site.zip": (200, b"<html>no</html>"),
                 "/backup.tar.gz": (200, b"\x1f\x8b\x08")})
    assert {x["template_id"] for x in f} == {"exposed-backup-zip", "exposed-backup-targz"}


def test_sql_dump_and_config_backup():
    f, _ = scan({"/backup.sql": (200, b"-- MySQL dump 10.13\nCREATE TABLE users (id int);"),
                 "/wp-config.php.bak": (200, b"<?php define('DB_PASSWORD', 'x');")})
    assert {(x["template_id"], x["severity"]) for x in f} == {
        ("exposed-backup-sql", "critical"), ("exposed-wp-config-backup", "critical")}


def test_private_key_and_aws_credentials():
    f, _ = scan({"/.ssh/id_rsa": (200, b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc"),
                 "/.aws/credentials": (200, b"[default]\naws_access_key_id = AKIA...")})
    assert {x["template_id"] for x in f} == {"exposed-ssh-key", "exposed-aws-credentials"}


def test_ds_store_magic():
    f, _ = scan({"/.DS_Store": (200, b"\x00\x00\x00\x01Bud1" + b"\x00" * 20)})
    assert f[0]["template_id"] == "exposed-ds-store" and f[0]["severity"] == "low"


def test_base_urls_dedupe_and_drop_paths():
    assert sf.base_urls(["https://a.com/x", "https://a.com/y?z=1", "http://a.com", "ftp://a.com", "junk"]) == [
        "https://a.com", "http://a.com"]


def test_run_reports_unreachable_hosts_as_partial_not_clean():
    out = sf.run_sensitive_file_check(["https://a.com"], get=lambda u: None, rate_limit=1000)
    assert out["module_status"].startswith("partial") and out["findings"] == []
    ok = sf.run_sensitive_file_check(["https://a.com/"], rate_limit=1000, get=site({"/.git/HEAD": (200, GIT_HEAD)}))
    assert ok["module_status"] == "ok" and len(ok["findings"]) == 1
    assert sf.run_sensitive_file_check([])["module_status"] == "no hosts provided"
