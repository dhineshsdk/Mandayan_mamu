import json

from sutra_scan.cli import main

from .conftest import FIXTURES
from .test_inventory import DPKG


def _rootfs(tmp_path, os_release="ID=debian\nVERSION_ID=12\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n"):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(DPKG)
    (root / "etc/os-release").write_text(os_release)
    return root


def test_inventory_match_and_rows_end_to_end(tmp_path, snapshot, capsys):
    root = _rootfs(tmp_path)
    inv = tmp_path / "inv.json"
    assert main(["inventory", "--root", str(root), "--hostname", "plant-web01", "-o", str(inv)]) == 0
    assert json.loads(inv.read_text())["hostname"] == "plant-web01"
    out = tmp_path / "rows.jsonl"
    assert main(["match", str(inv), "--feed", str(snapshot.path), "-o", str(out)]) == 0
    text = capsys.readouterr().out
    assert "plant-web01: Debian GNU/Linux 12 - 3 packages, 2 vulnerabilities" in text and "libssl3 3.0.9-1" in text
    lines = out.read_text().splitlines()
    assert json.loads(lines[0])["format"] == "sutra-rows" and len(lines) == 4  # header, host, two findings


def test_fail_on_gates_by_severity(tmp_path, snapshot, capsys):
    inv = tmp_path / "inv.json"
    main(["inventory", "--root", str(_rootfs(tmp_path)), "-o", str(inv)])
    feed = str(snapshot.path)
    assert main(["match", str(inv), "--feed", feed, "--fail-on", "critical"]) == 0   # worst finding is high
    assert main(["match", str(inv), "--feed", feed, "--fail-on", "high"]) == 3
    capsys.readouterr()


def test_json_output(tmp_path, snapshot, capsys):
    root = _rootfs(tmp_path)
    assert main(["scan", "--root", str(root), "--feed", str(snapshot.path), "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc[0]["detections"][0]["url"].startswith("https://osv.dev/vulnerability/")
    assert doc[0]["feed"]["ecosystems"]


def test_errors_exit_2_with_a_message(tmp_path, snapshot, capsys):
    assert main(["scan", "--root", str(tmp_path), "--feed", str(snapshot.path)]) == 2
    assert "no dpkg, apk or rpm database" in capsys.readouterr().err
    assert main(["scan", "--root", str(_rootfs(tmp_path)), "--feed", str(tmp_path / "nope.db")]) == 2
    assert "no advisory snapshot" in capsys.readouterr().err
    other = tmp_path / "o"
    other.mkdir()
    assert main(["scan", "--root", str(_rootfs(other, "ID=fedora\nVERSION_ID=40\n")), "--feed", str(snapshot.path)]) == 2
    assert "not supported" in capsys.readouterr().err


def test_feed_build_and_info(tmp_path, capsys):
    db = tmp_path / "s.db"
    assert main(["feed", "build", str(db), str(FIXTURES / "osv"), "-e", "Debian:12"]) == 0
    assert json.loads(capsys.readouterr().out)["ecosystems"] == ["Debian:12"]
    assert main(["feed", "info", str(db)]) == 0
    assert json.loads(capsys.readouterr().out)["advisories"] == 3  # the fixtures that name Debian:12
