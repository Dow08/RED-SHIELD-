"""Tests du bilan de santé (lecture seule + nettoyage dry-run non destructif)."""
import os

from app.core.bus import EventBus
from app.modules.health import HealthModule


def test_report_shape():
    m = HealthModule(EventBus())
    m.start()
    r = m._report()
    assert isinstance(r.disks, list) and len(r.disks) >= 1
    for d in r.disks:
        assert 0 <= d.percent <= 100 and d.total_gb >= 0
    # catégories nettoyables présentes (dont corbeille) avec tailles mesurées
    ids = {c.id for c in r.cleanables}
    assert {"temp", "recycle", "chrome_cache", "edge_cache", "winupdate"} <= ids
    assert r.cleanable_total_mb >= 0
    assert 0 <= r.ram_percent <= 100 and r.ram_total_gb > 0
    assert r.recommendations


def test_clean_temp_dry_run_is_non_destructive(tmp_path, monkeypatch):
    f = tmp_path / "junk.tmp"
    f.write_text("x" * 5000)
    old = os.path.getmtime(f) - 7200
    os.utime(f, (old, old))
    monkeypatch.setattr("app.modules.health._category_dirs", lambda cat: [str(tmp_path)] if cat == "temp" else [])
    m = HealthModule(EventBus())
    res = m.clean("temp", dry_run=True)
    assert res.category == "temp" and res.dry_run is True
    assert res.reclaimable_mb >= 0 and res.deleted_files == 0
    assert f.exists()


def test_clean_apply_skips_recent_files(tmp_path, monkeypatch):
    recent = tmp_path / "inuse.tmp"
    recent.write_text("y" * 3000)
    monkeypatch.setattr("app.modules.health._category_dirs", lambda cat: [str(tmp_path)] if cat == "temp" else [])
    m = HealthModule(EventBus())
    res = m.clean("temp", dry_run=False)
    assert recent.exists() and res.deleted_files == 0


def test_clean_unknown_category():
    m = HealthModule(EventBus())
    res = m.clean("does-not-exist", dry_run=True)
    assert res.error


def test_recycle_size_no_crash():
    # SHQueryRecycleBin ne doit jamais planter (renvoie 0 hors Windows)
    from app.modules.health import _recycle_size
    mb, n = _recycle_size()
    assert mb >= 0 and n >= 0
