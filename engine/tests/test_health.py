"""Tests du bilan de santé (lecture seule + nettoyage dry-run non destructif)."""
import os

from app.core.bus import EventBus
from app.modules.health import HealthModule, _temp_dirs


def test_report_shape():
    m = HealthModule(EventBus())
    m.start()
    r = m._report()
    assert isinstance(r.disks, list) and len(r.disks) >= 1      # au moins un disque réel
    for d in r.disks:
        assert 0 <= d.percent <= 100 and d.total_gb >= 0
    assert r.temp_total_mb >= 0
    assert r.recommendations  # toujours au moins une recommandation


def test_clean_dry_run_is_non_destructive(tmp_path, monkeypatch):
    # Dossier temp factice avec un vieux fichier
    f = tmp_path / "junk.tmp"
    f.write_text("x" * 5000)
    old = os.path.getmtime(f) - 7200
    os.utime(f, (old, old))
    monkeypatch.setattr("app.modules.health._temp_dirs", lambda: [str(tmp_path)])
    m = HealthModule(EventBus())
    res = m.clean_temp(dry_run=True)
    assert res.dry_run is True
    assert res.reclaimable_mb >= 0
    assert res.deleted_files == 0        # dry-run ne supprime rien
    assert f.exists()                    # le fichier est toujours là


def test_clean_apply_skips_recent_files(tmp_path, monkeypatch):
    recent = tmp_path / "inuse.tmp"
    recent.write_text("y" * 3000)        # fichier récent (< 1h) → protégé
    monkeypatch.setattr("app.modules.health._temp_dirs", lambda: [str(tmp_path)])
    m = HealthModule(EventBus())
    res = m.clean_temp(dry_run=False)
    assert recent.exists()               # non supprimé car trop récent
    assert res.deleted_files == 0
