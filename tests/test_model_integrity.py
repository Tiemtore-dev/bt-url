import hashlib

import pytest

from bt_url.ml import model as m


def write(tmp_path, content=b"payload"):
    p = tmp_path / "m.pkl"
    p.write_bytes(content)
    return str(p), hashlib.sha256(content).hexdigest()


def test_matching_hash_accepted(tmp_path):
    path, digest = write(tmp_path)
    m.verify_model(path, digest)
    m.verify_model(path, digest.upper())


def test_mismatching_hash_refused(tmp_path):
    path, _ = write(tmp_path)
    with pytest.raises(m.ModelIntegrityError):
        m.verify_model(path, "0" * 64)


def test_missing_expected_hash_refused_by_default(tmp_path):
    path, _ = write(tmp_path)
    with pytest.raises(m.ModelIntegrityError):
        m.verify_model(path, "")


def test_missing_hash_allowed_only_with_explicit_optin(tmp_path):
    path, _ = write(tmp_path)
    m.verify_model(path, "", allow_unverified=True)


def test_download_rejects_non_https(tmp_path):
    with pytest.raises(m.ModelIntegrityError):
        m.download_model("http://x/m.pkl", str(tmp_path / "m.pkl"), "a" * 64)


def test_download_removes_file_on_hash_mismatch(tmp_path, monkeypatch):
    def fake_retrieve(url, dest):
        open(dest, "wb").write(b"tampered")
    monkeypatch.setattr(m.urllib.request, "urlretrieve", fake_retrieve)
    dest = tmp_path / "sub" / "m.pkl"
    with pytest.raises(m.ModelIntegrityError):
        m.download_model("https://x/m.pkl", str(dest), "0" * 64)
    assert not dest.exists() and not list(dest.parent.glob("*.part"))


def test_download_success_moves_verified_file(tmp_path, monkeypatch):
    good = hashlib.sha256(b"ok").hexdigest()
    monkeypatch.setattr(m.urllib.request, "urlretrieve", lambda u, d: open(d, "wb").write(b"ok"))
    dest = tmp_path / "m.pkl"
    m.download_model("https://x/m.pkl", str(dest), good)
    assert dest.read_bytes() == b"ok"


def test_build_engine_disabled_returns_none():
    from bt_url.config import Settings
    assert m.build_engine(Settings(ml_enabled=False)) is None


def test_build_engine_refuses_tampered_model(tmp_path):
    from bt_url.config import Settings
    path, _ = write(tmp_path)
    assert m.build_engine(Settings(ml_enabled=True, model_path=path, model_sha256="0" * 64)) is None


def test_ml_is_disabled_by_default_and_ships_no_model(monkeypatch):
    from bt_url.config import Settings
    for var in ("BT_URL_ML_ENABLED", "BT_URL_MODEL_PATH", "BT_URL_MODEL_URL", "BT_URL_MODEL_SHA256"):
        monkeypatch.delenv(var, raising=False)
    s = Settings()
    assert s.ml_enabled is False and s.model_path == "" and s.model_url == "" and s.model_sha256 == ""
    assert m.build_engine(s) is None


def test_enabled_without_model_path_is_refused_not_crashing():
    from bt_url.config import Settings
    assert m.build_engine(Settings(ml_enabled=True, model_path="")) is None


def test_enabled_with_missing_file_and_no_url_is_unavailable(tmp_path):
    from bt_url.config import Settings
    assert m.build_engine(Settings(ml_enabled=True, model_path=str(tmp_path / "absent.pkl"))) is None
