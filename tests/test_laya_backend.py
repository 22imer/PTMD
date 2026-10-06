"""Offline contract tests for the pinned, lazy Laya backend."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from guardrail.laya_backend import LayaBackendError, LocalLayaBackend, load_laya_config

ROOT = Path(__file__).resolve().parents[1]


def _install_fake_modules(monkeypatch: pytest.MonkeyPatch, *, laya: object, hub: object) -> list[str]:
    imports: list[str] = []

    def import_module(name: str, package: str | None = None) -> object:
        imports.append(name)
        if name == "laya":
            return laya
        if name == "huggingface_hub":
            return hub
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(importlib, "import_module", import_module)
    monkeypatch.setattr(importlib.metadata, "version", lambda package: "0.3.28")
    return imports


def _predict(backend: LocalLayaBackend) -> object:
    return backend.predict(
        "{\"facts\":[]}",
        {},
        max_len=512,
        head_max_len=192,
        min_confidence=0.8,
    )


def test_laya_configuration_comes_from_exact_pinned_revision_and_digest() -> None:
    config = load_laya_config()

    assert config.model_id == "convaiinnovations/laya"
    assert config.revision == "7b928d828b7b0e022f929d9bd2e44165aa270148"
    assert config.weights_sha256 == "891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c"
    assert config.max_len == 512
    assert config.head_max_len == 192


def test_backend_manifest_and_constructor_do_not_import_laya(monkeypatch: pytest.MonkeyPatch) -> None:
    imports: list[str] = []

    def forbidden_import(name: str, package: str | None = None) -> object:
        imports.append(name)
        raise AssertionError(f"unexpected lazy import: {name}")

    monkeypatch.setattr(importlib, "import_module", forbidden_import)
    backend = LocalLayaBackend(config=load_laya_config())

    manifest = backend.manifest()

    assert imports == []
    assert manifest["loaded"] is False
    assert manifest["actual_weights_sha256"] is None
    assert manifest["package_version"] is None


def test_missing_optional_dependency_is_a_structured_pre_inference_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = LocalLayaBackend(config=load_laya_config())

    def no_laya(name: str, package: str | None = None) -> object:
        if name == "laya":
            raise ModuleNotFoundError("laya is not installed")
        raise AssertionError(f"unexpected dependency import: {name}")

    monkeypatch.setattr(importlib, "import_module", no_laya)

    with pytest.raises(LayaBackendError) as error:
        _predict(backend)

    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert error.value.model_invoked is False
    assert backend.manifest()["loaded"] is False


def test_cache_only_weight_digest_mismatch_blocks_model_prediction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "model.safetensors").write_bytes(b"wrong cached weights")
    predict_calls: list[object] = []
    cache_requests: list[dict[str, object]] = []

    class FakeAgent:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def system_one(self, *args: object, **kwargs: object) -> object:
            predict_calls.append((args, kwargs))
            return {"answers": {}, "usage": {}}

    def snapshot_download(**kwargs: object) -> str:
        cache_requests.append(kwargs)
        return str(tmp_path)

    imports = _install_fake_modules(
        monkeypatch,
        laya=SimpleNamespace(Agent=FakeAgent, __version__="0.3.28"),
        hub=SimpleNamespace(snapshot_download=snapshot_download),
    )
    backend = LocalLayaBackend(config=load_laya_config())

    with pytest.raises(LayaBackendError) as error:
        _predict(backend)

    assert error.value.code == "ARTIFACT_MISMATCH"
    assert error.value.model_invoked is False
    assert predict_calls == []
    assert cache_requests[0]["local_files_only"] is True
    assert imports == ["laya", "huggingface_hub"]
    assert backend.manifest()["actual_weights_sha256"] == hashlib.sha256(b"wrong cached weights").hexdigest()


def test_missing_cached_snapshot_does_not_fall_back_to_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    class FakeAgent:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def system_one(self, *args: object, **kwargs: object) -> object:
            return {"answers": {}, "usage": {}}

    def snapshot_download(**kwargs: object) -> str:
        calls.append(kwargs)
        raise OSError("snapshot missing from local cache")

    _install_fake_modules(
        monkeypatch,
        laya=SimpleNamespace(Agent=FakeAgent, __version__="0.3.28"),
        hub=SimpleNamespace(snapshot_download=snapshot_download),
    )
    backend = LocalLayaBackend(config=load_laya_config())

    with pytest.raises(LayaBackendError) as error:
        _predict(backend)

    assert error.value.code == "MODEL_UNAVAILABLE"
    assert error.value.model_invoked is False
    assert calls[0]["local_files_only"] is True


def test_laya_pin_rejects_unpinned_revision(tmp_path: Path) -> None:
    document = json.loads((ROOT / "reports" / "integration-pin.json").read_text(encoding="utf-8"))
    document["laya"]["revision"] = "main"
    pin_path = tmp_path / "integration-pin.json"
    pin_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="revision"):
        load_laya_config(pin_path)
