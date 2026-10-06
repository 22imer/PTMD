"""Lazy, cache-only loading for the pinned Laya malware-analysis model."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

__all__ = [
    "LayaBackendError",
    "LayaModelConfig",
    "LocalLayaBackend",
    "load_laya_config",
]

_MODEL_ID = "convaiinnovations/laya"
_REVISION = "7b928d828b7b0e022f929d9bd2e44165aa270148"
_PACKAGE_VERSION = "0.3.28"
_ARTIFACT = "model.safetensors"
_WEIGHTS_SHA256 = "891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c"
_SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
_REVISION_PATTERN = re.compile(r"[a-fA-F0-9]{40}\Z")


class LayaBackendError(RuntimeError):
    """Sanitized failure with the inference-boundary state preserved."""

    def __init__(self, code: str, *, model_invoked: bool) -> None:
        self.code = code
        self.model_invoked = model_invoked
        super().__init__(code)


@dataclass(frozen=True)
class LayaModelConfig:
    """Immutable configuration for the sole approved checkpoint and package."""

    model_id: str
    revision: str
    weights_sha256: str
    device: str = "cpu"
    max_len: int = 512
    head_max_len: int = 192

    def __post_init__(self) -> None:
        if self.model_id != _MODEL_ID:
            raise ValueError("Laya model_id must match the approved pinned model")
        if self.revision != _REVISION or _REVISION_PATTERN.fullmatch(self.revision) is None:
            raise ValueError("Laya revision must match the approved pinned revision")
        if self.weights_sha256 != _WEIGHTS_SHA256 or _SHA256.fullmatch(self.weights_sha256) is None:
            raise ValueError("Laya weights_sha256 must match the approved pinned artifact")
        if not isinstance(self.device, str) or not self.device.strip():
            raise ValueError("Laya device must be nonempty")
        if (
            isinstance(self.max_len, bool)
            or not isinstance(self.max_len, int)
            or self.max_len < 1
            or isinstance(self.head_max_len, bool)
            or not isinstance(self.head_max_len, int)
            or self.head_max_len < 1
        ):
            raise ValueError("Laya token budgets must be positive integers")


def load_laya_config(pin_path: str | Path | None = None) -> LayaModelConfig:
    """Read and verify the single model pin; never resolve a tag or latest revision."""
    active_path = (
        Path(pin_path)
        if pin_path is not None
        else Path(__file__).resolve().parents[2] / "reports" / "integration-pin.json"
    )
    try:
        document = json.loads(active_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("integration model pin is unavailable or invalid") from exc
    if not isinstance(document, dict) or not isinstance(document.get("laya"), dict):
        raise TypeError("integration pin needs a Laya object")
    pin = document["laya"]
    if pin.get("python_package") != f"laya=={_PACKAGE_VERSION}":
        raise ValueError("integration pin has an unsupported Laya package")
    if pin.get("model") != _MODEL_ID or pin.get("artifact") != _ARTIFACT:
        raise ValueError("integration pin has an unsupported Laya model artifact")
    revision = pin.get("revision")
    digest = pin.get("expected_sha256")
    if not isinstance(revision, str) or _REVISION_PATTERN.fullmatch(revision) is None:
        raise ValueError("integration pin revision must be a full commit hash")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ValueError("integration pin expected_sha256 must be a SHA-256 digest")
    if revision != _REVISION or digest != _WEIGHTS_SHA256:
        raise ValueError("integration pin differs from the approved Laya model revision or digest")
    return LayaModelConfig(model_id=_MODEL_ID, revision=revision, weights_sha256=digest)


class LocalLayaBackend:
    """Load the pinned checkpoint from the local Hugging Face cache on first use."""

    def __init__(self, *, config: LayaModelConfig) -> None:
        self.config = config
        self._agent: Any | None = None
        self._package_version: str | None = None
        self._actual_weights_sha256: str | None = None

    def manifest(self) -> dict[str, object]:
        return {
            "model_id": self.config.model_id,
            "revision": self.config.revision,
            "package_version": self._package_version,
            "expected_weights_sha256": self.config.weights_sha256,
            "actual_weights_sha256": self._actual_weights_sha256,
            "device": self.config.device,
            "loaded": self._agent is not None,
        }

    def predict(
        self,
        state: str,
        questions: dict[str, object] | Any,
        *,
        max_len: int,
        head_max_len: int,
        min_confidence: float,
    ) -> dict[str, object] | Any:
        agent = self._agent
        if agent is None:
            agent = self._load_agent()
        try:
            result = agent.system_one(
                state,
                questions,
                lang="en",
                max_len=max_len,
                head_max_len=head_max_len,
                min_confidence=min_confidence,
            )
        except Exception as exc:
            raise LayaBackendError("INFERENCE_FAILED", model_invoked=True) from exc
        if not isinstance(result, dict):
            raise LayaBackendError("INFERENCE_FAILED", model_invoked=True)
        return cast("dict[str, object]", result)

    def _load_agent(self) -> Any:
        try:
            laya = importlib.import_module("laya")
            package_version = importlib.metadata.version("laya")
        except ImportError as exc:
            raise LayaBackendError("DEPENDENCY_UNAVAILABLE", model_invoked=False) from exc
        self._package_version = package_version
        if package_version != _PACKAGE_VERSION:
            raise LayaBackendError("DEPENDENCY_UNAVAILABLE", model_invoked=False)

        try:
            hub = importlib.import_module("huggingface_hub")
            snapshot_path = hub.snapshot_download(
                repo_id=self.config.model_id,
                revision=self.config.revision,
                local_files_only=True,
                allow_patterns=[_ARTIFACT, "rl_agent_config.json", "encoder/*", "tokenizer/*"],
            )
        except ImportError as exc:
            raise LayaBackendError("DEPENDENCY_UNAVAILABLE", model_invoked=False) from exc
        except Exception as exc:
            raise LayaBackendError("MODEL_UNAVAILABLE", model_invoked=False) from exc

        weights_path = Path(snapshot_path) / _ARTIFACT
        try:
            digest = _sha256_file(weights_path)
        except OSError as exc:
            raise LayaBackendError("MODEL_UNAVAILABLE", model_invoked=False) from exc
        self._actual_weights_sha256 = digest
        if digest != self.config.weights_sha256:
            raise LayaBackendError("ARTIFACT_MISMATCH", model_invoked=False)

        try:
            agent = laya.Agent(
                str(snapshot_path),
                device=self.config.device,
                expected_sha256={_ARTIFACT: self.config.weights_sha256},
                backend="eager",
                compile=False,
                fast=False,
            )
        except ImportError as exc:
            raise LayaBackendError("DEPENDENCY_UNAVAILABLE", model_invoked=False) from exc
        except Exception as exc:
            raise LayaBackendError("MODEL_UNAVAILABLE", model_invoked=False) from exc
        self._agent = agent
        return agent


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
