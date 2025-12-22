import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


class SecrecyFingerprintError(Exception):
    pass


@dataclass(frozen=True)
class HashingScheme:
    scheme_id: str
    normalization: str
    digest_prefix: str
    key_id: str | None = None

    @classmethod
    def from_dict(cls, payload: dict) -> "HashingScheme":
        if not isinstance(payload, dict):
            raise SecrecyFingerprintError("hashing_scheme must be an object")
        required = {"scheme_id", "normalization", "digest_prefix"}
        missing = required - set(payload)
        if missing:
            raise SecrecyFingerprintError(f"hashing_scheme missing fields: {sorted(missing)}")
        return cls(
            scheme_id=str(payload["scheme_id"]),
            normalization=str(payload["normalization"]),
            digest_prefix=str(payload["digest_prefix"]),
            key_id=payload.get("key_id"),
        )

    def uses_hmac(self) -> bool:
        return self.scheme_id.startswith("hmac") or self.digest_prefix.startswith("hmacsha256:")


@dataclass
class ScanResult:
    fingerprints: set[str]
    fingerprint_sources: dict[str, set[str]]
    scanned_files: list[str]
    errors: list[str]


DEFAULT_PROTECTED_PATHS = [
    "training/data/",
    "training/corpora/",
    "culture/chronicle/training_data/",
    "prompts/",
    "prompt_libraries/",
]

SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml", ".jsonl", ".txt", ".md"}
LIST_KEYS = ("items", "examples", "prompts", "test_cases", "records")


def canonicalize_item(obj: Any) -> bytes:
    try:
        payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise SecrecyFingerprintError("Item is not JSON-serializable") from exc
    return payload.encode("utf-8")


def _normalize_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.strip()


def _resolve_hmac_key(scheme: HashingScheme, override_key: bytes | None) -> bytes:
    if override_key is not None:
        return override_key
    key_id = scheme.key_id or "EVOALIGN_SECRECY_HMAC_KEY"
    if ":" in key_id:
        _, env_name = key_id.split(":", 1)
    else:
        env_name = key_id
    value = os.environ.get(env_name)
    if not value:
        raise SecrecyFingerprintError("HMAC key missing for secrecy fingerprinting")
    return value.encode("utf-8")


def _digest_bytes(payload: bytes, scheme: HashingScheme, hmac_key: bytes | None) -> str:
    if scheme.uses_hmac():
        key = _resolve_hmac_key(scheme, hmac_key)
        digest = hmac.new(key, payload, hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(payload).hexdigest()
    return f"{scheme.digest_prefix}{digest}"


def fingerprint_item(obj: Any, scheme: HashingScheme, hmac_key: bytes | None = None) -> str:
    return _digest_bytes(canonicalize_item(obj), scheme, hmac_key)


def fingerprint_text_block(text: str, scheme: HashingScheme, hmac_key: bytes | None = None) -> str | None:
    normalized = _normalize_text(text)
    if not normalized:
        return None
    payload = normalized.encode("utf-8")
    return _digest_bytes(payload, scheme, hmac_key)


def load_hash_registry(path: Path) -> tuple[dict, HashingScheme]:
    if not path.exists():
        raise SecrecyFingerprintError(f"Secret hash registry not found: {path}")
    with path.open() as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SecrecyFingerprintError("Secret hash registry must be an object")
    for field in ("registry_version", "hashing_scheme", "generated_at", "suite_registry_hash", "suites"):
        if field not in data:
            raise SecrecyFingerprintError(f"Secret hash registry missing '{field}'")
    scheme = HashingScheme.from_dict(data["hashing_scheme"])
    return data, scheme


def _extract_items(data: Any) -> list[Any]:
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                return value
        return [data]
    return [data]


def _fingerprints_from_value(value: Any, scheme: HashingScheme, hmac_key: bytes | None) -> list[str]:
    if isinstance(value, str):
        fingerprint = fingerprint_text_block(value, scheme, hmac_key)
        return [fingerprint] if fingerprint else []
    return [fingerprint_item(value, scheme, hmac_key)]


def _scan_json_lines(text: str, scheme: HashingScheme, hmac_key: bytes | None) -> list[str]:
    fingerprints: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            value = line
        fingerprints.extend(_fingerprints_from_value(value, scheme, hmac_key))
    return fingerprints


def _scan_text_blocks(text: str, scheme: HashingScheme, hmac_key: bytes | None) -> list[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", normalized) if p.strip()]
    fingerprints: list[str] = []
    for paragraph in paragraphs:
        fingerprint = fingerprint_text_block(paragraph, scheme, hmac_key)
        if fingerprint:
            fingerprints.append(fingerprint)
    whole = fingerprint_text_block(normalized, scheme, hmac_key)
    if whole:
        fingerprints.append(whole)
    return fingerprints


def _scan_structured_data(data: Any, scheme: HashingScheme, hmac_key: bytes | None) -> list[str]:
    fingerprints: list[str] = []
    for item in _extract_items(data):
        fingerprints.extend(_fingerprints_from_value(item, scheme, hmac_key))
    return fingerprints


def scan_file(file_path: Path, scheme: HashingScheme, hmac_key: bytes | None = None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    try:
        if file_path.suffix == ".jsonl":
            text = file_path.read_text(errors="ignore")
            return _scan_json_lines(text, scheme, hmac_key), errors
        if file_path.suffix in {".json", ".yaml", ".yml"}:
            with file_path.open() as f:
                data = json.load(f) if file_path.suffix == ".json" else yaml.safe_load(f)
            return _scan_structured_data(data, scheme, hmac_key), errors
        if file_path.suffix in {".txt", ".md"}:
            text = file_path.read_text(errors="ignore")
            return _scan_text_blocks(text, scheme, hmac_key), errors
    except Exception as exc:
        errors.append(f"{file_path}: {exc}")
        return [], errors
    return [], errors


def scan_protected_paths(
    repo_root: Path,
    scheme: HashingScheme,
    hmac_key: bytes | None = None,
    protected_paths: Iterable[str] | None = None,
) -> ScanResult:
    fingerprints: set[str] = set()
    fingerprint_sources: dict[str, set[str]] = {}
    scanned_files: list[str] = []
    errors: list[str] = []

    paths = list(protected_paths) if protected_paths is not None else DEFAULT_PROTECTED_PATHS
    for rel_path in paths:
        base_path = repo_root / rel_path
        if not base_path.exists():
            continue
        for file_path in base_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in SUPPORTED_SUFFIXES:
                continue
            rel_file = str(file_path.relative_to(repo_root))
            scanned_files.append(rel_file)
            file_fingerprints, file_errors = scan_file(file_path, scheme, hmac_key)
            errors.extend(file_errors)
            for fingerprint in file_fingerprints:
                fingerprints.add(fingerprint)
                fingerprint_sources.setdefault(fingerprint, set()).add(rel_file)

    return ScanResult(
        fingerprints=fingerprints,
        fingerprint_sources=fingerprint_sources,
        scanned_files=scanned_files,
        errors=errors,
    )
