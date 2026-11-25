"""guardian_verify (Python) — stdlib-only verification SDK for Guardian v6 Layer 3.

Every HTTP/HTTP2/browser/OOB call is an RPC over a Unix-domain socket into the Guardian process,
which owns scope, persona credentials and the signed transcript. The script only sees response
data and exchange ids, never a credential.

Contract:
    setup(ctx)    optional
    verify(ctx)   required -> ctx.result(...) with transcript-backed claims
    cleanup(ctx)  optional

Guardian re-evaluates every claim against its own transcript and then re-runs the script in a
fresh session. Stdout is never evidence.

Only Python standard library modules are used (http.client, json, os, socket, statistics).
"""

from __future__ import annotations

import asyncio
import http.client
import inspect
import json
import math
import os
import re
import socket
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional


class _AwaitableDict(dict):
    """Dict that also supports `await` so inline Python scripts work with or without `await`."""

    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return self


class VerificationError(RuntimeError):
    """An RPC call or a script contract violation."""


def _context_path() -> str:
    return os.environ.get("GUARDIAN_RPC_CONTEXT_FILE", "/guardian-rpc/context.json")


def _socket_path() -> str:
    return os.environ.get("GUARDIAN_RPC_SOCKET", "/guardian-rpc/verify.sock")


def _token_path() -> str:
    return os.environ.get("GUARDIAN_RPC_TOKEN_FILE", "/guardian-rpc/token")


def _result_path() -> str:
    return os.environ.get("GUARDIAN_PROOF_RESULT_FILE", "/guardian-rpc/result.json")


def _read_context() -> dict[str, Any]:
    try:
        with open(_context_path(), "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError as error:
        raise VerificationError(f"Verification RPC context is unavailable: {error}") from error
    if not isinstance(raw, dict):
        raise VerificationError("Verification RPC context is malformed.")
    return raw


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:  # type: ignore[override]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def _rpc(op: str, args: dict[str, Any], timeout: float = 60.0) -> Any:
    context = _read_context()
    nonce = os.environ.get("GUARDIAN_VERIFY_NONCE", context.get("nonce", ""))
    try:
        with open(_token_path(), "r", encoding="utf-8") as handle:
            token = handle.read().strip()
    except OSError as error:
        raise VerificationError(f"Verification RPC capability is unavailable: {error}") from error
    payload = json.dumps({"op": op, "args": args}).encode("utf-8")
    connection = _UnixHTTPConnection(_socket_path(), timeout + 10.0)
    try:
        connection.request(
            "POST",
            "/rpc",
            body=payload,
            headers={
                "content-type": "application/json",
                "x-guardian-rpc-token": token,
                "x-guardian-verify-nonce": nonce,
            },
        )
        response = connection.getresponse()
        raw = response.read(8 * 1024 * 1024 + 1)
    except OSError as error:
        raise VerificationError(f"Verification RPC transport failed: {error}") from error
    finally:
        connection.close()
    if len(raw) > 8 * 1024 * 1024:
        raise VerificationError("Verification RPC response exceeded the SDK limit.")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("Verification RPC returned malformed JSON.") from error
    if not envelope.get("ok"):
        raise VerificationError(str(envelope.get("error", "Verification RPC call failed.")))
    return envelope.get("result")


@dataclass
class Exchange:
    raw: dict[str, Any]

    @property
    def exchange_id(self) -> str:
        return str(self.raw.get("exchangeId", ""))

    @property
    def exchangeId(self) -> str:  # noqa: N802 - compatibility with the TS/JSON shape
        return self.exchange_id

    @property
    def status(self) -> int:
        return int(self.raw.get("status", 0))

    @property
    def headers(self) -> dict[str, str]:
        return dict(self.raw.get("headers") or {})

    @property
    def body(self) -> str:
        return str(self.raw.get("body", ""))

    @property
    def duration_ms(self) -> float:
        return float(self.raw.get("durationMs", 0))

    @property
    def persona_handle(self) -> Optional[str]:
        value = self.raw.get("personaHandle")
        return str(value) if value is not None else None

    @property
    def consumed_capability_id(self) -> Optional[str]:
        value = self.raw.get("consumedCapabilityId")
        return str(value) if value is not None else None

    @property
    def derived_from_capability_ids(self) -> list[str]:
        return list(self.raw.get("derivedFromCapabilityIds") or [])

    @property
    def executed_sentinels(self) -> list[str]:
        return list(self.raw.get("executedSentinels") or [])

    def json(self) -> Any:
        return json.loads(self.body)

    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return self


@dataclass
class BrowserExchange(Exchange):
    @property
    def html(self) -> str:
        return str(self.raw.get("html", ""))

    @property
    def executed_sentinels(self) -> list[str]:
        return list(self.raw.get("executedSentinels") or [])


@dataclass
class OobHandle:
    raw: dict[str, Any]

    @property
    def exchange_id(self) -> str:
        return str(self.raw.get("exchangeId", ""))

    @property
    def token(self) -> str:
        return str(self.raw.get("token", ""))

    @property
    def url(self) -> str:
        return str(self.raw.get("url", ""))

    @property
    def dns_host(self) -> str:
        return str(self.raw.get("dnsHost", ""))

    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return self


@dataclass
class OobCheck(OobHandle):
    @property
    def hit(self) -> bool:
        return bool(self.raw.get("hit", False))


@dataclass
class TimingResult:
    control_ids: list[str]
    variant_ids: list[str]
    pairs: int

    @property
    def claim(self) -> dict[str, Any]:
        return {
            "kind": "timing",
            "controlIds": list(self.control_ids),
            "variantIds": list(self.variant_ids),
            "minPairs": self.pairs,
            "maxPValue": 0.05,
        }


@dataclass
class ProofResult:
    nonce: str
    title: str
    severity: str
    claims: list[dict[str, Any]]
    description: Optional[str] = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "sdk": "guardian_verify.py",
            "nonce": self.nonce,
            "title": self.title,
            "severity": self.severity,
            "claims": self.claims,
        }
        if self.description:
            out["description"] = self.description
        return out

    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return self


def _split_target(target: Any, default_origin: Optional[str]) -> tuple[Optional[str], str]:
    if isinstance(target, str):
        trimmed = target.strip()
        if not trimmed:
            raise VerificationError("HTTP target path/URL must be non-empty.")
        if trimmed.startswith("http://") or trimmed.startswith("https://"):
            from urllib.parse import urlsplit

            parts = urlsplit(trimmed)
            origin = f"{parts.scheme}://{parts.netloc}"
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            return origin, path
        path = trimmed if trimmed.startswith("/") else "/" + trimmed
        return default_origin, path
    if isinstance(target, dict):
        for key in ("url", "path", "pathAndQuery", "endpoint", "route"):
            value = target.get(key)
            if isinstance(value, str) and value.strip():
                origin, path = _split_target(value, target.get("origin") or default_origin)
                return target.get("origin", origin), path
        if target.get("target") is not None:
            origin, path = _split_target(target["target"], target.get("origin") or default_origin)
            return target.get("origin", origin), path
    raise VerificationError("HTTP target requires a path/URL string or a {'url' | 'path' | 'pathAndQuery' | 'endpoint': ...} mapping.")


def _extract_inline_options(spec: Any) -> dict[str, Any]:
    if not isinstance(spec, dict):
        return {}
    out: dict[str, Any] = {}
    if isinstance(spec.get("method"), str) and spec["method"].strip():
        out["method"] = spec["method"].strip().upper()
    if isinstance(spec.get("headers"), dict):
        out["headers"] = dict(spec["headers"])
    if spec.get("body") is not None:
        out["body"] = spec["body"]
    persona = spec.get("as_persona", spec.get("as", spec.get("persona")))
    if isinstance(persona, str) and persona:
        out["as_persona"] = persona
    if isinstance(spec.get("session"), str) and spec["session"]:
        out["session"] = spec["session"]
    if isinstance(spec.get("role"), str) and spec["role"]:
        out["role"] = spec["role"]
    if spec.get("follow_redirects") is not None:
        out["follow_redirects"] = bool(spec["follow_redirects"])
    elif spec.get("followRedirects") is not None:
        out["follow_redirects"] = bool(spec["followRedirects"])
    if spec.get("capability") is not None:
        out["capability"] = spec["capability"]
    for py_key, js_key in (
        ("capability_target", "capabilityTarget"),
        ("capability_header_name", "capabilityHeaderName"),
        ("capability_cookie_name", "capabilityCookieName"),
        ("capability_query_param", "capabilityQueryParam"),
        ("entity_id", "entityId"),
        ("correlation_ids", "correlationIds"),
        ("evidence_role", "evidenceRole"),
        ("replay_attempt", "replayAttempt"),
    ):
        val = spec.get(py_key, spec.get(js_key))
        if val is not None:
            out[py_key] = val
    return out


def _normalize_body_and_headers(body: Any, headers: Optional[dict[str, str]] = None) -> tuple[Optional[str], Optional[dict[str, str]]]:
    next_headers = dict(headers) if headers else None
    if body is None:
        return None, next_headers
    if isinstance(body, str):
        return body, next_headers
    serialized = json.dumps(body)
    if next_headers is None:
        next_headers = {"content-type": "application/json"}
    elif not any(key.lower() == "content-type" for key in next_headers):
        next_headers["content-type"] = "application/json"
    return serialized, next_headers


def _normalize_arm(arm: Any, helper_name: str, arm_name: str) -> tuple[Any, dict[str, Any]]:
    if arm is None:
        raise VerificationError(
            f"{helper_name} requires `{arm_name}` (path/URL string or {{'target'|'url'|'path'|'pathAndQuery', 'method'?, 'body'?, 'headers'?, 'as'?}})."
        )
    if isinstance(arm, tuple) and len(arm) == 2:
        return arm[0], dict(arm[1] or {})
    if isinstance(arm, str):
        return arm, {}
    if isinstance(arm, dict):
        raw_target = None
        for key in ("target", "url", "path", "pathAndQuery", "endpoint", "route"):
            if arm.get(key) is not None:
                raw_target = arm[key]
                break
        if raw_target is None:
            raise VerificationError(f"{helper_name}.{arm_name} requires a target string or 'url'/'path'/'pathAndQuery'.")
        opts = _extract_inline_options(arm)
        if isinstance(arm.get("options"), dict):
            opts.update(arm["options"])
        if isinstance(raw_target, str) and arm.get("origin"):
            raw_target = {"url": raw_target, "origin": arm["origin"]}
        return raw_target, opts
    raise VerificationError(f"{helper_name}.{arm_name} must be a path/URL string or request mapping.")


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _is_denied(status: int) -> bool:
    return status in (401, 403) or 300 <= status < 400


def _entry(role: str, exchange: Any = None, note: Optional[str] = None) -> dict[str, Any]:
    raw = getattr(exchange, "raw", exchange) or {}
    return {
        "exchangeId": str(raw.get("exchangeId", "")),
        "role": role,
        "personaHandle": raw.get("personaHandle"),
        "method": raw.get("method"),
        "pathAndQuery": raw.get("pathAndQuery"),
        "status": raw.get("status"),
        "durationMs": raw.get("durationMs", 0),
        **({"note": note} if note else {}),
    }


def _feedback(rejected_by: Optional[str], missing: list[str], transcript: list[dict[str, Any]]) -> dict[str, Any]:
    return {"rejectedBy": rejected_by, "missingEvidence": missing, "transcriptSummary": transcript}


def _parse_json(body: str) -> Any:
    if not body:
        return None
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        return None


def _field_parts(path: str) -> list[Any]:
    parts: list[Any] = []
    for raw in path.replace("[", ".").replace("]", "").split("."):
        if not raw:
            continue
        parts.append(int(raw) if raw.isdigit() else raw)
    return parts


def _read_field(value: Any, path: str) -> tuple[bool, Any]:
    current = value
    for part in _field_parts(path):
        if isinstance(current, list):
            if not isinstance(part, int) or part < 0 or part >= len(current):
                return False, None
            current = current[part]
            continue
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _flatten(value: Any, prefix: str = "", out: Optional[dict[str, str]] = None, depth: int = 0) -> dict[str, str]:
    fields = out if out is not None else {}
    if len(fields) >= 512 or depth > 6:
        return fields
    if isinstance(value, list):
        for index, child in enumerate(value[:64]):
            _flatten(child, f"{prefix}[{index}]" if prefix else f"[{index}]", fields, depth + 1)
        return fields
    if isinstance(value, dict):
        for key, child in value.items():
            _flatten(child, f"{prefix}.{key}" if prefix else str(key), fields, depth + 1)
        return fields
    if prefix:
        fields[prefix] = json.dumps(value)
    return fields


def _field_delta(before: Any, after: Any) -> dict[str, list[str]]:
    before_fields = _flatten(before)
    after_fields = _flatten(after)
    changed = [path for path, value in after_fields.items() if path in before_fields and before_fields[path] != value]
    added = [path for path in after_fields if path not in before_fields]
    removed = [path for path in before_fields if path not in after_fields]
    return {"changedFields": changed, "added": added, "removed": removed}


_STRUCTURAL_RULES: tuple[tuple[str, str], ...] = (
    (r'(["\']?(?:csrf|xsrf|nonce|authenticity[_-]?token|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|session[_-]?id|etag|server[_-]?time|request[_-]?time)["\']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;&}<]+)', r'\1"<dynamic>"'),
    (r'(\b(?:name|id)\s*=\s*["\'][^"\']*(?:csrf|xsrf|nonce|authenticity|request[_-]?id)[^"\']*["\'][^>]{0,200}?\b(?:content|value)\s*=\s*)("(?:[^"\\]|\\.)*"|\'[^\']*\')', r'\1"<dynamic>"'),
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>"),
    (r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?", "<timestamp>"),
    (r"\b1[5-9]\d{11}\b|\b2\d{12}\b", "<epoch>"),
    (r"\b[0-9a-f]{16,}\b", "<hex>"),
)
_LONG_OPAQUE_RE = re.compile(r"[A-Za-z0-9+/_=-]{24,}")


def normalize_structural_tokens(text: str) -> str:
    """Strip per-request tokens before structural comparison (same rules as the TS oracle)."""
    out = text
    for pattern, replacement in _STRUCTURAL_RULES:
        out = re.sub(pattern, replacement, out, flags=re.IGNORECASE)
    out = _LONG_OPAQUE_RE.sub(
        lambda match: "<opaque>" if (re.search(r"[A-Za-z]", match.group(0)) and re.search(r"\d", match.group(0))) else match.group(0),
        out,
    )
    return out


def _token_set(normalized: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", normalized.lower()) if len(token) >= 2}


def _changed_tokens(a: str, b: str) -> list[str]:
    tokens_a = _token_set(normalize_structural_tokens(a))
    tokens_b = _token_set(normalize_structural_tokens(b))
    return sorted(tokens_a.symmetric_difference(tokens_b))


def _normalize_equals(a: str, b: str) -> bool:
    return normalize_structural_tokens(a) == normalize_structural_tokens(b)


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return (ordered[middle - 1] + ordered[middle]) / 2 if len(ordered) % 2 == 0 else ordered[middle]


def _mad(values: list[float]) -> float:
    center = _median(values)
    return _median([abs(value - center) for value in values])


def _erf(x: float) -> float:
    sign = -1 if x < 0 else 1
    a = abs(x)
    t = 1 / (1 + 0.3275911 * a)
    y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * math.exp(-a * a)
    return sign * y


def _normal_cdf(z: float) -> float:
    return 0.5 * (1 + _erf(z / math.sqrt(2)))


def _mann_whitney(control: list[float], variant: list[float]) -> dict[str, float]:
    n1, n2 = len(control), len(variant)
    pooled = [(value, 0) for value in control] + [(value, 1) for value in variant]
    pooled.sort(key=lambda item: item[0])
    rank_sum = 0.0
    index = 0
    while index < len(pooled):
        end = index
        while end + 1 < len(pooled) and pooled[end + 1][0] == pooled[index][0]:
            end += 1
        average_rank = (index + end + 2) / 2
        for i in range(index, end + 1):
            if pooled[i][1] == 0:
                rank_sum += average_rank
        index = end + 1
    u1 = rank_sum - (n1 * (n1 + 1)) / 2
    mean_u = (n1 * n2) / 2
    sd_u = math.sqrt((n1 * n2 * (n1 + n2 + 1)) / 12)
    p_value = 1.0 if sd_u == 0 else 2 * (1 - _normal_cdf(abs(u1 - mean_u) / sd_u))
    median_control, median_variant = _median(control), _median(variant)
    pooled_mad = max(_mad(control), _mad(variant), 1e-9)
    return {
        "pValue": min(1.0, max(0.0, p_value)),
        "separation": abs(median_variant - median_control) / pooled_mad,
        "medianControl": median_control,
        "medianVariant": median_variant,
        "madControl": _mad(control),
        "madVariant": _mad(variant),
        "pairs": min(n1, n2),
    }


def _render_injection(template: str, canary: OobHandle) -> str:
    return (template
            .replace("{{canaryUrl}}", canary.url)
            .replace("{{canaryToken}}", canary.token)
            .replace("{{canaryHost}}", canary.dns_host))


class VerifyContext:
    def __init__(self) -> None:
        context = _read_context()
        self.nonce: str = os.environ.get("GUARDIAN_VERIFY_NONCE", context.get("nonce", ""))
        self.run_id: str = str(context.get("runId", "unknown-run"))
        self.target_origins: list[str] = list(context.get("targetOrigins") or [])
        self.target_origin: str = self.target_origins[0] if self.target_origins else ""
        self.sdk_version: str = str(context.get("sdkVersion", "guardian_verify/v6-mvp"))
        self.claims: list[dict[str, Any]] = []
        self._last_failed_composite_claim: Optional[dict[str, Any]] = None
        self._default_origin = self.target_origins[0] if self.target_origins else None

    # -- network ---------------------------------------------------------
    def _build_http_args(self, target: Any, options: dict[str, Any]) -> tuple[dict[str, Any], float]:
        origin, path = _split_target(target, self._default_origin)
        merged = {**_extract_inline_options(target), **options}
        body, headers = _normalize_body_and_headers(merged.get("body"), merged.get("headers"))
        args: dict[str, Any] = {
            "path": path,
            "method": str(merged.get("method", "GET")).upper(),
        }
        if origin:
            args["origin"] = origin
        if headers:
            args["headers"] = headers
        if body is not None:
            args["body"] = body
        persona = merged.get("as_persona", merged.get("as", merged.get("persona")))
        if persona:
            args["persona"] = persona
        if merged.get("session"):
            args["session"] = merged["session"]
        if merged.get("role"):
            args["sessionGroupRole"] = merged["role"]
        if merged.get("follow_redirects") is not None:
            args["followRedirects"] = bool(merged["follow_redirects"])
        cap = merged.get("capability")
        if cap is not None:
            if isinstance(cap, dict):
                cap_norm = dict(cap)
                if "header_name" in cap_norm and "headerName" not in cap_norm:
                    cap_norm["headerName"] = cap_norm.pop("header_name")
                if "cookie_name" in cap_norm and "cookieName" not in cap_norm:
                    cap_norm["cookieName"] = cap_norm.pop("cookie_name")
                if "query_param" in cap_norm and "queryParam" not in cap_norm:
                    cap_norm["queryParam"] = cap_norm.pop("query_param")
                args["capability"] = cap_norm
            else:
                args["capability"] = cap
        for py_key, rpc_key in (
            ("capability_target", "capabilityTarget"),
            ("capability_header_name", "capabilityHeaderName"),
            ("capability_cookie_name", "capabilityCookieName"),
            ("capability_query_param", "capabilityQueryParam"),
            ("entity_id", "entityId"),
            ("correlation_ids", "correlationIds"),
            ("evidence_role", "evidenceRole"),
            ("replay_attempt", "replayAttempt"),
        ):
            val = merged.get(py_key, merged.get(rpc_key))
            if val is not None:
                args[rpc_key] = val
        timeout = float(merged.get("timeout", 60.0))
        return args, timeout

    def http(self, target: Any, **options: Any) -> Exchange:
        args, timeout = self._build_http_args(target, options)
        return Exchange(_rpc("http", args, timeout))

    def http_send(self, target: Any, **options: Any) -> Exchange:
        args, timeout = self._build_http_args(target, options)
        return Exchange(_rpc("http.send", args, timeout))

    def httpSend(self, target: Any, **options: Any) -> Exchange:
        return self.http_send(target, **options)

    def request(self, target: Any, **options: Any) -> Exchange:
        return self.http_send(target, **options)

    def seal_capability(
        self,
        exchange_or_id: Any,
        slot: str,
        *,
        hop_receipt_id: Optional[str] = None,
        hop_id: Optional[str] = None,
        json_path: Optional[str] = None,
        header: Optional[str] = None,
        cookie: Optional[str] = None,
        regex: Optional[str] = None,
        value: Optional[str] = None,
        kind: Optional[str] = None,
        ttl_ms: Optional[int] = None,
        default_header_name: Optional[str] = None,
        default_cookie_name: Optional[str] = None,
        allowed_origins: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        exchange_id = exchange_or_id.exchange_id if isinstance(exchange_or_id, Exchange) else str(exchange_or_id)
        args: dict[str, Any] = {"exchangeId": exchange_id, "slot": slot}
        hop_r = hop_receipt_id or kwargs.get("hopReceiptId")
        if hop_r:
            args["hopReceiptId"] = hop_r
        hop_i = hop_id or kwargs.get("hopId")
        if hop_i:
            args["hopId"] = hop_i
        jp = json_path or kwargs.get("jsonPath")
        if jp:
            args["jsonPath"] = jp
        if header:
            args["header"] = header
        if cookie:
            args["cookie"] = cookie
        if regex:
            args["regex"] = regex
        if value is not None:
            args["value"] = value
        if kind:
            args["kind"] = kind
        ttl = ttl_ms if ttl_ms is not None else kwargs.get("ttlMs")
        if ttl is not None:
            args["ttlMs"] = ttl
        dhn = default_header_name or kwargs.get("defaultHeaderName")
        if dhn:
            args["defaultHeaderName"] = dhn
        dcn = default_cookie_name or kwargs.get("defaultCookieName")
        if dcn:
            args["defaultCookieName"] = dcn
        ao = allowed_origins or kwargs.get("allowedOrigins")
        if ao:
            args["allowedOrigins"] = list(ao)
        return _AwaitableDict(_rpc("capability.seal", args, 30.0))

    def hmac_sign(
        self,
        secret_handle: str,
        payload: str,
        alg: str = "sha256",
        encoding: str = "hex",
    ) -> dict[str, Any]:
        return _AwaitableDict(_rpc("crypto.hmacSign", {
            "secretHandle": secret_handle,
            "payload": payload,
            "alg": alg,
            "encoding": encoding,
        }, 30.0))

    def jwt_sign(
        self,
        secret_handle: str,
        claims: dict[str, Any],
        alg: str = "HS256",
        *,
        header: Optional[dict[str, Any]] = None,
        hop_receipt_id: Optional[str] = None,
        slot: Optional[str] = None,
        ttl_ms: Optional[int] = None,
        allowed_origins: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {
            "secretHandle": secret_handle,
            "claims": dict(claims),
            "alg": alg,
        }
        if header is not None:
            args["header"] = dict(header)
        hop_r = hop_receipt_id or kwargs.get("hopReceiptId")
        if hop_r:
            args["hopReceiptId"] = hop_r
        if slot:
            args["slot"] = slot
        ttl = ttl_ms if ttl_ms is not None else kwargs.get("ttlMs")
        if ttl is not None:
            args["ttlMs"] = ttl
        ao = allowed_origins or kwargs.get("allowedOrigins")
        if ao:
            args["allowedOrigins"] = list(ao)
        return _AwaitableDict(_rpc("crypto.jwtSign", args, 30.0))

    def await_async(
        self,
        poll_request: Any,
        match_predicate: Optional[dict[str, Any]] = None,
        *,
        profile: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        interval_ms: Optional[int] = None,
        max_attempts: Optional[int] = None,
        trigger_exchange_id: Optional[str] = None,
        t_trigger_ms: Optional[int] = None,
        correlation_id: Optional[str] = None,
        correlation_ids: Optional[list[str]] = None,
        entity_id: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        poll_args, _ = self._build_http_args(poll_request, {})
        args: dict[str, Any] = {"pollRequest": poll_args}
        mp = match_predicate if match_predicate is not None else kwargs.get("matchPredicate")
        if mp is not None:
            args["matchPredicate"] = dict(mp)
        if profile:
            args["profile"] = profile
        t_ms = timeout_ms if timeout_ms is not None else kwargs.get("timeoutMs")
        if t_ms is not None:
            args["timeoutMs"] = t_ms
        i_ms = interval_ms if interval_ms is not None else kwargs.get("intervalMs")
        if i_ms is not None:
            args["intervalMs"] = i_ms
        m_att = max_attempts if max_attempts is not None else kwargs.get("maxAttempts")
        if m_att is not None:
            args["maxAttempts"] = m_att
        trig = trigger_exchange_id or kwargs.get("triggerExchangeId")
        if trig:
            args["triggerExchangeId"] = trig.exchange_id if isinstance(trig, Exchange) else str(trig)
        tt = t_trigger_ms if t_trigger_ms is not None else kwargs.get("tTriggerMs")
        if tt is not None:
            args["tTriggerMs"] = tt
        cid = correlation_id or kwargs.get("correlationId")
        if cid:
            args["correlationId"] = cid
        cids = correlation_ids or kwargs.get("correlationIds")
        if cids:
            args["correlationIds"] = list(cids)
        eid = entity_id or kwargs.get("entityId")
        if eid:
            args["entityId"] = eid
        rpc_timeout = max((float(t_ms) / 1000.0 if t_ms else 30.0) + 10.0, 15.0)
        return _AwaitableDict(_rpc("async.awaitResult", args, rpc_timeout))

    def prove_composite(self, receipt: dict[str, Any]) -> dict[str, Any]:
        raw_receipt = (
            receipt["receipt"]
            if isinstance(receipt, dict) and isinstance(receipt.get("receipt"), dict)
            else (receipt if isinstance(receipt, dict) else {})
        )
        payload = receipt if isinstance(receipt, dict) and "receipt" in receipt else {"receipt": receipt}
        raw_result = _rpc("composite.verify", payload, 30.0)
        res: dict[str, Any] = dict(raw_result) if isinstance(raw_result, dict) else {}
        confirmed = bool(res.get("confirmed") is True or res.get("ok") is True or res.get("verified") is True)
        hops = raw_receipt.get("hops") if isinstance(raw_receipt.get("hops"), list) else []
        ti = raw_receipt.get("terminalImpact") if isinstance(raw_receipt.get("terminalImpact"), dict) else {}
        term_hop_id = ti.get("terminalHopId") if isinstance(ti.get("terminalHopId"), str) else ""
        term_hop = next((h for h in hops if isinstance(h, dict) and h.get("hopId") == term_hop_id), hops[-1] if hops and isinstance(hops[-1], dict) else None)
        term_target = term_hop.get("target") if isinstance(term_hop, dict) and isinstance(term_hop.get("target"), dict) else {}
        route = term_target.get("pathAndQuery") if isinstance(term_target.get("pathAndQuery"), str) else None

        def _str_ids(val: Any) -> list[str]:
            return [x for x in val if isinstance(x, str) and x] if isinstance(val, list) else []

        ex_ids: list[str] = []
        seen_ids: set[str] = set()
        for h in hops:
            if isinstance(h, dict):
                for x in _str_ids(h.get("exchangeIds")):
                    if x not in seen_ids:
                        seen_ids.add(x)
                        ex_ids.append(x)
        for key in ("preChainControlExchangeIds", "postChainReadbackExchangeIds"):
            for x in _str_ids(ti.get(key)):
                if x not in seen_ids:
                    seen_ids.add(x)
                    ex_ids.append(x)
        term_ex_field = ti.get("terminalExchangeId")
        if isinstance(term_ex_field, str) and term_ex_field.strip() and term_ex_field.strip() not in seen_ids:
            seen_ids.add(term_ex_field.strip())
            ex_ids.append(term_ex_field.strip())
        ex_ids = ex_ids[:64]

        term_hop_ex_ids = _str_ids(term_hop.get("exchangeIds")) if isinstance(term_hop, dict) else []
        terminal_exchange_id = (
            term_ex_field.strip()
            if isinstance(term_ex_field, str) and term_ex_field.strip()
            else (term_hop_ex_ids[-1] if term_hop_ex_ids else None)
        )
        cwe_blob = f"{raw_receipt.get('cwe', '')} {ti.get('cwe', '')} {raw_receipt.get('terminalVulnClass', '')} {ti.get('summary') or ti.get('claimedImpact') or ''}"
        cwe_match = re.search(r"\bCWE-\d{1,4}\b", cwe_blob, re.IGNORECASE)
        rejected_by = None if confirmed else (
            res.get("rejectedBy")
            or (f"composite_{res['failedStage']}" if res.get("failedStage") else "composite_receipt")
        )
        raw_missing = res.get("missingEvidence")
        missing_evidence = [] if confirmed else (
            list(raw_missing) if isinstance(raw_missing, list) and raw_missing else [str(rejected_by or "composite_receipt")]
        )
        claim: dict[str, Any] = {
            "kind": "composite_receipt",
            "chainId": str(res.get("chainId") or raw_receipt.get("chainId") or "invalid"),
            "terminalVulnClass": str(res.get("terminalVulnClass") or raw_receipt.get("terminalVulnClass") or "unknown"),
            "exchangeIds": ex_ids,
            "hopCount": int(res["hopCount"]) if isinstance(res.get("hopCount"), int) else len(hops),
            "compositeReceipt": raw_receipt,
        }
        if isinstance(res.get("verificationId"), str) and res["verificationId"]:
            claim["verificationId"] = res["verificationId"]
        if cwe_match:
            claim["cwe"] = cwe_match.group(0).upper()
        if route:
            claim["route"] = route
        if terminal_exchange_id:
            claim["terminalExchangeId"] = terminal_exchange_id
        if isinstance(res.get("replayMode"), str) and res["replayMode"]:
            claim["replayMode"] = res["replayMode"]
        if not confirmed:
            claim["rejectedBy"] = rejected_by
            claim["missingEvidence"] = missing_evidence
            if isinstance(res.get("reason"), str):
                claim["reason"] = res["reason"]
            self._last_failed_composite_claim = claim
        else:
            self._last_failed_composite_claim = None
            self.claims.append(claim)
        res["confirmed"] = confirmed
        res["ok"] = confirmed
        res["verified"] = confirmed
        res["rejectedBy"] = rejected_by
        res["missingEvidence"] = missing_evidence
        res["claim"] = claim
        return _AwaitableDict(res)

    def _effective_claims(self) -> list[dict[str, Any]]:
        if self.claims:
            return list(self.claims)
        return [self._last_failed_composite_claim] if self._last_failed_composite_claim else []

    def http2(self, target: Any, **options: Any) -> Exchange:
        origin, path = _split_target(target, self._default_origin)
        merged = {**_extract_inline_options(target), **options}
        body, headers = _normalize_body_and_headers(merged.get("body"), merged.get("headers"))
        args: dict[str, Any] = {"path": path, "method": str(merged.get("method", "GET")).upper()}
        if origin:
            args["origin"] = origin
        if headers:
            args["headers"] = headers
        if body is not None:
            args["body"] = body
        persona = merged.get("as_persona", merged.get("as", merged.get("persona")))
        if persona:
            args["persona"] = persona
        return Exchange(_rpc("http2", args, float(merged.get("timeout", 60.0))))

    def browser(self, target: Any, **options: Any) -> BrowserExchange:
        origin, path = _split_target(target, self._default_origin)
        args: dict[str, Any] = {"path": path}
        if origin:
            args["origin"] = origin
        persona = options.get("as_persona", options.get("as"))
        if persona:
            args["persona"] = persona
        if options.get("wait_for_selector"):
            args["waitForSelector"] = options["wait_for_selector"]
        return BrowserExchange(_rpc("browser", args, float(options.get("timeout", 60.0))))

    # -- OOB -------------------------------------------------------------
    def oob_mint(self, label: str, origin: Optional[str] = None) -> OobHandle:
        args: dict[str, Any] = {"action": "mint", "label": label}
        if origin:
            args["origin"] = origin
        return OobHandle(_rpc("oob", args, 30.0))

    def oob_check(self, handle: OobHandle) -> OobCheck:
        result = _rpc("oob", {"action": "check", "token": handle.token, "exchangeId": handle.exchange_id}, 30.0)
        merged = dict(handle.raw)
        merged.update(result or {})
        return OobCheck(merged)

    # -- assertions ------------------------------------------------------
    def _push(self, claim: dict[str, Any]) -> dict[str, Any]:
        self.claims.append(claim)
        return claim

    def expect_status(self, exchange: Exchange, expected: Any, message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "status", "exchangeId": exchange.exchange_id, "expected": expected}
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_status_not(self, exchange: Exchange, unexpected: int, message: Optional[str] = None) -> dict[str, Any]:
        candidates = [code for code in (200, 201, 202, 204, 301, 302, 400, 401, 403, 404, 405) if code != unexpected]
        return self.expect_status(exchange, candidates, message)

    def expect_header(self, exchange: Exchange, name: str, equals: Optional[str] = None,
                      matches: Optional[str] = None, absent: Optional[bool] = None,
                      message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "header", "exchangeId": exchange.exchange_id, "name": name}
        if equals is not None:
            claim["equals"] = equals
        if matches is not None:
            claim["matches"] = matches
        if absent is not None:
            claim["absent"] = bool(absent)
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_body(self, exchange: Exchange, text: str, message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "body_contains", "exchangeId": exchange.exchange_id, "text": text}
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_body_absent(self, exchange: Exchange, text: str, message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "body_contains", "exchangeId": exchange.exchange_id, "text": text, "absent": True}
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_json_path(self, exchange: Exchange, path: str, expected: Any = ..., message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "jsonpath", "exchangeId": exchange.exchange_id, "path": path}
        if expected is ...:
            claim["exists"] = True
        else:
            claim["equals"] = expected
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_css(self, exchange: Exchange, selector: str, exists: Optional[bool] = None,
                   count: Optional[int] = None, text_equals: Optional[str] = None,
                   text_contains: Optional[str] = None, message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "css", "exchangeId": exchange.exchange_id, "selector": selector}
        if exists is not None:
            claim["exists"] = bool(exists)
        if count is not None:
            claim["count"] = int(count)
        if text_equals is not None:
            claim["textEquals"] = text_equals
        if text_contains is not None:
            claim["textContains"] = text_contains
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_dom_sentinel(self, exchange: Exchange, sentinel: str, mode: str = "executed",
                            message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {
            "kind": "dom_sentinel",
            "exchangeId": exchange.exchange_id,
            "sentinel": sentinel,
            "mode": mode,
        }
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_oob(self, exchange: OobHandle, expect_hit: bool = True, message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "oob", "exchangeId": exchange.exchange_id, "expectHit": bool(expect_hit)}
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_timing(self, timing: TimingResult, message: Optional[str] = None) -> dict[str, Any]:
        claim = timing.claim
        if message:
            claim["message"] = message
        return self._push(claim)

    # -- timing ----------------------------------------------------------
    def timing_compare(self, control: Any, variant: Any, pairs: int = 6) -> TimingResult:
        count = max(5, min(int(pairs), 7))
        control_ids: list[str] = []
        variant_ids: list[str] = []
        for index in range(count):
            order = ("control", "variant") if index % 2 == 0 else ("variant", "control")
            for which in order:
                call = control if which == "control" else variant
                if isinstance(call, tuple):
                    target, options = call
                else:
                    target, options = call, {}
                exchange = self.http(target, **options)
                if which == "control":
                    control_ids.append(exchange.exchange_id)
                else:
                    variant_ids.append(exchange.exchange_id)
        return TimingResult(control_ids=control_ids, variant_ids=variant_ids, pairs=count)

    # -- first-class proof helpers ----------------------------------------
    def prove_access_boundary(self, control_persona: Optional[str] = None, probe_persona: Optional[str] = None,
                              route: Any = None, expect_control_denied: bool = True, **options: Any) -> dict[str, Any]:
        """Denied control + crossing variant on one route; emits a `boundary` claim."""
        if route is None:
            route = options.get("url", options.get("path"))
        if not route:
            raise VerificationError("prove_access_boundary requires `route`.")
        method = str(options.get("method", "GET")).upper()
        control_opts = dict(options.get("control_options") or options.get("controlOptions") or {})
        probe_opts = dict(options.get("probe_options") or options.get("probeOptions") or {})

        def _clean_persona(value: Any) -> Optional[str]:
            if not isinstance(value, str):
                return None
            trimmed = value.strip()
            if not trimmed or re.match(r"^(?:anonymous|anon|unauthenticated|none)$", trimmed, re.IGNORECASE):
                return None
            return trimmed

        ctrl_p = _clean_persona(control_persona if control_persona is not None else control_opts.pop("as", control_opts.pop("as_persona", control_opts.pop("persona", None))))
        prb_p = _clean_persona(probe_persona if probe_persona is not None else probe_opts.pop("as", probe_opts.pop("as_persona", probe_opts.pop("persona", None))))
        probe_route = options.get("probe_route", options.get("probeRoute", route))
        control = self.http(route, method=method, as_persona=ctrl_p, role="control",
                            session=options.get("control_session", options.get("controlSession", "access-boundary-control")),
                            **control_opts)
        probe = self.http(probe_route, method=method, as_persona=prb_p, role="probe",
                          session=options.get("probe_session", options.get("probeSession", "access-boundary-probe")),
                          **probe_opts)
        control_denied = _is_denied(control.status)
        crossed = _is_success(probe.status) and len(probe.body) >= 8
        vuln_class_raw = options.get("vuln_class", options.get("vulnClass"))
        vuln_class = str(vuln_class_raw).strip() if isinstance(vuln_class_raw, str) and vuln_class_raw.strip() else None
        is_auth_vuln = bool(vuln_class and re.match(r"^(?:auth_bypass|jwt_forgery|broken_auth|auth_protocol|token_forgery|authentication_bypass)$", vuln_class, re.IGNORECASE))
        boundary_class = options.get("boundary_class", options.get("boundaryClass", "auth" if is_auth_vuln else "access"))
        claim: dict[str, Any] = {
            "kind": "boundary",
            "boundaryClass": boundary_class,
            "controlExchangeId": control.exchange_id,
            "probeExchangeId": probe.exchange_id,
            "expectControlDenied": bool(expect_control_denied),
        }
        if vuln_class:
            claim["vulnClass"] = vuln_class
        if control_opts.get("body") is not None:
            raw_cb = control_opts["body"]
            claim["controlRequestBody"] = (_parse_json(raw_cb) or raw_cb) if isinstance(raw_cb, str) else raw_cb
        if probe_opts.get("body") is not None:
            raw_pb = probe_opts["body"]
            claim["probeRequestBody"] = (_parse_json(raw_pb) or raw_pb) if isinstance(raw_pb, str) else raw_pb
        if options.get("actor_roles") or options.get("actorRoles"):
            claim["actorRoles"] = options.get("actor_roles") or options.get("actorRoles")
        if options.get("actor_tenants") or options.get("actorTenants"):
            claim["actorTenants"] = options.get("actor_tenants") or options.get("actorTenants")
        if options.get("message"):
            claim["message"] = options["message"]
        self._push(claim)
        missing: list[str] = []
        if expect_control_denied and not control_denied:
            missing.append("control_denied")
        if not crossed:
            missing.append("variant_crossed")
        if not expect_control_denied and (ctrl_p or "") == (prb_p or ""):
            missing.append("actor_differential")
        return _AwaitableDict({
            "ok": not missing,
            "claim": claim,
            "control": control,
            "probe": probe,
            "transcript": {"control_denied": control.exchange_id, "variant_crossed": probe.exchange_id},
            "evidence": {"controlStatus": control.status, "variantStatus": probe.status,
                         "controlDenied": control_denied, "crossed": crossed},
            **_feedback("boundary" if missing else None, missing, [
                _entry("control_denied", control), _entry("variant_crossed", probe),
            ]),
        })

    def prove_persisted_mutation(self, read_route: Any, mutation: Any, field_path: str,
                                 expect_delta: Any = ..., **options: Any) -> dict[str, Any]:
        """Baseline GET + probe write + clean readback GET; emits an `impact` claim."""
        mut_target, mut_opts = _normalize_arm(mutation, "prove_persisted_mutation", "mutation")
        read_persona = options.get("read_persona", mut_opts.get("as_persona"))
        mutate_persona = options.get("mutate_persona", mut_opts.get("as_persona"))
        read_session = options.get("read_session", "persisted-read")
        before = self.http(read_route, method=options.get("read_method", "GET"),
                           as_persona=read_persona, role="control", session=read_session)
        body, headers = _normalize_body_and_headers(mut_opts.get("body"), mut_opts.get("headers"))
        if body is not None and not any(key.lower() == "content-type" for key in (headers or {})):
            headers = {"content-type": "application/json", **(headers or {})}
        write = self.http(mut_target, method=str(mut_opts.get("method", "POST")).upper(),
                          body=body, headers=headers, as_persona=mutate_persona,
                          role="probe", session=mut_opts.get("session", read_session))
        after = self.http(read_route, method=options.get("read_method", "GET"),
                          as_persona=read_persona, role="control", session=read_session)
        before_json, after_json = _parse_json(before.body), _parse_json(after.body)
        before_found, before_value = _read_field(before_json, field_path)
        after_found, after_value = _read_field(after_json, field_path)
        fields = _field_delta(before_json, after_json)
        delta = {
            "fieldPath": field_path,
            "before": before_value if before_found else None,
            "after": after_value if after_found else None,
            "changed": before_found and after_found and before_value != after_value,
            **fields,
        }
        if callable(expect_delta):
            expectation_matched = bool(expect_delta(delta["before"], delta["after"], delta))
        elif expect_delta is ...:
            expectation_matched = True
        else:
            expectation_matched = delta["after"] == expect_delta
        claim: dict[str, Any] = {
            "kind": "impact",
            "impactClass": options.get("impact_class", "mass_assignment"),
            "probeExchangeId": write.exchange_id,
            "beforeExchangeId": before.exchange_id,
            "afterExchangeId": after.exchange_id,
        }
        for key, source in (("requiredRole", "required_role"), ("resourceTenant", "resource_tenant"),
                            ("oracleEvents", "oracle_events"), ("actorRoles", "actor_roles"),
                            ("actorTenants", "actor_tenants"), ("message", "message")):
            if options.get(source):
                claim[key] = options[source]
        request_json = _parse_json(body) if body is not None else None
        if request_json is not None:
            claim["requestBody"] = request_json
        self._push(claim)
        missing: list[str] = []
        if not _is_success(before.status):
            missing.append("before_get")
        if not _is_success(write.status):
            missing.append("mutation_success")
        if not _is_success(after.status):
            missing.append("after_get")
        if before_json is None or after_json is None:
            missing.append("json_readback")
        if not delta["changed"]:
            missing.append(f"field_delta:{field_path}")
        if not expectation_matched:
            missing.append("expected_delta")
        return _AwaitableDict({
            "ok": not missing, "claim": claim, "before": before, "mutation": write, "after": after,
            "delta": delta, "expectationMatched": expectation_matched,
            **_feedback("impact" if missing else None, missing, [
                _entry("before_get", before), _entry("mutation", write), _entry("after_get", after),
            ]),
        })

    def prove_boolean_or_timing_diff(self, control: Any, variant: Any, mode: str,
                                     rounds: Optional[int] = None, **options: Any) -> dict[str, Any]:
        """Interleaved boolean/content or timing differential; emits the matching claim."""
        control_target, control_options = _normalize_arm(control, "prove_boolean_or_timing_diff", "control")
        variant_target, variant_options = _normalize_arm(variant, "prove_boolean_or_timing_diff", "variant")
        session = options.get("session", f"diff-{mode}")
        control_exchanges: list[Exchange] = []
        variant_exchanges: list[Exchange] = []
        if mode == "timing":
            pairs = max(5, min(int(rounds or 6), 7))
            for index in range(pairs):
                order = ("control", "variant") if index % 2 == 0 else ("variant", "control")
                for which in order:
                    target, extra = ((control_target, control_options) if which == "control"
                                     else (variant_target, variant_options))
                    exchange = self.http(target, role=("control" if which == "control" else "probe"), session=session, **extra)
                    (control_exchanges if which == "control" else variant_exchanges).append(exchange)
            control_ids = [item.exchange_id for item in control_exchanges]
            variant_ids = [item.exchange_id for item in variant_exchanges]
            claim: dict[str, Any] = {
                "kind": "timing", "controlIds": control_ids, "variantIds": variant_ids,
                "minPairs": pairs, "maxPValue": options.get("max_p_value", 0.05),
            }
            if options.get("message"):
                claim["message"] = options["message"]
            self._push(claim)
            stats = _mann_whitney([item.duration_ms for item in control_exchanges],
                                  [item.duration_ms for item in variant_exchanges])
            missing: list[str] = []
            if len(control_ids) < pairs:
                missing.append("control_arm")
            if len(variant_ids) < pairs:
                missing.append("variant_arm")
            if stats["pValue"] > float(options.get("max_p_value", 0.05)) or stats["separation"] < 3:
                missing.append("timing_separation")
            return _AwaitableDict({
                "ok": not missing, "mode": "timing", "controlIds": control_ids,
                "variantIds": variant_ids, "claim": claim, "stats": stats,
                "exchanges": {"control": control_exchanges, "variant": variant_exchanges},
                **_feedback("timing" if missing else None, sorted(set(missing), key=missing.index), [
                    *[_entry("control", item, f"timing {item.duration_ms}ms") for item in control_exchanges],
                    *[_entry("probe", item, f"timing {item.duration_ms}ms") for item in variant_exchanges],
                ]),
            })

        count = max(2, min(int(rounds or 3), 6))
        for index in range(count):
            order = ("control", "variant") if index % 2 == 0 else ("variant", "control")
            for which in order:
                target, extra = ((control_target, control_options) if which == "control"
                                 else (variant_target, variant_options))
                exchange = self.http(target, role=("control" if which == "control" else "probe"), session=session, **extra)
                (control_exchanges if which == "control" else variant_exchanges).append(exchange)
        control_ids = [item.exchange_id for item in control_exchanges]
        variant_ids = [item.exchange_id for item in variant_exchanges]
        control_bodies = [item.body for item in control_exchanges]
        variant_bodies = [item.body for item in variant_exchanges]
        stable_control = all(_normalize_equals(control_bodies[0], body) for body in control_bodies)
        stable_variant = all(_normalize_equals(variant_bodies[0], body) for body in variant_bodies)
        round_deltas = [_changed_tokens(body, variant_bodies[index] if index < len(variant_bodies) else variant_bodies[0])
                        for index, body in enumerate(control_bodies)]
        stable_delta = [token for token in (round_deltas[0] if round_deltas else [])
                        if all(token in other for other in round_deltas)]
        control_tokens = _token_set(normalize_structural_tokens(control_bodies[0] if control_bodies else ""))
        variant_tokens = _token_set(normalize_structural_tokens(variant_bodies[0] if variant_bodies else ""))
        union = control_tokens | variant_tokens
        similarity = 1.0 if not union else len(control_tokens & variant_tokens) / len(union)
        min_delta = int(options.get("min_delta_tokens", options.get("min_similarity_delta", 1)))
        max_similarity = float(options.get("max_similarity", 1))
        claim = {
            "kind": "structural_diff", "controlIds": control_ids, "variantIds": variant_ids,
            "minRounds": count, "minDeltaTokens": min_delta, "maxSimilarity": max_similarity,
        }
        if options.get("message"):
            claim["message"] = options["message"]
        self._push(claim)
        missing = []
        if not stable_control:
            missing.append("stable_control_arm")
        if not stable_variant:
            missing.append("stable_variant_arm")
        if len(stable_delta) < min_delta:
            missing.append("stable_variant_delta")
        if _normalize_equals(control_bodies[0] if control_bodies else "",
                             variant_bodies[0] if variant_bodies else "") or similarity >= max_similarity:
            missing.append("arm_differential")
        return _AwaitableDict({
            "ok": not missing, "mode": "boolean", "controlIds": control_ids,
            "variantIds": variant_ids, "claim": claim,
            "stats": {"stableDelta": stable_delta, "similarity": round(similarity, 4),
                      "rounds": count, "stableControl": stable_control, "stableVariant": stable_variant},
            "exchanges": {"control": control_exchanges, "variant": variant_exchanges},
            **_feedback("structural_diff" if missing else None, missing, [
                *[_entry("control", item) for item in control_exchanges],
                *[_entry("probe", item) for item in variant_exchanges],
            ]),
        })

    def prove_oob_callback(self, inject: Any, token: Optional[str] = None,
                           timeout_ms: int = 6000, immediate_ms: int = 3000,
                           window_ms: Optional[int] = None, **options: Any) -> dict[str, Any]:
        """Mint -> durable pending_oob subscription -> inject -> wait/promote a late callback."""
        handle = self.oob_mint(token or "oob")
        subscribe_args: dict[str, Any] = {
            "action": "subscribe", "token": handle.token,
            "exchangeId": handle.exchange_id, "immediateMs": int(immediate_ms),
        }
        if window_ms is not None:
            subscribe_args["windowMs"] = int(window_ms)
        subscription = _rpc("oob", subscribe_args, 30.0) or {}
        injection: Optional[Exchange] = None
        injection_error: Optional[str] = None
        try:
            if callable(inject):
                injected = inject(handle)
                injection = injected if isinstance(injected, Exchange) else None
            else:
                spec = dict(inject)
                body = spec.get("body")
                if body is not None:
                    body = _render_injection(str(body), handle)
                injection = self.http(spec.get("target", spec.get("url", "/")),
                                      method=str(spec.get("method", "POST")).upper(),
                                      body=body, headers=spec.get("headers"),
                                      as_persona=spec.get("as"), role="probe", session="oob-injection")
        except Exception as error:  # noqa: BLE001 - injection failure is evidence, not a crash
            injection_error = str(error)[:300]
        wait_args: dict[str, Any] = {
            "action": "wait", "token": handle.token, "immediateMs": int(immediate_ms),
            "timeoutMs": int(timeout_ms),
        }
        if subscription.get("subscriptionId"):
            wait_args["subscriptionId"] = subscription["subscriptionId"]
        if isinstance(subscription.get("createdAt"), (int, float)):
            wait_args["subscriptionCreatedAt"] = subscription["createdAt"]
        wait = _rpc("oob", wait_args, float(timeout_ms) / 1000 + 10.0) or {}
        claim: dict[str, Any] = {"kind": "oob", "exchangeId": handle.exchange_id, "expectHit": True}
        if options.get("message"):
            claim["message"] = options["message"]
        self._push(claim)
        hit = bool(wait.get("hit"))
        missing: list[str] = []
        if not subscription.get("subscriptionId"):
            missing.append("pending_oob_subscription")
        if injection_error:
            missing.append("injection")
        if not hit:
            missing.append("oob_callback_hit")
        transcript = [_entry("oob_mint", {"exchangeId": handle.exchange_id, "method": "MINT", "pathAndQuery": "/"})]
        if subscription.get("subscriptionId"):
            transcript.append(_entry("pending_oob", {"exchangeId": subscription["subscriptionId"],
                                                     "method": "SUBSCRIBE", "pathAndQuery": "/oob/pending"}, subscription.get("status", "pending")))
        if injection is not None:
            transcript.append(_entry("oob_injection", injection))
        if wait.get("exchangeId"):
            transcript.append(_entry("oob_wait", {"exchangeId": wait["exchangeId"], "method": "WAIT",
                                                  "pathAndQuery": "/oob/wait"}, "hit" if hit else "no callback"))
        return _AwaitableDict({
            "ok": not missing, "claim": claim, "token": handle.token, "url": handle.url,
            "dnsHost": handle.dns_host, "hit": hit,
            "stage": wait.get("stage", "immediate" if hit else ("pending" if subscription.get("subscriptionId") else "none")),
            "promoted": bool(wait.get("promoted")),
            "subscriptionId": wait.get("subscriptionId", subscription.get("subscriptionId")),
            "exchanges": {"mint": handle.exchange_id,
                          "injection": injection.exchange_id if injection else None,
                          "wait": wait.get("exchangeId")},
            **_feedback("injection" if injection_error else ("oob" if missing else None), missing, transcript),
        })

    def prove_race_burst(self, requests: list[Any], barrier: str = "auto", **options: Any) -> dict[str, Any]:
        """Synchronized HTTP/2 single-packet burst with optional conserved-balance readbacks + serial control."""
        if len(requests) < 2 or len(requests) > 10:
            claim = {"kind": "race", "exchangeIds": [], "mode": "http1-fallback",
                     "minDistinctOutcomes": int(options.get("min_distinct_outcomes", options.get("minDistinctOutcomes", 2)))}
            return {"ok": False, "claim": claim, "mode": "http1-fallback",
                    "fallbackReason": "race requires between 2 and 10 requests", "summary": {},
                    "exchanges": [], **_feedback("race", ["race_requests"], [])}
        payload: list[dict[str, Any]] = []
        first_request_body: Any = None
        for index, request in enumerate(requests):
            if isinstance(request, str):
                origin, path = _split_target(request, self._default_origin)
                payload.append({"path": path, "method": "GET", "sessionGroupRole": "probe",
                                **({"origin": origin or self._default_origin} if (origin or self._default_origin) else {}),
                                **({"session": options.get("session", "race")} if options.get("session") else {})})
                continue
            spec = dict(request)
            raw_target = spec.get("target", spec.get("url", spec.get("path", spec.get("pathAndQuery", spec.get("endpoint", spec.get("route", "/"))))))
            origin, path = _split_target(raw_target, self._default_origin)
            body_str, headers_norm = _normalize_body_and_headers(spec.get("body"), spec.get("headers"))
            if index == 0 and body_str is not None:
                parsed_req = _parse_json(body_str)
                first_request_body = parsed_req if parsed_req is not None else body_str
            entry: dict[str, Any] = {
                "path": path, "method": str(spec.get("method", "GET")).upper(),
                "sessionGroupRole": "probe", "session": options.get("session", f"race-{index}"),
            }
            if spec.get("origin") or origin or self._default_origin:
                entry["origin"] = spec.get("origin") or origin or self._default_origin
            if headers_norm:
                entry["headers"] = headers_norm
            if body_str is not None:
                entry["body"] = body_str
            persona = spec.get("as_persona", spec.get("as", spec.get("persona")))
            if persona:
                entry["persona"] = persona
            payload.append(entry)
        read_route = options.get("read_route", options.get("readRoute"))
        first_persona = payload[0].get("persona") if payload else None
        read_persona = options.get("read_persona", options.get("readPersona", first_persona))
        read_method = str(options.get("read_method", options.get("readMethod", "GET"))).upper()
        baseline: Optional[Exchange] = None
        if read_route is not None:
            baseline = self.http(
                read_route,
                method=read_method,
                as_persona=read_persona,
                role="setup",
                session=f"{options['session']}-baseline" if options.get("session") else "race-baseline",
            )
        result = _rpc("race", {"requests": payload}, 70.0) or {}
        mode = result.get("mode", "http1-fallback")
        exchanges = [{"exchangeId": item.get("exchangeId", ""), "status": int(item.get("status", 0)),
                      "durationMs": item.get("durationMs", 0), "bodySha256": item.get("bodySha256", "")}
                     for item in result.get("results", [])]
        post: Optional[Exchange] = None
        serial: Optional[Exchange] = None
        serial_post: Optional[Exchange] = None
        if read_route is not None:
            post = self.http(
                read_route,
                method=read_method,
                as_persona=read_persona,
                role="control",
                session=f"{options['session']}-post" if options.get("session") else "race-post",
            )
            serial_spec = options.get("serial_request", options.get("serialRequest", requests[0]))
            serial_target, serial_opts = _normalize_arm(serial_spec, "prove_race_burst", "serial_request")
            serial_opts.setdefault("method", payload[0]["method"])
            if first_persona and not serial_opts.get("as_persona"):
                serial_opts["as_persona"] = first_persona
            serial = self.http(
                serial_target,
                role="control",
                session=f"{options['session']}-serial" if options.get("session") else "race-serial",
                **serial_opts,
            )
            if _is_success(serial.status):
                serial_post = self.http(
                    read_route,
                    method=read_method,
                    as_persona=read_persona,
                    role="control",
                    session=f"{options['session']}-serial-post" if options.get("session") else "race-serial-post",
                )
        distinct_bodies = len({item["bodySha256"] for item in exchanges})
        distinct_statuses = len({item["status"] for item in exchanges})
        distinct_outcomes = max(distinct_bodies, distinct_statuses)
        min_distinct = int(options.get("min_distinct_outcomes", options.get("minDistinctOutcomes", 2)))
        acked_count = sum(1 for item in exchanges if _is_success(item["status"]))
        baseline_id = baseline.exchange_id if baseline else options.get("baseline_exchange_id", options.get("baselineExchangeId"))
        post_id = post.exchange_id if post else options.get("post_exchange_id", options.get("postExchangeId"))
        serial_ids = [serial.exchange_id] if serial else options.get("serial_exchange_ids", options.get("serialExchangeIds"))
        serial_pre_id = options.get("serial_pre_exchange_id", options.get("serialPreExchangeId"))
        serial_post_id = serial_post.exchange_id if serial_post else options.get("serial_post_exchange_id", options.get("serialPostExchangeId"))
        has_conserved = bool(read_route is not None or baseline_id or post_id or serial_ids)
        explicit_expect_all = options.get("expect_all_success", options.get("expectAllSuccess"))
        if explicit_expect_all is not None:
            expect_all = bool(explicit_expect_all)
        else:
            expect_all = False if (has_conserved and acked_count >= 2 and acked_count < len(exchanges)) else True
        burst_ids = [item["exchangeId"] for item in exchanges]
        claim: dict[str, Any] = {
            "kind": "race",
            "exchangeIds": burst_ids,
            "mode": mode,
            "minDistinctOutcomes": min_distinct,
            "expectAllSuccess": expect_all,
        }
        if has_conserved:
            claim["burstExchangeIds"] = burst_ids
        if baseline_id:
            claim["baselineExchangeId"] = baseline_id
        if post_id:
            claim["postExchangeId"] = post_id
        if serial_pre_id:
            claim["serialPreExchangeId"] = serial_pre_id
        if serial_ids:
            claim["serialExchangeIds"] = list(serial_ids)
        if serial_post_id:
            claim["serialPostExchangeId"] = serial_post_id
        balance_field = options.get("balance_field", options.get("balanceField"))
        cap_field = options.get("cap_field", options.get("capField"))
        unit_debit = options.get("unit_debit", options.get("unitDebit"))
        vuln_class = options.get("vuln_class", options.get("vulnClass"))
        if balance_field:
            claim["balanceField"] = str(balance_field)
        if cap_field:
            claim["capField"] = str(cap_field)
        if unit_debit is not None:
            claim["unitDebit"] = float(unit_debit)
        if vuln_class:
            claim["vulnClass"] = str(vuln_class)
        elif has_conserved:
            claim["vulnClass"] = "race_double_spend"
        if first_request_body is not None:
            claim["requestBody"] = first_request_body
        if options.get("message"):
            claim["message"] = options["message"]
        self._push(claim)
        missing: list[str] = []
        if barrier == "h2" and mode != "h2-single-packet":
            missing.append("h2_single_packet_barrier")
        if distinct_outcomes < min_distinct:
            missing.append("duplicate_effect")
        if expect_all and any(not _is_success(item["status"]) for item in exchanges):
            missing.append("all_participants_success")
        if has_conserved and acked_count < 2:
            missing.append("acked_burst_mutations")
        transcript: list[dict[str, Any]] = []
        if baseline is not None:
            transcript.append(_entry("setup", baseline, "baseline_read"))
        transcript.extend(
            _entry("race", {"exchangeId": item["exchangeId"], "method": payload[index]["method"],
                            "pathAndQuery": payload[index]["path"], "status": item["status"],
                            "durationMs": item["durationMs"]}, mode)
            for index, item in enumerate(exchanges)
        )
        if post is not None:
            transcript.append(_entry("control", post, "post_read"))
        if serial is not None:
            transcript.append(_entry("control", serial, "serial_control"))
        if serial_post is not None:
            transcript.append(_entry("control", serial_post, "serial_post_read"))
        out: dict[str, Any] = {
            "ok": not missing, "claim": claim, "mode": mode,
            "fallbackReason": result.get("fallbackReason"), "summary": result.get("summary", {}),
            "exchanges": exchanges,
            **_feedback("race" if missing else None, missing, transcript),
        }
        if baseline is not None:
            out["baseline"] = baseline
        if post is not None:
            out["post"] = post
        if serial is not None:
            out["serial"] = serial
        if serial_post is not None:
            out["serialPost"] = serial_post
        return _AwaitableDict(out)

    def prove_injection_differential(
        self,
        control: Any = None,
        probe: Any = None,
        *,
        variant: Any = None,
        expected_output: Optional[str] = None,
        expectedOutput: Optional[str] = None,
        vuln_class: Optional[str] = None,
        vulnClass: Optional[str] = None,
        session: str = "injection-diff",
        message: Optional[str] = None,
        **options: Any,
    ) -> dict[str, Any]:
        """Benign control vs differential probe (evaluated marker with anti-reflection, or engine fingerprint)."""
        base_route = options.get("url", options.get("path", options.get("pathAndQuery", options.get("endpoint", options.get("route")))))
        base_opts: dict[str, Any] = {}
        if options.get("method"):
            base_opts["method"] = options["method"]
        if options.get("headers"):
            base_opts["headers"] = options["headers"]
        persona = options.get("as_persona", options.get("as", options.get("persona")))
        if persona:
            base_opts["as_persona"] = persona
        ctrl_body = options.get("control_body", options.get("controlBody"))
        prb_body = options.get("probe_body", options.get("probeBody"))
        raw_control = control if control is not None else ({"target": base_route, "options": {**base_opts, "body": ctrl_body}} if base_route and ctrl_body is not None else None)
        raw_probe = probe if probe is not None else (variant if variant is not None else ({"target": base_route, "options": {**base_opts, "body": prb_body}} if base_route and prb_body is not None else None))
        c_target, c_opts = _normalize_arm(raw_control, "prove_injection_differential", "control")
        p_target, p_opts = _normalize_arm(raw_probe, "prove_injection_differential", "probe")
        expected = (expected_output or expectedOutput or "").strip()
        vclass = (vuln_class or vulnClass or "").strip() or None

        def _parse_req_body(raw_b: Any) -> Any:
            if raw_b is None:
                return None
            if isinstance(raw_b, str):
                parsed_b = _parse_json(raw_b)
                return parsed_b if parsed_b is not None else raw_b
            return raw_b

        c_req_body = _parse_req_body(c_opts.get("body"))
        p_req_body = _parse_req_body(p_opts.get("body"))
        c_ex = self.http(c_target, role="control", session=session, **c_opts)
        p_ex = self.http(p_target, role="probe", session=session, **p_opts)
        transcript_entries = [_entry("control", c_ex), _entry("probe", p_ex)]
        missing: list[str] = []
        emitted: list[dict[str, Any]] = []
        evaluated = False
        if len(expected) >= 4:
            p_ex2 = self.http(p_target, role="probe", session=session, **p_opts)
            c_ex2 = self.http(c_target, role="control", session=session, **c_opts)
            transcript_entries.extend([_entry("probe", p_ex2), _entry("control", c_ex2)])
            probe_req_text = f"{p_target}\n{json.dumps(p_opts.get('body', '')) if not isinstance(p_opts.get('body'), str) else p_opts.get('body', '')}"
            in_probe = expected in (p_ex.body or "") and expected in (p_ex2.body or "")
            in_control = expected in (c_ex.body or "") or expected in (c_ex2.body or "")
            reflected = expected in probe_req_text
            evaluated = in_probe and not in_control and not reflected
            if not _is_success(c_ex.status):
                missing.append("control_2xx")
            if not in_probe:
                missing.append("evaluated_marker_in_probe")
            if in_control:
                missing.append("marker_absent_from_control")
            if reflected:
                missing.append("non_reflected_expression")
            absent_claim: dict[str, Any] = {
                "kind": "body_contains", "exchangeId": c_ex.exchange_id, "text": expected,
                "absent": True, "message": f"{vclass or 'ssti'} control lacks evaluated marker",
            }
            if c_req_body is not None:
                absent_claim["controlRequestBody"] = c_req_body
            present_claim: dict[str, Any] = {
                "kind": "body_contains", "exchangeId": p_ex.exchange_id, "text": expected,
                "absent": False, "message": message or f"{vclass or 'ssti'} evaluated marker present in probe",
            }
            if vclass:
                present_claim["vulnClass"] = vclass
            if c_req_body is not None:
                present_claim["controlRequestBody"] = c_req_body
            if p_req_body is not None:
                present_claim["probeRequestBody"] = p_req_body
            diff_claim: dict[str, Any] = {
                "kind": "structural_diff",
                "controlIds": [c_ex.exchange_id, c_ex2.exchange_id],
                "variantIds": [p_ex.exchange_id, p_ex2.exchange_id],
                "minRounds": 2,
                "minDeltaTokens": 1,
                "message": message or f"{vclass or 'ssti'} evaluated differential across 2 rounds",
            }
            self.claims.extend([absent_claim, present_claim, diff_claim])
            emitted.extend([absent_claim, present_claim, diff_claim])
        else:
            impact_claim: dict[str, Any] = {
                "kind": "impact", "impactClass": "injection",
                "controlExchangeIds": [c_ex.exchange_id], "probeExchangeId": p_ex.exchange_id,
            }
            if vclass:
                impact_claim["vulnClass"] = vclass
            if p_req_body is not None:
                impact_claim["requestBody"] = p_req_body
            if message:
                impact_claim["message"] = message
            self.claims.append(impact_claim)
            emitted.append(impact_claim)
        return _AwaitableDict({
            "ok": not missing, "control": c_ex, "probe": p_ex, "claims": emitted, "evaluated": evaluated,
            **_feedback("injection_differential" if missing else None, missing, transcript_entries),
        })

    # -- camelCase aliases matching the TS contract ----------------------
    def proveAccessBoundary(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.prove_access_boundary(*args, **kwargs)

    def provePersistedMutation(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.prove_persisted_mutation(*args, **kwargs)

    def proveBooleanOrTimingDiff(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.prove_boolean_or_timing_diff(*args, **kwargs)

    def proveInjectionDifferential(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.prove_injection_differential(*args, **kwargs)

    def proveOobCallback(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.prove_oob_callback(*args, **kwargs)

    def proveRaceBurst(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.prove_race_burst(*args, **kwargs)

    def sealCapability(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.seal_capability(*args, **kwargs)

    def hmacSign(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.hmac_sign(*args, **kwargs)

    def jwtSign(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.jwt_sign(*args, **kwargs)

    def awaitAsync(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.await_async(*args, **kwargs)

    def proveComposite(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.prove_composite(*args, **kwargs)

    def result(self, title: str, severity: str = "high", description: Optional[str] = None) -> ProofResult:
        if not title or not title.strip():
            raise VerificationError("Proof result requires a title.")
        return ProofResult(
            nonce=self.nonce,
            title=title[:300],
            severity=severity[:32],
            claims=self._effective_claims(),
            description=description[:4000] if description else None,
        )


@dataclass
class VerificationScript:
    verify: Callable[[VerifyContext], ProofResult]
    setup: Optional[Callable[[VerifyContext], None]] = None
    cleanup: Optional[Callable[[VerifyContext], None]] = None


def define(*, verify: Callable[[VerifyContext], ProofResult],
           setup: Optional[Callable[[VerifyContext], None]] = None,
           cleanup: Optional[Callable[[VerifyContext], None]] = None) -> VerificationScript:
    return VerificationScript(verify=verify, setup=setup, cleanup=cleanup)


def _write_result(value: dict[str, Any]) -> None:
    path = _result_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _normalize_proof_result(ctx: VerifyContext, returned: Any, default_title: Optional[str] = None) -> dict[str, Any]:
    fallback_title = (default_title.strip() if isinstance(default_title, str) and default_title.strip() else "Verification script proof")[:300]
    fallback_claims = ctx._effective_claims()
    if isinstance(returned, ProofResult):
        payload = returned.to_json()
        if not payload.get("claims") and fallback_claims:
            payload["claims"] = fallback_claims
        return payload
    if isinstance(returned, dict) and isinstance(returned.get("claims"), list):
        title = str(returned.get("title") or "").strip()[:300] or fallback_title
        severity = str(returned.get("severity") or "high").strip()[:32] or "high"
        claims = returned["claims"] if returned["claims"] else fallback_claims
        out: dict[str, Any] = {
            "sdk": "guardian_verify.py",
            "nonce": str(returned.get("nonce") or ctx.nonce),
            "title": title,
            "severity": severity,
            "claims": claims,
        }
        if returned.get("description"):
            out["description"] = str(returned["description"])[:4000]
        return out
    return {
        "sdk": "guardian_verify.py",
        "nonce": ctx.nonce,
        "title": fallback_title,
        "severity": "high",
        "claims": fallback_claims,
    }


def _invoke_hook(fn: Callable[[VerifyContext], Any], ctx: VerifyContext) -> Any:
    res = fn(ctx)
    if inspect.iscoroutine(res):
        return asyncio.run(res)
    return res


def run(script: VerificationScript, default_title: Optional[str] = None) -> None:
    """Run the 3-hook contract and emit the claims document. Stdout is never evidence."""
    ctx = VerifyContext()
    try:
        if script.setup:
            _invoke_hook(script.setup, ctx)
        result = _invoke_hook(script.verify, ctx)
        if script.cleanup:
            _invoke_hook(script.cleanup, ctx)
    except Exception as error:  # noqa: BLE001 - scripts must fail closed
        _write_result({"sdk": "guardian_verify.py", "nonce": ctx.nonce, "error": str(error)[:2000], "claims": []})
        print(f"guardian_verify: {error}", file=sys.stderr)
        sys.exit(1)
    normalized = _normalize_proof_result(ctx, result, default_title)
    _write_result(normalized)
    print(f"guardian_verify: {len(normalized['claims'])} transcript-backed claim(s) recorded")


def run_entrypoint(
    entry: Any,
    *,
    setup: Optional[Callable[[VerifyContext], None]] = None,
    cleanup: Optional[Callable[[VerifyContext], None]] = None,
    default_title: Optional[str] = None,
) -> None:
    """Run an inline function `verify(ctx)` or `VerificationScript` and emit the proof document."""
    if isinstance(entry, VerificationScript):
        run(entry, default_title=default_title)
        return
    if callable(entry):
        run(VerificationScript(verify=entry, setup=setup if callable(setup) else None, cleanup=cleanup if callable(cleanup) else None), default_title=default_title)
        return
    ctx = VerifyContext()
    message = "guardian_verify script must define verify(ctx) or call ctx.prove_* directly."
    _write_result({"sdk": "guardian_verify.py", "nonce": ctx.nonce, "error": message, "claims": []})
    print(f"guardian_verify: {message}", file=sys.stderr)
    sys.exit(1)


__all__ = [
    "BrowserExchange",
    "Exchange",
    "OobCheck",
    "OobHandle",
    "ProofResult",
    "TimingResult",
    "VerificationError",
    "VerificationScript",
    "VerifyContext",
    "define",
    "run",
    "run_entrypoint",
]
