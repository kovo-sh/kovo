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
        if target.startswith("http://") or target.startswith("https://"):
            from urllib.parse import urlsplit

            parts = urlsplit(target)
            origin = f"{parts.scheme}://{parts.netloc}"
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            return origin, path
        if not target.startswith("/"):
            raise VerificationError('Relative verification paths must start with "/".')
        return None, target
    if isinstance(target, dict) and isinstance(target.get("url"), str):
        origin, path = _split_target(target["url"], default_origin)
        return target.get("origin", origin), path
    raise VerificationError("HTTP target requires a path string or a {'url': ...} mapping.")


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
        self.sdk_version: str = str(context.get("sdkVersion", "guardian_verify/v6-mvp"))
        self.claims: list[dict[str, Any]] = []
        self._default_origin = self.target_origins[0] if self.target_origins else None

    # -- network ---------------------------------------------------------
    def http(self, target: Any, **options: Any) -> Exchange:
        origin, path = _split_target(target, self._default_origin)
        args: dict[str, Any] = {
            "path": path,
            "method": str(options.get("method", "GET")).upper(),
        }
        if origin:
            args["origin"] = origin
        if options.get("headers"):
            args["headers"] = options["headers"]
        if options.get("body") is not None:
            args["body"] = options["body"]
        persona = options.get("as_persona", options.get("as"))
        if persona:
            args["persona"] = persona
        if options.get("session"):
            args["session"] = options["session"]
        if options.get("role"):
            args["sessionGroupRole"] = options["role"]
        if options.get("follow_redirects") is not None:
            args["followRedirects"] = bool(options["follow_redirects"])
        timeout = float(options.get("timeout", 60.0))
        return Exchange(_rpc("http", args, timeout))

    def http2(self, target: Any, **options: Any) -> Exchange:
        origin, path = _split_target(target, self._default_origin)
        args: dict[str, Any] = {"path": path, "method": str(options.get("method", "GET")).upper()}
        if origin:
            args["origin"] = origin
        if options.get("headers"):
            args["headers"] = options["headers"]
        if options.get("body") is not None:
            args["body"] = options["body"]
        persona = options.get("as_persona", options.get("as"))
        if persona:
            args["persona"] = persona
        return Exchange(_rpc("http2", args, float(options.get("timeout", 60.0))))

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
    def prove_access_boundary(self, control_persona: str, probe_persona: str, route: Any,
                              expect_control_denied: bool = True, **options: Any) -> dict[str, Any]:
        """Denied control + crossing variant on one route; emits a `boundary` claim."""
        method = str(options.get("method", "GET")).upper()
        control = self.http(route, method=method, as_persona=control_persona, role="control",
                            session=options.get("control_session", "access-boundary-control"),
                            **(options.get("control_options") or {}))
        probe = self.http(route, method=method, as_persona=probe_persona, role="probe",
                          session=options.get("probe_session", "access-boundary-probe"),
                          **(options.get("probe_options") or {}))
        control_denied = _is_denied(control.status)
        crossed = _is_success(probe.status) and len(probe.body) >= 8
        claim: dict[str, Any] = {
            "kind": "boundary",
            "boundaryClass": options.get("boundary_class", "access"),
            "controlExchangeId": control.exchange_id,
            "probeExchangeId": probe.exchange_id,
            "expectControlDenied": bool(expect_control_denied),
        }
        if options.get("actor_roles"):
            claim["actorRoles"] = options["actor_roles"]
        if options.get("actor_tenants"):
            claim["actorTenants"] = options["actor_tenants"]
        if options.get("message"):
            claim["message"] = options["message"]
        self._push(claim)
        missing: list[str] = []
        if expect_control_denied and not control_denied:
            missing.append("control_denied")
        if not crossed:
            missing.append("variant_crossed")
        if not expect_control_denied and control_persona == probe_persona:
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
        if isinstance(mutation, dict) and "target" in mutation:
            spec = dict(mutation)
        else:
            spec = {"target": mutation}
        read_persona = options.get("read_persona", spec.get("as"))
        mutate_persona = options.get("mutate_persona", spec.get("as"))
        read_session = options.get("read_session", "persisted-read")
        before = self.http(read_route, method=options.get("read_method", "GET"),
                           as_persona=read_persona, role="control", session=read_session)
        body = spec.get("body")
        headers = dict(spec.get("headers") or {})
        if body is not None and not any(key.lower() == "content-type" for key in headers):
            headers["content-type"] = "application/json"
        write = self.http(spec["target"], method=str(spec.get("method", "POST")).upper(),
                          body=body, headers=headers or None, as_persona=mutate_persona,
                          role="probe", session=spec.get("session", read_session))
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
        def arm_of(arm: Any) -> tuple[Any, dict[str, Any]]:
            if isinstance(arm, tuple) and len(arm) == 2:
                return arm[0], dict(arm[1] or {})
            if isinstance(arm, dict) and "target" in arm:
                return arm["target"], dict(arm.get("options") or {})
            return arm, {}

        control_target, control_options = arm_of(control)
        variant_target, variant_options = arm_of(variant)
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
        """Synchronized HTTP/2 single-packet burst with an explicit HTTP/1.1 fallback report."""
        if len(requests) < 2 or len(requests) > 10:
            claim = {"kind": "race", "exchangeIds": [], "mode": "http1-fallback",
                     "minDistinctOutcomes": int(options.get("min_distinct_outcomes", 2))}
            return {"ok": False, "claim": claim, "mode": "http1-fallback",
                    "fallbackReason": "race requires between 2 and 10 requests", "summary": {},
                    "exchanges": [], **_feedback("race", ["race_requests"], [])}
        payload: list[dict[str, Any]] = []
        for index, request in enumerate(requests):
            if isinstance(request, str):
                origin, path = _split_target(request, self._default_origin)
                payload.append({"path": path, "method": "GET", "sessionGroupRole": "probe",
                                **({"origin": origin or self._default_origin} if (origin or self._default_origin) else {}),
                                **({"session": options.get("session", "race")} if options.get("session") else {})})
                continue
            spec = dict(request)
            raw_target = spec.get("target", spec.get("url", spec.get("path", "/")))
            origin, path = _split_target(raw_target, self._default_origin)
            entry: dict[str, Any] = {
                "path": path, "method": str(spec.get("method", "GET")).upper(),
                "sessionGroupRole": "probe", "session": options.get("session", f"race-{index}"),
            }
            if spec.get("origin") or origin or self._default_origin:
                entry["origin"] = spec.get("origin") or origin or self._default_origin
            for camel, snake in (("headers", "headers"), ("body", "body")):
                if spec.get(snake) is not None:
                    entry[camel] = spec[snake]
            if spec.get("as"):
                entry["persona"] = spec["as"]
            payload.append(entry)
        result = _rpc("race", {"requests": payload}, 70.0) or {}
        mode = result.get("mode", "http1-fallback")
        exchanges = [{"exchangeId": item.get("exchangeId", ""), "status": int(item.get("status", 0)),
                      "durationMs": item.get("durationMs", 0), "bodySha256": item.get("bodySha256", "")}
                     for item in result.get("results", [])]
        distinct_bodies = len({item["bodySha256"] for item in exchanges})
        distinct_statuses = len({item["status"] for item in exchanges})
        distinct_outcomes = max(distinct_bodies, distinct_statuses)
        min_distinct = int(options.get("min_distinct_outcomes", 2))
        claim = {"kind": "race", "exchangeIds": [item["exchangeId"] for item in exchanges],
                 "mode": mode, "minDistinctOutcomes": min_distinct,
                 "expectAllSuccess": options.get("expect_all_success", True)}
        self._push(claim)
        missing: list[str] = []
        if barrier == "h2" and mode != "h2-single-packet":
            missing.append("h2_single_packet_barrier")
        if distinct_outcomes < min_distinct:
            missing.append("duplicate_effect")
        if options.get("expect_all_success", True) and any(not _is_success(item["status"]) for item in exchanges):
            missing.append("all_participants_success")
        transcript = [_entry("race", {"exchangeId": item["exchangeId"], "method": payload[index]["method"],
                                      "pathAndQuery": payload[index]["path"], "status": item["status"],
                                      "durationMs": item["durationMs"]}, mode)
                      for index, item in enumerate(exchanges)]
        return _AwaitableDict({
            "ok": not missing, "claim": claim, "mode": mode,
            "fallbackReason": result.get("fallbackReason"), "summary": result.get("summary", {}),
            "exchanges": exchanges,
            **_feedback("race" if missing else None, missing, transcript),
        })

    def prove_injection_differential(
        self,
        control: Any,
        probe: Any,
        *,
        expected_output: Optional[str] = None,
        vuln_class: Optional[str] = None,
        session: str = "injection-diff",
        message: Optional[str] = None,
    ) -> dict[str, Any]:
        """Benign control vs injection/SSTI probe (evaluated marker with anti-reflection, or engine fingerprint)."""
        def _split_arm(arm: Any) -> tuple[Any, dict[str, Any]]:
            if isinstance(arm, dict) and "target" in arm:
                return arm["target"], dict(arm.get("options") or {})
            return arm, {}
        c_target, c_opts = _split_arm(control)
        p_target, p_opts = _split_arm(probe)
        c_ex = self.http(c_target, role="control", session=session, **c_opts)
        p_ex = self.http(p_target, role="probe", session=session, **p_opts)
        expected = (expected_output or "").strip()
        missing: list[str] = []
        emitted: list[dict[str, Any]] = []
        evaluated = False
        if len(expected) >= 4:
            probe_req_text = f"{p_target}\n{p_opts.get('body', '')}"
            in_probe = expected in (p_ex.body or "")
            in_control = expected in (c_ex.body or "")
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
            absent_claim = {
                "kind": "body_contains", "exchangeId": c_ex.exchange_id, "text": expected,
                "absent": True, "message": f"{vuln_class or 'ssti'} control lacks evaluated marker",
            }
            present_claim = {
                "kind": "body_contains", "exchangeId": p_ex.exchange_id, "text": expected,
                "absent": False, "message": message or f"{vuln_class or 'ssti'} evaluated marker present in probe",
            }
            self.claims.extend([absent_claim, present_claim])
            emitted.extend([absent_claim, present_claim])
        else:
            impact_claim: dict[str, Any] = {
                "kind": "impact", "impactClass": "injection",
                "controlExchangeIds": [c_ex.exchange_id], "probeExchangeId": p_ex.exchange_id,
            }
            if vuln_class:
                impact_claim["vulnClass"] = vuln_class
            if message:
                impact_claim["message"] = message
            self.claims.append(impact_claim)
            emitted.append(impact_claim)
        return _AwaitableDict({
            "ok": not missing, "control": c_ex, "probe": p_ex, "claims": emitted, "evaluated": evaluated,
            **_feedback("injection_differential" if missing else None, missing, [
                _entry("control", c_ex), _entry("probe", p_ex),
            ]),
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

    def result(self, title: str, severity: str = "high", description: Optional[str] = None) -> ProofResult:
        if not title or not title.strip():
            raise VerificationError("Proof result requires a title.")
        return ProofResult(
            nonce=self.nonce,
            title=title[:300],
            severity=severity[:32],
            claims=list(self.claims),
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
    if isinstance(returned, ProofResult):
        payload = returned.to_json()
        if not payload.get("claims") and ctx.claims:
            payload["claims"] = list(ctx.claims)
        return payload
    if isinstance(returned, dict) and isinstance(returned.get("claims"), list):
        title = str(returned.get("title") or "").strip()[:300] or fallback_title
        severity = str(returned.get("severity") or "high").strip()[:32] or "high"
        claims = returned["claims"] if returned["claims"] else list(ctx.claims)
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
        "claims": list(ctx.claims),
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
