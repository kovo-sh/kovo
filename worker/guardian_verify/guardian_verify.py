"""guardian_verify (Python) — thin, stdlib-only verification SDK for Guardian Layer 3.

Every HTTP/HTTP2/browser/OOB/crypto/proof call crosses a Unix-domain socket into the Guardian
host process (`VerifyRpcServer`), which owns scope, credentials, HMAC-signed transcripts, and
the authoritative oracle (`prove.*` / `composite.verify`).
"""

from __future__ import annotations

import asyncio
import http.client
import inspect
import json
import os
import socket
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urlsplit


class _AttrDict(dict):
    """Dict supporting attribute access (exact + snake_case->camelCase) and `await`."""

    def __getattr__(self, name: str) -> Any:
        if name in self:
            return self[name]
        parts = name.split("_")
        camel = parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])
        if camel in self:
            return self[camel]
        raise AttributeError(name)

    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return self


_AwaitableDict = _AttrDict


class VerificationError(RuntimeError):
    """An RPC call or a script contract violation."""


def _context_path() -> str: return os.environ.get("GUARDIAN_RPC_CONTEXT_FILE", "/guardian-rpc/context.json")
def _socket_path() -> str: return os.environ.get("GUARDIAN_RPC_SOCKET", "/guardian-rpc/verify.sock")
def _token_path() -> str: return os.environ.get("GUARDIAN_RPC_TOKEN_FILE", "/guardian-rpc/token")
def _result_path() -> str: return os.environ.get("GUARDIAN_PROOF_RESULT_FILE", "/guardian-rpc/result.json")


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
    def exchange_id(self) -> str: return str(self.raw.get("exchangeId", ""))
    @property
    def exchangeId(self) -> str: return self.exchange_id  # noqa: N802
    @property
    def status(self) -> int: return int(self.raw.get("status", 0))
    @property
    def headers(self) -> dict[str, str]: return dict(self.raw.get("headers") or {})
    @property
    def body(self) -> str: return str(self.raw.get("body", ""))
    @property
    def duration_ms(self) -> float: return float(self.raw.get("durationMs", 0))
    @property
    def persona_handle(self) -> Optional[str]:
        v = self.raw.get("personaHandle")
        return str(v) if v is not None else None
    @property
    def consumed_capability_id(self) -> Optional[str]:
        v = self.raw.get("consumedCapabilityId")
        return str(v) if v is not None else None
    @property
    def derived_from_capability_ids(self) -> list[str]: return list(self.raw.get("derivedFromCapabilityIds") or [])
    @property
    def executed_sentinels(self) -> list[str]: return list(self.raw.get("executedSentinels") or [])
    def json(self) -> Any: return json.loads(self.body)
    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return self


@dataclass
class BrowserExchange(Exchange):
    @property
    def html(self) -> str: return str(self.raw.get("html", ""))


@dataclass
class OobHandle:
    raw: dict[str, Any]

    @property
    def exchange_id(self) -> str: return str(self.raw.get("exchangeId", ""))
    @property
    def token(self) -> str: return str(self.raw.get("token", ""))
    @property
    def url(self) -> str: return str(self.raw.get("url", ""))
    @property
    def dns_host(self) -> str: return str(self.raw.get("dnsHost", ""))
    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return self


@dataclass
class OobCheck(OobHandle):
    @property
    def hit(self) -> bool: return bool(self.raw.get("hit", False))


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
            parts = urlsplit(trimmed)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            return f"{parts.scheme}://{parts.netloc}", path
        return default_origin, trimmed if trimmed.startswith("/") else "/" + trimmed
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


def _normalize_body_and_headers(body: Any, headers: Optional[dict[str, str]] = None) -> tuple[Optional[str], Optional[dict[str, str]]]:
    next_headers = dict(headers) if headers else None
    if body is None:
        return None, next_headers
    if isinstance(body, str):
        return body, next_headers
    if next_headers is None:
        next_headers = {"content-type": "application/json"}
    elif not any(key.lower() == "content-type" for key in next_headers):
        next_headers["content-type"] = "application/json"
    return json.dumps(body), next_headers


def _pack_arm(arm: Any) -> Any:
    if isinstance(arm, tuple) and len(arm) == 2:
        return {"target": arm[0], "options": dict(arm[1] or {})}
    return arm


def _wrap_exchanges(res: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    out = dict(res)
    for key in keys:
        val = out.get(key)
        if isinstance(val, dict) and "exchangeId" in val:
            out[key] = Exchange(val)
    return out


def _pick(d: dict[str, Any], *keys: str) -> Any:
    return next((d[k] for k in keys if k in d and d[k] is not None), None)


def _cap_handle(v: Any) -> str:
    return str(_pick(v, "handle", "derivedHandle", "cap_id") or "") if isinstance(v, dict) else ("" if v is None else str(v))


def _norm_pred(raw: Any, expect_status: Any = None) -> Optional[dict[str, Any]]:
    pred: dict[str, Any] = {"bodyContains": raw} if isinstance(raw, str) else ({"status": raw} if isinstance(raw, (int, list)) else (dict(raw) if isinstance(raw, dict) else {}))
    for src, dst in (("body_contains", "bodyContains"), ("body_matches", "bodyMatches"), ("json_path", "jsonPath"), ("expect_status", "status"), ("expectStatus", "status")):
        if src in pred and dst not in pred: pred[dst] = pred.pop(src)
    if expect_status is not None and "status" not in pred: pred["status"] = expect_status
    return pred or None


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

    def _build_http_args(self, target: Any, options: dict[str, Any]) -> tuple[dict[str, Any], float]:
        origin, path = _split_target(target, self._default_origin)
        merged: dict[str, Any] = {**(target if isinstance(target, dict) else {}), **options}
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
        if merged.get("session"):
            args["session"] = merged["session"]
        if merged.get("role"):
            args["sessionGroupRole"] = merged["role"]
        fr = merged.get("follow_redirects", merged.get("followRedirects"))
        if fr is not None:
            args["followRedirects"] = bool(fr)
        cap = merged.get("capability")
        if cap is not None:
            if isinstance(cap, dict):
                cap_norm = dict(cap)
                for src, dst in (("header_name", "headerName"), ("cookie_name", "cookieName"), ("query_param", "queryParam")):
                    if src in cap_norm and dst not in cap_norm:
                        cap_norm[dst] = cap_norm.pop(src)
                args["capability"] = cap_norm
            else:
                args["capability"] = cap
        for py_key, rpc_key in (
            ("capability_target", "capabilityTarget"), ("capability_header_name", "capabilityHeaderName"),
            ("capability_cookie_name", "capabilityCookieName"), ("capability_query_param", "capabilityQueryParam"),
            ("entity_id", "entityId"), ("correlation_ids", "correlationIds"),
            ("evidence_role", "evidenceRole"), ("replay_attempt", "replayAttempt"),
        ):
            val = merged.get(py_key, merged.get(rpc_key))
            if val is not None:
                args[rpc_key] = val
        return args, float(merged.get("timeout", 60.0))

    def http(self, target: Any, **options: Any) -> Exchange:
        args, timeout = self._build_http_args(target, options)
        return Exchange(_rpc("http", args, timeout))

    def http_send(self, target: Any, **options: Any) -> Exchange:
        args, timeout = self._build_http_args(target, options)
        return Exchange(_rpc("http.send", args, timeout))

    def httpSend(self, target: Any, **options: Any) -> Exchange:  # noqa: N802
        return self.http_send(target, **options)

    def request(self, target: Any, **options: Any) -> Exchange:
        return self.http_send(target, **options)

    def seal_capability(self, exchange_or_id: Any = None, slot: Optional[str] = None, *, hop_receipt_id: Optional[str] = None, hop_id: Optional[str] = None, json_path: Optional[str] = None, header: Optional[str] = None, cookie: Optional[str] = None, regex: Optional[str] = None, value: Optional[str] = None, kind: Optional[str] = None, ttl_ms: Optional[int] = None, default_header_name: Optional[str] = None, default_cookie_name: Optional[str] = None, allowed_origins: Optional[list[str]] = None, **kwargs: Any) -> dict[str, Any]:
        is_opt = isinstance(exchange_or_id, dict) and (slot is None or any(k in exchange_or_id for k in ("slot", "exchange", "exchange_id", "jsonPath", "json_path", "header", "cookie", "regex", "value")))
        m = {**(exchange_or_id if is_opt else {}), **kwargs}
        ex_src = _pick(m, "exchange", "exchangeId", "exchange_id") if (is_opt or exchange_or_id is None) else exchange_or_id
        exchange_id = ex_src.exchange_id if isinstance(ex_src, Exchange) else (str(_pick(ex_src, "exchangeId", "exchange_id") or "") if isinstance(ex_src, dict) else str(ex_src or ""))
        args: dict[str, Any] = {"exchangeId": exchange_id, "slot": slot if slot is not None else m.get("slot")}
        for dst, val in (("hopReceiptId", hop_receipt_id or _pick(m, "hopReceiptId", "hop_receipt_id")), ("hopId", hop_id or _pick(m, "hopId", "hop_id")), ("jsonPath", json_path or _pick(m, "jsonPath", "json_path")), ("header", header or m.get("header")), ("cookie", cookie or m.get("cookie")), ("regex", regex or m.get("regex")), ("kind", kind or m.get("kind")), ("defaultHeaderName", default_header_name or _pick(m, "defaultHeaderName", "default_header_name")), ("defaultCookieName", default_cookie_name or _pick(m, "defaultCookieName", "default_cookie_name"))):
            if val: args[dst] = val
        val_raw = value if value is not None else m.get("value")
        if val_raw is not None: args["value"] = val_raw
        ttl = ttl_ms if ttl_ms is not None else _pick(m, "ttlMs", "ttl_ms")
        if ttl is not None: args["ttlMs"] = ttl
        ao = allowed_origins or _pick(m, "allowedOrigins", "allowed_origins")
        if ao: args["allowedOrigins"] = list(ao)
        res = dict(_rpc("capability.seal", args, 30.0) or {})
        if "handle" in res and "cap_id" not in res: res["cap_id"] = res["handle"]
        return _AttrDict(res)

    def hmac_sign(self, secret_handle: Any = None, payload: Any = None, alg: Any = None, encoding: Optional[str] = None, **kwargs: Any) -> dict[str, Any]:
        is_opt = isinstance(secret_handle, dict) and payload is None and any(k in secret_handle for k in ("secretHandle", "secret_handle", "keyHandle", "key_handle", "payload", "message", "body"))
        m = {**(secret_handle if is_opt else {}), **(alg if isinstance(alg, dict) else {}), **kwargs}
        sh = _cap_handle(_pick(m, "secretHandle", "secret_handle", "keyHandle", "key_handle") if (is_opt or secret_handle is None) else secret_handle)
        raw_p = payload if payload is not None else _pick(m, "payload", "message", "body")
        p_str = raw_p if isinstance(raw_p, str) else ("" if raw_p is None else json.dumps(raw_p))
        alg_v = (alg if isinstance(alg, str) else None) or _pick(m, "alg", "algorithm") or "sha256"
        res = dict(_rpc("crypto.hmacSign", {"secretHandle": sh, "payload": p_str, "alg": alg_v, "encoding": encoding or m.get("encoding") or "hex"}, 30.0) or {})
        h = res.get("handle") or res.get("derivedHandle") or res.get("signature")
        res.setdefault("handle", h); res.setdefault("derivedHandle", h)
        return _AttrDict(res)

    def jwt_sign(self, secret_handle: Any = None, claims: Any = None, alg: Any = None, *, header: Optional[dict[str, Any]] = None, hop_receipt_id: Optional[str] = None, slot: Optional[str] = None, ttl_ms: Optional[int] = None, allowed_origins: Optional[list[str]] = None, **kwargs: Any) -> dict[str, Any]:
        is_opt = isinstance(secret_handle, dict) and claims is None and any(k in secret_handle for k in ("secretHandle", "secret_handle", "keyHandle", "key_handle", "claims", "payload"))
        m = {**(secret_handle if is_opt else {}), **(alg if isinstance(alg, dict) else {}), **kwargs}
        sh = _cap_handle(_pick(m, "secretHandle", "secret_handle", "keyHandle", "key_handle") if (is_opt or secret_handle is None) else secret_handle)
        c_val = claims if claims is not None else _pick(m, "claims", "payload")
        alg_v = (alg if isinstance(alg, str) else None) or _pick(m, "alg", "algorithm") or "HS256"
        args: dict[str, Any] = {"secretHandle": sh, "claims": dict(c_val) if isinstance(c_val, dict) else {}, "alg": alg_v}
        hdr = header if header is not None else m.get("header")
        if hdr is not None: args["header"] = dict(hdr)
        for dst, val in (("hopReceiptId", hop_receipt_id or _pick(m, "hopReceiptId", "hop_receipt_id")), ("slot", slot or m.get("slot"))):
            if val: args[dst] = val
        ttl = ttl_ms if ttl_ms is not None else _pick(m, "ttlMs", "ttl_ms")
        if ttl is not None: args["ttlMs"] = ttl
        ao = allowed_origins or _pick(m, "allowedOrigins", "allowed_origins")
        if ao: args["allowedOrigins"] = list(ao)
        res = dict(_rpc("crypto.jwtSign", args, 30.0) or {})
        dh = res.get("derivedHandle")
        res.setdefault("handle", dh); res.setdefault("token", dh)
        return _AttrDict(res)

    def await_async(self, poll_request: Any = None, match_predicate: Any = None, *, profile: Optional[str] = None, timeout_ms: Optional[int] = None, interval_ms: Optional[int] = None, max_attempts: Optional[int] = None, trigger_exchange_id: Optional[str] = None, t_trigger_ms: Optional[int] = None, correlation_id: Optional[str] = None, correlation_ids: Optional[list[str]] = None, entity_id: Optional[str] = None, **kwargs: Any) -> dict[str, Any]:
        m = {**(poll_request if isinstance(poll_request, dict) else {}), **kwargs}
        nested = _pick(m, "pollRequest", "poll_request", "request")
        target = nested if nested is not None else (poll_request if poll_request is not None else m)
        poll_args, _ = self._build_http_args(target, m if isinstance(target, str) else {})
        args: dict[str, Any] = {"pollRequest": poll_args}
        mp = _norm_pred(match_predicate if match_predicate is not None else _pick(m, "matchPredicate", "match_predicate", "match", "predicate", "until"), _pick(m, "expectStatus", "expect_status"))
        if mp is not None: args["matchPredicate"] = mp
        prof = profile or m.get("profile")
        if prof: args["profile"] = prof
        t_ms = timeout_ms if timeout_ms is not None else _pick(m, "timeoutMs", "timeout_ms")
        for dst, val in (("timeoutMs", t_ms), ("intervalMs", interval_ms if interval_ms is not None else _pick(m, "intervalMs", "interval_ms")), ("maxAttempts", max_attempts if max_attempts is not None else _pick(m, "maxAttempts", "max_attempts")), ("tTriggerMs", t_trigger_ms if t_trigger_ms is not None else _pick(m, "tTriggerMs", "t_trigger_ms"))):
            if val is not None: args[dst] = val
        trig = trigger_exchange_id or _pick(m, "triggerExchangeId", "trigger_exchange_id")
        if trig: args["triggerExchangeId"] = trig.exchange_id if isinstance(trig, Exchange) else (str(_pick(trig, "exchangeId", "exchange_id") or "") if isinstance(trig, dict) else str(trig))
        for dst, val in (("correlationId", correlation_id or _pick(m, "correlationId", "correlation_id")), ("entityId", entity_id or _pick(m, "entityId", "entity_id"))):
            if val: args[dst] = val
        cids = correlation_ids or _pick(m, "correlationIds", "correlation_ids")
        if cids: args["correlationIds"] = list(cids)
        res = dict(_rpc("async.awaitResult", args, max((float(t_ms) / 1000.0 if t_ms else 30.0) + 10.0, 15.0)) or {})
        if isinstance(res.get("exchange"), dict): res["exchange"] = _AttrDict(res["exchange"])
        return _AttrDict(res)

    def prove_composite(self, receipt: dict[str, Any]) -> dict[str, Any]:
        payload = receipt if isinstance(receipt, dict) and "receipt" in receipt else {"receipt": receipt}
        raw = _rpc("composite.verify", payload, 30.0)
        res: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
        confirmed = bool(res.get("confirmed") is True or res.get("ok") is True or res.get("verified") is True)
        claim = res.get("claim")
        if isinstance(claim, dict):
            if confirmed:
                self._last_failed_composite_claim = None
                self.claims.append(claim)
            else:
                self._last_failed_composite_claim = claim
        res["confirmed"] = confirmed
        res["ok"] = confirmed
        res["verified"] = confirmed
        return _AwaitableDict(res)

    def _effective_claims(self) -> list[dict[str, Any]]:
        if self.claims:
            return list(self.claims)
        return [self._last_failed_composite_claim] if self._last_failed_composite_claim else []

    def http2(self, target: Any, **options: Any) -> Exchange:
        args, timeout = self._build_http_args(target, options)
        return Exchange(_rpc("http2", args, timeout))

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

    def oob_mint(self, label: str, origin: Optional[str] = None) -> OobHandle:
        args: dict[str, Any] = {"action": "mint", "label": label}
        if origin:
            args["origin"] = origin
        return OobHandle(_rpc("oob", args, 30.0))

    def oob_check(self, handle: OobHandle) -> OobCheck:
        result = _rpc("oob", {"action": "check", "token": handle.token, "exchangeId": handle.exchange_id}, 30.0)
        return OobCheck({**handle.raw, **(result or {})})

    def _push(self, claim: dict[str, Any]) -> dict[str, Any]:
        self.claims.append(claim)
        return claim

    def expect_status(self, exchange: Exchange, expected: Any, message: Optional[str] = None) -> dict[str, Any]:
        return self._push({"kind": "status", "exchangeId": exchange.exchange_id, "expected": expected, **({"message": message} if message else {})})

    def expect_status_not(self, exchange: Exchange, unexpected: int, message: Optional[str] = None) -> dict[str, Any]:
        return self.expect_status(exchange, [c for c in (200, 201, 202, 204, 301, 302, 400, 401, 403, 404, 405) if c != unexpected], message)

    def expect_header(self, exchange: Exchange, name: str, equals: Optional[str] = None, matches: Optional[str] = None,
                      absent: Optional[bool] = None, message: Optional[str] = None) -> dict[str, Any]:
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
        return self._push({"kind": "body_contains", "exchangeId": exchange.exchange_id, "text": text, **({"message": message} if message else {})})

    def expect_body_absent(self, exchange: Exchange, text: str, message: Optional[str] = None) -> dict[str, Any]:
        return self._push({"kind": "body_contains", "exchangeId": exchange.exchange_id, "text": text, "absent": True, **({"message": message} if message else {})})

    def expect_json_path(self, exchange: Exchange, path: str, expected: Any = ..., message: Optional[str] = None) -> dict[str, Any]:
        claim: dict[str, Any] = {"kind": "jsonpath", "exchangeId": exchange.exchange_id, "path": path}
        claim["exists" if expected is ... else "equals"] = True if expected is ... else expected
        if message:
            claim["message"] = message
        return self._push(claim)

    def expect_css(self, exchange: Exchange, selector: str, exists: Optional[bool] = None, count: Optional[int] = None,
                   text_equals: Optional[str] = None, text_contains: Optional[str] = None, message: Optional[str] = None) -> dict[str, Any]:
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

    def expect_dom_sentinel(self, exchange: Exchange, sentinel: str, mode: str = "executed", message: Optional[str] = None) -> dict[str, Any]:
        return self._push({"kind": "dom_sentinel", "exchangeId": exchange.exchange_id, "sentinel": sentinel, "mode": mode, **({"message": message} if message else {})})

    def expect_oob(self, exchange: OobHandle, expect_hit: bool = True, message: Optional[str] = None) -> dict[str, Any]:
        return self._push({"kind": "oob", "exchangeId": exchange.exchange_id, "expectHit": bool(expect_hit), **({"message": message} if message else {})})

    def expect_timing(self, timing: TimingResult, message: Optional[str] = None) -> dict[str, Any]:
        claim = timing.claim
        if message:
            claim["message"] = message
        return self._push(claim)

    def timing_compare(self, control: Any, variant: Any, pairs: int = 6) -> TimingResult:
        count = max(5, min(int(pairs), 7))
        control_ids: list[str] = []
        variant_ids: list[str] = []
        for index in range(count):
            for which in (("control", "variant") if index % 2 == 0 else ("variant", "control")):
                call = control if which == "control" else variant
                target, opts = (call[0], call[1]) if isinstance(call, tuple) else (call, {})
                ex = self.http(target, **opts)
                (control_ids if which == "control" else variant_ids).append(ex.exchange_id)
        return TimingResult(control_ids=control_ids, variant_ids=variant_ids, pairs=count)

    # -- authoritative host-backed proof helpers (`prove.*`) ----------------

    def prove_access_boundary(self, control_persona: Optional[str] = None, probe_persona: Optional[str] = None,
                              route: Any = None, expect_control_denied: bool = True, **options: Any) -> dict[str, Any]:
        args: dict[str, Any] = dict(options)
        if control_persona is not None:
            args["controlPersona"] = control_persona
        if probe_persona is not None:
            args["probePersona"] = probe_persona
        if route is not None:
            args["route"] = route
        args.setdefault("expectControlDenied", bool(expect_control_denied))
        res = _rpc("prove.accessBoundary", args, 70.0) or {}
        if isinstance(res.get("claim"), dict):
            self._push(res["claim"])
        return _AwaitableDict(_wrap_exchanges(res, ("control", "probe")))

    def prove_persisted_mutation(self, read_route: Any, mutation: Any, field_path: str,
                                 expect_delta: Any = ..., **options: Any) -> dict[str, Any]:
        args: dict[str, Any] = {**options, "readRoute": read_route, "mutation": _pack_arm(mutation), "fieldPath": field_path}
        expect_fn = expect_delta if callable(expect_delta) else None
        if expect_fn is not None:
            args["hasCustomExpectFn"] = True
        elif expect_delta is not ...:
            args["expectDelta"] = expect_delta
        res = _rpc("prove.persistedMutation", args, 70.0) or {}
        if isinstance(res.get("claim"), dict):
            self._push(res["claim"])
        out = _wrap_exchanges(res, ("before", "mutation", "after"))
        if expect_fn is not None and not bool(expect_fn(out.get("delta", {}).get("before"), out.get("delta", {}).get("after"), out.get("delta", {}))):
            out["ok"] = False
            out["confirmed"] = False
            out["expectationMatched"] = False
            out["rejectedBy"] = out.get("rejectedBy") or "impact"
            missing = list(out.get("missingEvidence") or [])
            if "expected_delta" not in missing:
                missing.append("expected_delta")
            out["missingEvidence"] = missing
        return _AwaitableDict(out)

    def prove_boolean_or_timing_diff(self, control: Any, variant: Any, mode: str = "boolean",
                                     rounds: Optional[int] = None, **options: Any) -> dict[str, Any]:
        args: dict[str, Any] = {**options, "control": _pack_arm(control), "variant": _pack_arm(variant), "mode": mode}
        if rounds is not None:
            args["rounds"] = rounds
        res = _rpc("prove.differential", args, 120.0) or {}
        if isinstance(res.get("claim"), dict):
            self._push(res["claim"])
        out = dict(res)
        if isinstance(out.get("exchanges"), dict):
            out["exchanges"] = {
                "control": [Exchange(x) if isinstance(x, dict) else x for x in out["exchanges"].get("control", [])],
                "variant": [Exchange(x) if isinstance(x, dict) else x for x in out["exchanges"].get("variant", [])],
            }
        return _AwaitableDict(out)

    def prove_oob_callback(self, inject: Any, token: Optional[str] = None, timeout_ms: int = 6000,
                           immediate_ms: int = 3000, window_ms: Optional[int] = None, **options: Any) -> dict[str, Any]:
        if callable(inject):
            start_args: dict[str, Any] = {"phase": "start", "immediateMs": int(immediate_ms)}
            if token:
                start_args["token"] = token
            if window_ms is not None:
                start_args["windowMs"] = int(window_ms)
            started = _rpc("prove.oob", start_args, 30.0) or {}
            handle = OobHandle(started.get("handle") or {})
            injection: Optional[dict[str, Any]] = None
            injection_error: Optional[str] = None
            try:
                injected = inject(handle)
                if isinstance(injected, Exchange):
                    injection = injected.raw
                elif isinstance(injected, dict) and "exchangeId" in injected:
                    injection = injected
            except Exception as error:  # noqa: BLE001
                injection_error = str(error)[:300]
            finish_args: dict[str, Any] = {
                "phase": "finish",
                "handle": handle.raw,
                "subscription": started.get("subscription") or {},
                "immediateMs": int(immediate_ms),
                "timeoutMs": int(timeout_ms),
                **({"injection": injection} if injection else {}),
                **({"injectionError": injection_error} if injection_error else {}),
                **({"message": options["message"]} if options.get("message") else {}),
            }
            res = _rpc("prove.oob", finish_args, float(timeout_ms) / 1000.0 + 15.0) or {}
        else:
            args: dict[str, Any] = {
                **options, "inject": _pack_arm(inject), "timeoutMs": int(timeout_ms), "immediateMs": int(immediate_ms),
                **({"token": token} if token else {}),
                **({"windowMs": int(window_ms)} if window_ms is not None else {}),
            }
            res = _rpc("prove.oob", args, float(timeout_ms) / 1000.0 + 20.0) or {}
        if isinstance(res.get("claim"), dict):
            self._push(res["claim"])
        return _AwaitableDict(res)

    def prove_race_burst(self, requests: list[Any], barrier: str = "auto", **options: Any) -> dict[str, Any]:
        args: dict[str, Any] = {**options, "requests": [_pack_arm(r) for r in requests], "barrier": barrier}
        res = _rpc("prove.race", args, 80.0) or {}
        claim = res.get("claim")
        if isinstance(claim, dict) and isinstance(claim.get("exchangeIds"), list) and len(claim["exchangeIds"]) >= 2:
            self._push(claim)
        return _AwaitableDict(_wrap_exchanges(res, ("baseline", "post", "serial", "serialPost")))

    def prove_injection_differential(
        self, control: Any = None, probe: Any = None, *, variant: Any = None,
        expected_output: Optional[str] = None, expectedOutput: Optional[str] = None,
        vuln_class: Optional[str] = None, vulnClass: Optional[str] = None,
        session: str = "injection-diff", message: Optional[str] = None, **options: Any,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {**options, "session": session}
        if control is not None:
            args["control"] = _pack_arm(control)
        if probe is not None:
            args["probe"] = _pack_arm(probe)
        elif variant is not None:
            args["variant"] = _pack_arm(variant)
        if expected_output is not None or expectedOutput is not None:
            args["expectedOutput"] = expected_output if expected_output is not None else expectedOutput
        if vuln_class is not None or vulnClass is not None:
            args["vulnClass"] = vuln_class if vuln_class is not None else vulnClass
        if message:
            args["message"] = message
        res = _rpc("prove.injection", args, 70.0) or {}
        if isinstance(res.get("claims"), list):
            self.claims.extend(c for c in res["claims"] if isinstance(c, dict))
        elif isinstance(res.get("claim"), dict):
            self._push(res["claim"])
        return _AwaitableDict(_wrap_exchanges(res, ("control", "probe")))

    # -- camelCase aliases matching the TS contract ----------------------
    def proveAccessBoundary(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.prove_access_boundary(*args, **kwargs)  # noqa: N802
    def provePersistedMutation(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.prove_persisted_mutation(*args, **kwargs)  # noqa: N802
    def proveBooleanOrTimingDiff(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.prove_boolean_or_timing_diff(*args, **kwargs)  # noqa: N802
    def proveInjectionDifferential(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.prove_injection_differential(*args, **kwargs)  # noqa: N802
    def proveOobCallback(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.prove_oob_callback(*args, **kwargs)  # noqa: N802
    def proveRaceBurst(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.prove_race_burst(*args, **kwargs)  # noqa: N802
    def sealCapability(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.seal_capability(*args, **kwargs)  # noqa: N802
    def hmacSign(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.hmac_sign(*args, **kwargs)  # noqa: N802
    def jwtSign(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.jwt_sign(*args, **kwargs)  # noqa: N802
    def awaitAsync(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.await_async(*args, **kwargs)  # noqa: N802
    def proveComposite(self, *args: Any, **kwargs: Any) -> dict[str, Any]: return self.prove_composite(*args, **kwargs)  # noqa: N802

    def result(self, title: str, severity: str = "high", description: Optional[str] = None) -> ProofResult:
        if not title or not title.strip():
            raise VerificationError("Proof result requires a title.")
        return ProofResult(
            nonce=self.nonce, title=title[:300], severity=severity[:32],
            claims=self._effective_claims(), description=description[:4000] if description else None,
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
        out: dict[str, Any] = {
            "sdk": "guardian_verify.py",
            "nonce": str(returned.get("nonce") or ctx.nonce),
            "title": str(returned.get("title") or "").strip()[:300] or fallback_title,
            "severity": str(returned.get("severity") or "high").strip()[:32] or "high",
            "claims": returned["claims"] if returned["claims"] else fallback_claims,
        }
        if returned.get("description"):
            out["description"] = str(returned["description"])[:4000]
        return out
    return {"sdk": "guardian_verify.py", "nonce": ctx.nonce, "title": fallback_title, "severity": "high", "claims": fallback_claims}


def _invoke_hook(fn: Callable[[VerifyContext], Any], ctx: VerifyContext) -> Any:
    res = fn(ctx)
    return asyncio.run(res) if inspect.iscoroutine(res) else res


def run(script: VerificationScript, default_title: Optional[str] = None) -> None:
    """Run the 3-hook contract and emit the claims document. Stdout is never evidence."""
    ctx = VerifyContext()
    try:
        if script.setup:
            _invoke_hook(script.setup, ctx)
        result = _invoke_hook(script.verify, ctx)
        if script.cleanup:
            _invoke_hook(script.cleanup, ctx)
    except Exception as error:  # noqa: BLE001
        _write_result({"sdk": "guardian_verify.py", "nonce": ctx.nonce, "error": str(error)[:2000], "claims": []})
        print(f"guardian_verify: {error}", file=sys.stderr)
        sys.exit(1)
    normalized = _normalize_proof_result(ctx, result, default_title)
    _write_result(normalized)
    print(f"guardian_verify: {len(normalized['claims'])} transcript-backed claim(s) recorded")


def run_entrypoint(
    entry: Any, *, setup: Optional[Callable[[VerifyContext], None]] = None,
    cleanup: Optional[Callable[[VerifyContext], None]] = None, default_title: Optional[str] = None,
) -> None:
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
    "BrowserExchange", "Exchange", "OobCheck", "OobHandle", "ProofResult", "TimingResult",
    "VerificationError", "VerificationScript", "VerifyContext", "define", "run", "run_entrypoint",
]
