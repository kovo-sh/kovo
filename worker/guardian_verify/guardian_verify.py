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

import http.client
import json
import os
import socket
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional


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


def run(script: VerificationScript) -> None:
    """Run the 3-hook contract and emit the claims document. Stdout is never evidence."""
    ctx = VerifyContext()
    try:
        if script.setup:
            script.setup(ctx)
        result = script.verify(ctx)
        if script.cleanup:
            script.cleanup(ctx)
    except Exception as error:  # noqa: BLE001 - scripts must fail closed
        _write_result({"sdk": "guardian_verify.py", "nonce": ctx.nonce, "error": str(error)[:2000], "claims": []})
        print(f"guardian_verify: {error}", file=sys.stderr)
        sys.exit(1)
    _write_result(result.to_json())
    print(f"guardian_verify: {len(result.claims)} transcript-backed claim(s) recorded")


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
]
